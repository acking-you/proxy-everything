//! The desktop app's local controller.
//!
//! Dart owns the node catalogue and the switching workflow, so this [`Host`]
//! turns each question into a call that the UI collects with `next` and
//! answers with its following `next`. Website rules are answered natively from
//! the profile's shared store. No HTTP worker ever borrows a proxy handle.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use proxy_client::controller::{
    ApiError, BindError, Controller, Host, InvalidToken, Node, Nodes, Selection, Status, Token,
};
use proxy_client::site_rules::{RuleSet, RulesError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snafu::{ResultExt, Snafu, ensure};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

const SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "windows",
    all(target_os = "macos", not(feature = "mac-app-store"))
));
/// Calls waiting for the UI. HTTP requests beyond this wait for a slot,
/// bounded by the controller's connection timeout.
const PENDING_CALLS: usize = 8;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Request {
    Start {
        port: u16,
        token: String,
        /// The profile whose website rules the API edits.
        directory: PathBuf,
    },
    /// Answer the previous call, if any, and wait for the next one. Returns
    /// `{"call": null}` once the controller has stopped.
    Next {
        id: u64,
        reply: Option<Reply>,
    },
    Stop {
        id: u64,
    },
}

type Reply = Result<Value, ApiError>;

/// A question for the UI, as `{"operation": ...}`.
#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Call {
    Nodes,
    Status,
    Switch(Selection),
    RulesChanged(RuleSet),
}

#[derive(Debug, Snafu)]
pub(crate) enum Error {
    #[snafu(display("The local controller is available in desktop builds"))]
    Unsupported,
    #[snafu(display("A local controller is already running"))]
    AlreadyRunning,
    #[snafu(display("Another reader is already waiting for controller calls"))]
    Busy,
    #[snafu(transparent)]
    Token { source: InvalidToken },
    #[snafu(transparent)]
    Rules { source: RulesError },
    #[snafu(transparent)]
    Bind { source: BindError },
    #[snafu(display("Could not read the controller's listening address"))]
    Address { source: io::Error },
}

struct Pending {
    call: Call,
    reply: oneshot::Sender<Reply>,
}

struct Calls {
    queue: mpsc::Receiver<Pending>,
    unanswered: Option<oneshot::Sender<Reply>>,
}

struct Service {
    id: u64,
    calls: Arc<Mutex<Calls>>,
    server: AbortOnDropHandle<()>,
}

static SERVICE: Mutex<Option<Service>> = Mutex::const_new(None);

struct DartHost {
    calls: mpsc::Sender<Pending>,
}

impl DartHost {
    async fn ask<T: DeserializeOwned>(&self, call: Call) -> Result<T, ApiError> {
        let (reply, answer) = oneshot::channel();
        self.calls
            .send(Pending { call, reply })
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let value = answer.await.map_err(|_| ApiError::Unavailable)??;
        serde_json::from_value(value).map_err(|error| {
            tracing::warn!(%error, "the app answered a local controller call in an unexpected shape");
            ApiError::Unavailable
        })
    }
}

impl Host for DartHost {
    async fn nodes(&self) -> Result<Vec<Node>, ApiError> {
        self.ask::<Nodes>(Call::Nodes)
            .await
            .map(|nodes| nodes.nodes)
    }

    async fn status(&self) -> Result<Status, ApiError> {
        self.ask(Call::Status).await
    }

    async fn switch(&self, selection: Selection) -> Result<Status, ApiError> {
        self.ask(Call::Switch(selection)).await
    }

    async fn rules_changed(&self, rules: Arc<RuleSet>) {
        let call = Call::RulesChanged(RuleSet::clone(&rules));
        if let Err(error) = self.ask::<()>(call).await {
            tracing::debug!(%error, "the app did not take the edited website rules");
        }
    }
}

impl Request {
    pub(crate) async fn execute(self) -> Result<Value, Error> {
        match self {
            Self::Start {
                port,
                token,
                directory,
            } => start(port, token, &directory).await,
            Self::Next { id, reply } => next(id, reply).await,
            Self::Stop { id } => {
                stop(id).await;
                Ok(json!({}))
            }
        }
    }
}

async fn start(port: u16, token: String, directory: &std::path::Path) -> Result<Value, Error> {
    ensure!(SUPPORTED, UnsupportedSnafu);
    let mut service = SERVICE.lock().await;
    ensure!(service.is_none(), AlreadyRunningSnafu);
    let token = Token::try_from(token)?;
    let rules = crate::site_rules::open(directory)?;
    let (calls, queue) = mpsc::channel(PENDING_CALLS);
    let controller = Controller::bind(port, token, DartHost { calls }, rules).await?;
    let port = controller.local_addr().context(AddressSnafu)?.port();
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    *service = Some(Service {
        id,
        calls: Arc::new(Mutex::new(Calls {
            queue,
            unanswered: None,
        })),
        server: AbortOnDropHandle::new(tokio::spawn(controller.serve())),
    });
    tracing::info!(port, "local controller started");
    Ok(json!({"id": id, "port": port}))
}

async fn next(id: u64, reply: Option<Reply>) -> Result<Value, Error> {
    let calls = match SERVICE.lock().await.as_ref() {
        Some(service) if service.id == id => service.calls.clone(),
        _ => return Ok(json!({"call": null})),
    };
    let mut calls = calls.try_lock().map_err(|_| Error::Busy)?;
    // Without a reply the waiting request fails as unavailable.
    if let (Some(waiting), Some(reply)) = (calls.unanswered.take(), reply) {
        let _ = waiting.send(reply);
    }
    // The queue closes when stopping drops the controller with its host.
    while let Some(Pending { call, reply }) = calls.queue.recv().await {
        if !reply.is_closed() {
            calls.unanswered = Some(reply);
            return Ok(json!({"call": call}));
        }
    }
    Ok(json!({"call": null}))
}

async fn stop(id: u64) {
    let stopped = {
        let mut service = SERVICE.lock().await;
        if service.as_ref().is_some_and(|service| service.id == id) {
            service.take()
        } else {
            None
        }
    };
    if let Some(Service { server, .. }) = stopped {
        server.abort();
        // Wait until the port is released, so a restart can bind it again.
        let _ = server.await;
        tracing::info!("local controller stopped");
    }
}
