//! The desktop provider owns the catalogue and the handle operation queue.
//! Exchange one command at a time with it. HTTP workers never borrow a raw handle.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use proxy_client::controller::{BindError, Call, Reply, Server};
use serde::Deserialize;
use serde_json::{Value, json};
use snafu::{ResultExt, Snafu};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum Request {
    Start { port: u16, token: String },
    Exchange { id: u64, reply: Option<Reply> },
    Stop { id: u64 },
}

#[derive(Debug, Snafu)]
pub(crate) enum Error {
    #[snafu(display("A local controller is already running"))]
    AlreadyRunning,
    #[snafu(display("The local controller is available in desktop builds"))]
    Unsupported,
    #[snafu(display("Another host exchange is in progress"))]
    Busy,
    #[snafu(display("Invalid controller reply sequence"))]
    Sequence,
    #[snafu(transparent)]
    Bind { source: BindError },
    #[snafu(display("Reading the controller listener address failed"))]
    Address { source: std::io::Error },
}

struct Exchange {
    calls: mpsc::Receiver<Call>,
    waiting: Option<oneshot::Sender<Reply>>,
}

struct Service {
    id: u64,
    exchange: Arc<Mutex<Exchange>>,
    server: AbortOnDropHandle<()>,
}

static SERVICE: Mutex<Option<Service>> = Mutex::const_new(None);

impl Request {
    pub(crate) async fn execute(self) -> Result<Value, Error> {
        let mut service = SERVICE.lock().await;
        match self {
            Self::Start { port, token } => {
                if !cfg!(any(
                    target_os = "linux",
                    target_os = "windows",
                    all(target_os = "macos", not(feature = "mac-app-store"))
                )) {
                    return Err(Error::Unsupported);
                }
                if service.is_some() {
                    return Err(Error::AlreadyRunning);
                }
                let (server, calls) = Server::bind(port, token).await?;
                let port = server.port().context(AddressSnafu)?;
                static NEXT: AtomicU64 = AtomicU64::new(1);
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                *service = Some(Service {
                    id,
                    exchange: Arc::new(Mutex::new(Exchange {
                        calls,
                        waiting: None,
                    })),
                    server: AbortOnDropHandle::new(tokio::spawn(async move {
                        if let Err(error) = server.serve().await {
                            tracing::error!(?error, "local controller stopped");
                        }
                    })),
                });
                Ok(json!({"id":id, "port":port}))
            }
            Self::Exchange { id, reply } => {
                let Some(current) = service.as_ref().filter(|s| s.id == id) else {
                    return Ok(json!({"command":null}));
                };
                let exchange = current.exchange.clone();
                drop(service);
                let mut exchange = exchange.try_lock().map_err(|_| Error::Busy)?;
                if exchange.waiting.is_some() != reply.is_some() {
                    return Err(Error::Sequence);
                }
                if let (Some(sender), Some(reply)) = (exchange.waiting.take(), reply) {
                    let _ = sender.send(reply);
                }
                while let Some(call) = exchange.calls.recv().await {
                    if !call.reply.is_closed() {
                        exchange.waiting = Some(call.reply);
                        return Ok(json!({"command":call.command}));
                    }
                }
                Ok(json!({"command":null}))
            }
            Self::Stop { id } => {
                if service.as_ref().is_some_and(|s| s.id == id)
                    && let Some(current) = service.take()
                {
                    current.server.abort();
                    let _ = current.server.await;
                }
                Ok(json!({}))
            }
        }
    }
}
