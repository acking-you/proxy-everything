//! Authenticated loopback HTTP API shared by the CLI and desktop app.
//! The host owns node resolution and serializes changes with its own lifecycle.
use std::convert::Infallible;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use proxy_core::upstream::Carrier;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snafu::ResultExt;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

/// Catalogue identity used by both configured entries and incoming selections.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct NodeId(String);

#[derive(Debug, snafu::Snafu)]
#[snafu(display("Node ID must contain a non-whitespace character"))]
pub struct EmptyNodeId;

impl TryFrom<String> for NodeId {
    type Error = EmptyNodeId;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        if id.trim().is_empty() {
            return Err(EmptyNodeId);
        }
        Ok(Self(id))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl NodeId {
    pub fn startup() -> Self {
        Self("startup".into())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub node_id: NodeId,
    pub transport: Carrier,
    #[serde(default)]
    pub close_existing: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSelection {
    pub site: crate::site_routes::Site,
    pub target: RuleTarget,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleTarget {
    Direct,
    Node { node_id: NodeId, transport: Carrier },
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Command {
    Nodes,
    Status,
    Switch(Selection),
    Rules,
    SetRule(RuleSelection),
    RemoveRule { site: crate::site_routes::Site },
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, snafu::Snafu)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    #[snafu(display("Supply the local controller bearer token."))]
    Unauthorized,
    #[snafu(display("Unknown API path."))]
    NotFound,
    #[snafu(display("Use the method documented for this resource."))]
    MethodNotAllowed,
    #[snafu(display("Send a JSON object with node_id, transport and optional close_existing."))]
    InvalidRequest,
    #[snafu(display(
        "Provide a valid site and a direct or node target as documented by /v1/openapi.json."
    ))]
    InvalidRule,
    #[snafu(display(
        "Cannot save these website rules. Check the rule limit and local file permissions."
    ))]
    RuleStorage,
    #[snafu(display("Select a node ID from GET /v1/nodes."))]
    UnknownNode,
    #[snafu(display("Select a transport listed for this node."))]
    UnsupportedTransport,
    #[snafu(display("Start the local proxy listener first."))]
    NotRunning,
    #[snafu(display("Another operation is in progress. Query status before retrying."))]
    Busy,
    #[snafu(display("Switch failed. Check proxy status, TUN routes and the local log."))]
    SwitchFailed,
    #[snafu(display("The local controller is stopping or unavailable."))]
    Unavailable,
}

impl Failure {
    fn response(self) -> Response<Full<Bytes>> {
        use StatusCode as S;
        let status = match self {
            Self::Unauthorized => S::UNAUTHORIZED,
            Self::NotFound => S::NOT_FOUND,
            Self::MethodNotAllowed => S::METHOD_NOT_ALLOWED,
            Self::InvalidRequest | Self::InvalidRule => S::BAD_REQUEST,
            Self::RuleStorage => S::CONFLICT,
            Self::UnknownNode => S::NOT_FOUND,
            Self::UnsupportedTransport => S::UNPROCESSABLE_ENTITY,
            Self::NotRunning => S::CONFLICT,
            Self::Busy => S::CONFLICT,
            Self::SwitchFailed => S::CONFLICT,
            Self::Unavailable => S::SERVICE_UNAVAILABLE,
        };
        response(
            status,
            json!({"error":{"kind":self,"message":self.to_string()}})
                .to_string()
                .into(),
        )
    }
}

impl From<crate::site_routes::StoreError> for Failure {
    fn from(error: crate::site_routes::StoreError) -> Self {
        use crate::site_routes::StoreError;
        tracing::warn!(?error, "website rule operation failed");
        match error {
            StoreError::Busy => Self::Busy,
            StoreError::File { .. }
            | StoreError::Decode { .. }
            | StoreError::Encode { .. }
            | StoreError::Limit => Self::RuleStorage,
        }
    }
}

pub type Reply = Result<Value, Failure>;

pub struct Call {
    pub command: Command,
    pub reply: oneshot::Sender<Reply>,
}

#[derive(Debug, snafu::Snafu)]
pub enum BindError {
    #[snafu(display(
        "Controller token must contain 32–256 printable ASCII characters without spaces"
    ))]
    InvalidToken,
    #[snafu(display("Could not bind the local controller to 127.0.0.1:{port}"))]
    Listen { port: u16, source: io::Error },
}

pub struct Server {
    listener: TcpListener,
    token: Arc<str>,
    calls: mpsc::Sender<Call>,
}

impl Server {
    /// Port zero picks a free port. The host supplies a separate controller secret.
    pub async fn bind(port: u16, token: String) -> Result<(Self, mpsc::Receiver<Call>), BindError> {
        if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(BindError::InvalidToken);
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .context(ListenSnafu { port })?;
        let (calls, receiver) = mpsc::channel(1);
        Ok((
            Self {
                listener,
                token: token.into(),
                calls,
            },
            receiver,
        ))
    }

    pub fn port(&self) -> io::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    /// Dropping this future closes the listener and its outstanding connections.
    pub async fn serve(self) -> io::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = self.calls.closed() => return Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept(), if connections.len() < 32 => {
                    let (socket, _) = accepted?;
                    let token = self.token.clone();
                    let calls = self.calls.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let token = token.clone();
                            let calls = calls.clone();
                            async move {
                                Ok::<_, Infallible>(handle(request, &token, calls).await.unwrap_or_else(Failure::response))
                            }
                        });
                        let connection = http1::Builder::new()
                            .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5))
                            .max_buf_size(8192).keep_alive(false)
                            .serve_connection(TokioIo::new(socket), service);
                        // Includes slow readers. Submitted switches finish in the host.
                        let _ = tokio::time::timeout(Duration::from_secs(60), connection).await;
                    });
                }
            }
        }
    }
}

async fn handle(
    request: Request<Incoming>,
    token: &str,
    calls: mpsc::Sender<Call>,
) -> Result<Response<Full<Bytes>>, Failure> {
    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.as_bytes().strip_prefix(b"Bearer "))
        .unwrap_or_default();
    if !bool::from(supplied.ct_eq(token.as_bytes())) || request.headers().contains_key(ORIGIN) {
        return Err(Failure::Unauthorized);
    }
    let command = match (request.method(), request.uri().path()) {
        (&Method::GET, "/v1/openapi.json") => {
            return Ok(response(
                StatusCode::OK,
                Bytes::from_static(include_bytes!("controller.openapi.json")),
            ));
        }
        (&Method::GET, "/v1/nodes") => Command::Nodes,
        (&Method::GET, "/v1/rules") => Command::Rules,
        (&Method::PUT, "/v1/rules") => {
            Command::SetRule(body(request).await.map_err(|_| Failure::InvalidRule)?)
        }
        (&Method::DELETE, "/v1/rules") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Remove {
                site: crate::site_routes::Site,
            }
            let Remove { site } = body(request).await.map_err(|_| Failure::InvalidRule)?;
            Command::RemoveRule { site }
        }
        (&Method::GET, "/v1/status") => Command::Status,
        (&Method::POST, "/v1/switch") => Command::Switch(body(request).await?),
        (_, "/v1/status" | "/v1/nodes" | "/v1/switch" | "/v1/openapi.json" | "/v1/rules") => {
            return Err(Failure::MethodNotAllowed);
        }
        _ => return Err(Failure::NotFound),
    };
    let (reply, result) = oneshot::channel();
    calls
        .try_send(Call { command, reply })
        .map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Failure::Busy,
            mpsc::error::TrySendError::Closed(_) => Failure::Unavailable,
        })?;
    let value = result.await.map_err(|_| Failure::Unavailable)??;
    Ok(response(StatusCode::OK, value.to_string().into()))
}

async fn body<T: serde::de::DeserializeOwned>(request: Request<Incoming>) -> Result<T, Failure> {
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        Limited::new(request.into_body(), 4096).collect(),
    )
    .await
    .map_err(|_| Failure::InvalidRequest)?
    .map_err(|_| Failure::InvalidRequest)?;
    serde_json::from_slice(&bytes.to_bytes()).map_err(|_| Failure::InvalidRequest)
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut reply = Response::new(Full::new(body));
    *reply.status_mut() = status;
    reply
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    reply
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    reply
}
