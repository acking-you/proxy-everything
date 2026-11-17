//! Authenticated loopback HTTP API shared by the CLI and the desktop app.
//!
//! The controller owns HTTP, authentication, error kinds and website rules.
//! What depends on the live proxy — its node catalogue, listener state and
//! upstream switching — belongs to a [`Host`] that the embedding process
//! implements.
use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use proxy_core::upstream::{Carrier, UpstreamAddress};
use proxy_core::util::error_report;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::site_rules::{NodeId, Rule, RuleSet, RulesError, Site, SiteRules, Target};

const OPENAPI: &[u8] = include_bytes!("openapi.json");
const MAX_CONNECTIONS: usize = 32;
const MAX_BODY_BYTES: usize = 4096;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds slow clients and a host that never answers. A switch the host has
/// already started still finishes there.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Snafu)]
#[snafu(display("A controller token is 32 to 256 printable ASCII characters without spaces"))]
pub struct InvalidToken;

/// The bearer secret, separate from every proxy and control-plane credential.
#[derive(Clone)]
pub struct Token(Arc<str>);

impl TryFrom<String> for Token {
    type Error = InvalidToken;

    fn try_from(token: String) -> Result<Self, InvalidToken> {
        if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(InvalidToken);
        }
        Ok(Self(token.into()))
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    fn authorizes(&self, header: Option<&HeaderValue>) -> bool {
        let supplied = header
            .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
            .unwrap_or_default();
        supplied.ct_eq(self.0.as_bytes()).into()
    }
}

/// A selectable node and the endpoints it can be reached on, at most one per
/// carrier.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: NodeId,
    pub endpoints: Vec<UpstreamAddress>,
}

impl Node {
    pub fn endpoint(&self, carrier: Carrier) -> Option<&UpstreamAddress> {
        self.endpoints.iter().find(|e| e.carrier == carrier)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nodes {
    pub nodes: Vec<Node>,
}

/// The local listener and the upstream new connections use.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub running: bool,
    pub local_port: Option<u16>,
    pub active: Option<Active>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Active {
    /// Null when the endpoint is outside the catalogue.
    pub node_id: Option<NodeId>,
    pub endpoint: UpstreamAddress,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub node_id: NodeId,
    pub transport: Carrier,
    /// Close the listener's open sessions once the switch has succeeded.
    #[serde(default)]
    pub close_existing: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    site: Site,
    target: TargetInput,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum TargetInput {
    Direct,
    Node { node_id: NodeId, transport: Carrier },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRemoval {
    site: Site,
}

/// Stable error kinds. Callers branch on the kind; the message says what to
/// do. Causes stay in the local log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Snafu)]
#[serde(rename_all = "snake_case")]
pub enum ApiError {
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

impl ApiError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound | Self::UnknownNode => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::InvalidRequest | Self::InvalidRule => StatusCode::BAD_REQUEST,
            Self::RuleStorage | Self::NotRunning | Self::Busy | Self::SwitchFailed => {
                StatusCode::CONFLICT
            }
            Self::UnsupportedTransport => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl From<RulesError> for ApiError {
    fn from(error: RulesError) -> Self {
        match error {
            RulesError::Read { .. }
            | RulesError::TooLarge { .. }
            | RulesError::Decode { .. }
            | RulesError::Write { .. }
            | RulesError::Invalid { .. } => Self::RuleStorage,
        }
    }
}

/// What the controller needs from the process that owns the live proxy.
///
/// Calls can arrive concurrently. A host that cannot run two switches at once
/// answers the second with [`ApiError::Busy`].
pub trait Host: Send + Sync + 'static {
    fn nodes(&self) -> impl Future<Output = Result<Vec<Node>, ApiError>> + Send;

    fn status(&self) -> impl Future<Output = Result<Status, ApiError>> + Send;

    /// Select the upstream for new connections and return the committed status.
    fn switch(&self, selection: Selection)
    -> impl Future<Output = Result<Status, ApiError>> + Send;

    /// The controller replaced the website rules, for hosts that display them.
    fn rules_changed(&self, rules: Arc<RuleSet>) -> impl Future<Output = ()> + Send {
        let _ = rules;
        async {}
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("Could not bind the local controller to 127.0.0.1:{port}"))]
pub struct BindError {
    port: u16,
    source: io::Error,
}

/// A bound controller. [`Controller::serve`] answers requests until dropped.
pub struct Controller<H> {
    listener: TcpListener,
    shared: Arc<Shared<H>>,
}

struct Shared<H> {
    token: Token,
    host: H,
    rules: Arc<SiteRules>,
}

impl<H: Host> Controller<H> {
    /// Port zero picks a free port.
    pub async fn bind(
        port: u16,
        token: Token,
        host: H,
        rules: Arc<SiteRules>,
    ) -> Result<Self, BindError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .context(BindSnafu { port })?;
        Ok(Self {
            listener,
            shared: Arc::new(Shared { token, host, rules }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Never returns. Dropping the future closes the listener and every open
    /// connection.
    pub async fn serve(self) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let socket = match accepted {
                        Ok((socket, _)) => socket,
                        Err(error) => {
                            tracing::warn!(%error, "local controller accept failed; retrying");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    connections.spawn(serve_connection(socket, self.shared.clone()));
                }
            }
        }
    }
}

async fn serve_connection<H: Host>(socket: tokio::net::TcpStream, shared: Arc<Shared<H>>) {
    let service = service_fn(move |request| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(shared.respond(request).await) }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(8192)
        .keep_alive(false)
        .serve_connection(TokioIo::new(socket), service);
    match tokio::time::timeout(CONNECTION_TIMEOUT, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%error, "local controller connection failed"),
        Err(_) => tracing::debug!("local controller connection timed out"),
    }
}

#[derive(Clone, Copy)]
enum Route {
    OpenApi,
    Nodes,
    Status,
    Switch,
    Rules,
    SetRule,
    RemoveRule,
}

impl Route {
    fn find(method: &Method, path: &str) -> Result<Self, ApiError> {
        let allowed: &[(Method, Self)] = match path {
            "/v1/openapi.json" => &[(Method::GET, Self::OpenApi)],
            "/v1/nodes" => &[(Method::GET, Self::Nodes)],
            "/v1/status" => &[(Method::GET, Self::Status)],
            "/v1/switch" => &[(Method::POST, Self::Switch)],
            "/v1/rules" => &[
                (Method::GET, Self::Rules),
                (Method::PUT, Self::SetRule),
                (Method::DELETE, Self::RemoveRule),
            ],
            _ => return Err(ApiError::NotFound),
        };
        allowed
            .iter()
            .find(|(allowed, _)| allowed == method)
            .map(|&(_, route)| route)
            .ok_or(ApiError::MethodNotAllowed)
    }
}

impl<H: Host> Shared<H> {
    async fn respond(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match self.answer(request).await {
            Ok(body) => response(StatusCode::OK, body),
            Err(error) => {
                #[derive(Serialize)]
                struct Body {
                    error: Detail,
                }
                #[derive(Serialize)]
                struct Detail {
                    kind: ApiError,
                    message: String,
                }
                let body = Body {
                    error: Detail {
                        kind: error,
                        message: error.to_string(),
                    },
                };
                response(error.status(), encode(&body).unwrap_or_default())
            }
        }
    }

    async fn answer(&self, request: Request<Incoming>) -> Result<Bytes, ApiError> {
        // A browser page names its origin. Only local programs may call.
        if !self.token.authorizes(request.headers().get(AUTHORIZATION))
            || request.headers().contains_key(ORIGIN)
        {
            return Err(ApiError::Unauthorized);
        }
        match Route::find(request.method(), request.uri().path())? {
            Route::OpenApi => Ok(Bytes::from_static(OPENAPI)),
            Route::Nodes => encode(&Nodes {
                nodes: self.host.nodes().await?,
            }),
            Route::Status => encode(&self.host.status().await?),
            Route::Switch => {
                let selection = read_json(request, ApiError::InvalidRequest).await?;
                encode(&self.host.switch(selection).await?)
            }
            Route::Rules => encode(&*self.rules.snapshot()),
            Route::SetRule => {
                let RuleInput { site, target } = read_json(request, ApiError::InvalidRule).await?;
                let rule = Rule {
                    site,
                    target: self.target(target).await?,
                };
                self.edit_rules(move |rules| rules.set(rule)).await
            }
            Route::RemoveRule => {
                let RuleRemoval { site } = read_json(request, ApiError::InvalidRule).await?;
                self.edit_rules(move |rules| rules.remove(&site)).await
            }
        }
    }

    /// Pin a node rule to the endpoint the catalogue lists now.
    async fn target(&self, input: TargetInput) -> Result<Target, ApiError> {
        let (node_id, transport) = match input {
            TargetInput::Direct => return Ok(Target::Direct),
            TargetInput::Node { node_id, transport } => (node_id, transport),
        };
        let nodes = self.host.nodes().await?;
        let node = nodes
            .iter()
            .find(|node| node.id == node_id)
            .ok_or(ApiError::UnknownNode)?;
        let endpoint = node
            .endpoint(transport)
            .ok_or(ApiError::UnsupportedTransport)?
            .clone();
        Ok(Target::Node { node_id, endpoint })
    }

    async fn edit_rules(
        &self,
        edit: impl FnOnce(&SiteRules) -> Result<Arc<RuleSet>, RulesError> + Send + 'static,
    ) -> Result<Bytes, ApiError> {
        let rules = self.rules.clone();
        let edited = tokio::task::spawn_blocking(move || edit(&rules))
            .await
            .map_err(|_| ApiError::Unavailable)?
            .map_err(|error| {
                tracing::warn!(error = %error_report(&error), "website rule update failed");
                ApiError::from(error)
            })?;
        let body = encode(&*edited)?;
        self.host.rules_changed(edited).await;
        Ok(body)
    }
}

async fn read_json<T: DeserializeOwned>(
    request: Request<Incoming>,
    invalid: ApiError,
) -> Result<T, ApiError> {
    let body = tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(request.into_body(), MAX_BODY_BYTES).collect(),
    )
    .await
    .map_err(|_| invalid)?
    .map_err(|_| invalid)?;
    serde_json::from_slice(&body.to_bytes()).map_err(|_| invalid)
}

fn encode(value: &impl Serialize) -> Result<Bytes, ApiError> {
    serde_json::to_vec(value).map(Bytes::from).map_err(|error| {
        tracing::error!(%error, "could not encode a local controller response");
        ApiError::Unavailable
    })
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
