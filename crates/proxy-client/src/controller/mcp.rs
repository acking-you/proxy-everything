//! The controller's operations as Model Context Protocol tools, served over
//! Streamable HTTP at [`PATH`] behind the controller's bearer token.
//!
//! Three tools cover the whole API, and each returns the same [`ProxyState`],
//! so a code-mode client programs against one generated result type.
use std::sync::Arc;

use proxy_core::upstream::{Carrier, UpstreamAddress};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{Json, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::{ApiError, Host, Node, Selection, Shared, Status, TargetInput};
use crate::site_rules::{NodeId, RuleSet, Site, Target};

pub(super) const PATH: &str = "/mcp";
const MAX_BODY_BYTES: usize = 64 * 1024;
const INSTRUCTIONS: &str = "CipherRelay is the local encrypted proxy on this computer. \
                            get_proxy_state reads the listener, the upstream new connections use, \
                            the selectable nodes and the website rules. switch_node selects the \
                            node and transport for new connections. set_website_rule sends one \
                            website directly or through a chosen node, or back to the default \
                            route. Changes apply to connections opened afterwards; switch_node \
                            can also close open ones. Every tool returns the resulting state.";

pub(super) type Service<H> = StreamableHttpService<Tools<H>, NeverSessionManager>;

/// Stateless, with plain JSON responses: every tool answers in one reply.
pub(super) fn service<H: Host>(shared: Arc<Shared<H>>, stop: CancellationToken) -> Service<H> {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_max_request_body_bytes(MAX_BODY_BYTES)
        .with_cancellation_token(stop);
    StreamableHttpService::new(
        move || Ok(Tools::new(shared.clone())),
        Arc::default(),
        config,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum Transport {
    Tcp,
    Quic,
}

impl From<Carrier> for Transport {
    fn from(carrier: Carrier) -> Self {
        match carrier {
            Carrier::Tcp => Self::Tcp,
            Carrier::Quic => Self::Quic,
        }
    }
}

impl From<Transport> for Carrier {
    fn from(transport: Transport) -> Self {
        match transport {
            Transport::Tcp => Self::Tcp,
            Transport::Quic => Self::Quic,
        }
    }
}

/// Where a node is reached.
#[derive(Serialize, JsonSchema)]
pub(super) struct Endpoint {
    host: String,
    port: u16,
    transport: Transport,
}

impl From<&UpstreamAddress> for Endpoint {
    fn from(address: &UpstreamAddress) -> Self {
        Self {
            host: address.host.clone(),
            port: address.port,
            transport: address.carrier.into(),
        }
    }
}

#[derive(Serialize, JsonSchema)]
pub(super) struct NodeEntry {
    id: String,
    /// At most one per transport.
    endpoints: Vec<Endpoint>,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct ActiveUpstream {
    /// Null when the endpoint is not in the node list.
    node_id: Option<String>,
    endpoint: Endpoint,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum RuleRoute {
    Direct,
    Node,
}

#[derive(Serialize, JsonSchema)]
pub(super) struct WebsiteRule {
    /// Canonical form: `[*.]host[:port]`.
    site: String,
    route: RuleRoute,
    /// Set when the route is `node`.
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    /// The endpoint pinned when the rule was saved, for a `node` route.
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<Endpoint>,
}

/// What every tool returns.
#[derive(Serialize, JsonSchema)]
pub(super) struct ProxyState {
    /// Whether the local proxy listener is running.
    running: bool,
    local_port: Option<u16>,
    /// The upstream new connections use; null while stopped.
    active: Option<ActiveUpstream>,
    /// Selectable nodes, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<Vec<NodeEntry>>,
    /// Saved website rules, sorted by site.
    website_rules: Vec<WebsiteRule>,
}

impl ProxyState {
    fn new(status: Status, nodes: Option<Vec<Node>>, rules: &RuleSet) -> Self {
        let Status {
            running,
            local_port,
            active,
        } = status;
        Self {
            running,
            local_port,
            active: active.map(|active| ActiveUpstream {
                node_id: active.node_id.map(String::from),
                endpoint: (&active.endpoint).into(),
            }),
            nodes: nodes.map(|nodes| {
                nodes
                    .into_iter()
                    .map(|node| NodeEntry {
                        endpoints: node.endpoints.iter().map(Endpoint::from).collect(),
                        id: node.id.into(),
                    })
                    .collect()
            }),
            website_rules: rules
                .rules()
                .iter()
                .map(|rule| match &rule.target {
                    Target::Direct => WebsiteRule {
                        site: rule.site.to_string(),
                        route: RuleRoute::Direct,
                        node_id: None,
                        endpoint: None,
                    },
                    Target::Node { node_id, endpoint } => WebsiteRule {
                        site: rule.site.to_string(),
                        route: RuleRoute::Node,
                        node_id: Some(node_id.to_string()),
                        endpoint: Some(endpoint.into()),
                    },
                })
                .collect(),
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct StateRequest {
    /// Include the node list. Leave it out of repeated reads to save tokens.
    #[serde(default = "yes")]
    include_nodes: bool,
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct SwitchRequest {
    /// A node ID from get_proxy_state.
    node_id: String,
    /// Defaults to TCP when the node offers it, otherwise its only transport.
    transport: Option<Transport>,
    /// Also close the connections already open through the local proxy.
    #[serde(default)]
    close_existing: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum Route {
    /// Connect without a proxy.
    Direct,
    /// Always use `node_id`, over `transport`.
    Node,
    /// Delete the rule, so the website follows the normal routing again.
    Default,
}

#[derive(Deserialize, JsonSchema)]
pub(super) struct RuleRequest {
    /// `example.com`, or `*.example.com` for every subdomain but not the
    /// domain itself, either optionally with `:port`; an IP address; or an
    /// http(s) URL, whose host and effective port are kept.
    site: String,
    route: Route,
    /// Required when `route` is `node`.
    node_id: Option<String>,
    /// For a `node` route. Defaults as in switch_node.
    transport: Option<Transport>,
}

pub(super) struct Tools<H> {
    shared: Arc<Shared<H>>,
    tool_router: ToolRouter<Self>,
}

impl<H> Clone for Tools<H> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            tool_router: self.tool_router.clone(),
        }
    }
}

#[tool_router]
impl<H: Host> Tools<H> {
    fn new(shared: Arc<Shared<H>>) -> Self {
        Self {
            shared,
            tool_router: Self::tool_router(),
        }
    }

    /// Read the proxy's state: listener, active upstream, nodes and website rules.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn get_proxy_state(
        &self,
        params: Parameters<StateRequest>,
    ) -> Result<Json<ProxyState>, String> {
        let shared = &self.shared;
        let nodes = match params.0.include_nodes {
            true => Some(shared.host.nodes().await.map_err(failure)?),
            false => None,
        };
        let status = shared.host.status().await.map_err(failure)?;
        Ok(Json(ProxyState::new(
            status,
            nodes,
            &shared.rules.snapshot(),
        )))
    }

    /// Select the node and transport that new proxy connections use. The local
    /// listener keeps running; the proxy must already be started.
    #[tool(annotations(destructive_hint = false, open_world_hint = false))]
    async fn switch_node(
        &self,
        params: Parameters<SwitchRequest>,
    ) -> Result<Json<ProxyState>, String> {
        let SwitchRequest {
            node_id,
            transport,
            close_existing,
        } = params.0;
        let status = async {
            let node_id = node_id_from(node_id)?;
            let transport = self.transport(&node_id, transport).await?;
            self.shared
                .host
                .switch(Selection {
                    node_id,
                    transport,
                    close_existing,
                })
                .await
        }
        .await
        .map_err(failure)?;
        Ok(Json(ProxyState::new(
            status,
            None,
            &self.shared.rules.snapshot(),
        )))
    }

    /// Route one website: directly, through a chosen node, or back to the
    /// default route. The most specific rule wins: an exact host beats
    /// *.domain, and a rule with a port beats one without. Saved rules persist.
    #[tool(annotations(destructive_hint = false, open_world_hint = false))]
    async fn set_website_rule(
        &self,
        params: Parameters<RuleRequest>,
    ) -> Result<Json<ProxyState>, String> {
        let RuleRequest {
            site,
            route,
            node_id,
            transport,
        } = params.0;
        let shared = &self.shared;
        let rules = async {
            let site: Site = site.parse().map_err(|_| ApiError::InvalidRule)?;
            match route {
                Route::Default => shared.remove_rule(site).await,
                Route::Direct => shared.set_rule(site, TargetInput::Direct).await,
                Route::Node => {
                    let node_id = node_id_from(node_id.ok_or(ApiError::InvalidRule)?)?;
                    let transport = self.transport(&node_id, transport).await?;
                    shared
                        .set_rule(site, TargetInput::Node { node_id, transport })
                        .await
                }
            }
        }
        .await
        .map_err(failure)?;
        let status = shared.host.status().await.map_err(failure)?;
        Ok(Json(ProxyState::new(status, None, &rules)))
    }

    /// The requested transport, or the node's default one.
    async fn transport(
        &self,
        node_id: &NodeId,
        requested: Option<Transport>,
    ) -> Result<Carrier, ApiError> {
        if let Some(transport) = requested {
            return Ok(transport.into());
        }
        let nodes = self.shared.host.nodes().await?;
        let node = nodes
            .iter()
            .find(|node| node.id == *node_id)
            .ok_or(ApiError::UnknownNode)?;
        node.endpoint(Carrier::Tcp)
            .or_else(|| node.endpoints.first())
            .map(|endpoint| endpoint.carrier)
            .ok_or(ApiError::UnsupportedTransport)
    }
}

#[tool_handler]
impl<H: Host> ServerHandler for Tools<H> {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cipherrelay", env!("CARGO_PKG_VERSION"))
                    .with_title("CipherRelay"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

fn node_id_from(id: String) -> Result<NodeId, ApiError> {
    NodeId::try_from(id).map_err(|_| ApiError::UnknownNode)
}

/// A tool error the model can act on: the stable kind, then what to do.
fn failure(error: ApiError) -> String {
    match serde_json::to_value(error) {
        Ok(serde_json::Value::String(kind)) => format!("{kind}: {error}"),
        _ => error.to_string(),
    }
}
