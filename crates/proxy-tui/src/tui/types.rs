//! TUI type definitions.

use std::collections::HashMap;

use clap::Parser;
use proxy_core::config::SERVER_PORT;
use proxy_core::metrics::{ConnectionRecord, RealtimeSnapshot, TimeBucket};
use proxy_core::nodes::{NodeGroup, NodeInfo};
use proxy_core::relay::{LoadBalanceAlgo, RelayConfig, RelayStatus, UpstreamTarget};

pub const TAB_COUNT: usize = 6;
pub const TAB_TITLES: [&str; TAB_COUNT] = [
    "Nodes",
    "Groups",
    "Relay",
    "Realtime",
    "Connections",
    "Top-N",
];

#[derive(Parser, Clone)]
#[command(author, version, about = "Proxy TUI - Terminal UI for monitoring")]
pub struct Cli {
    /// Proxy server host
    #[arg(short = 'H', long)]
    pub server_host: String,
    /// Proxy server port
    #[arg(short, long, default_value_t = *SERVER_PORT)]
    pub server_port: u16,
    /// Admin token
    #[arg(short, long)]
    pub token: Option<String>,
    /// Session key (defaults to same as server/client)
    #[arg(short = 'k', long)]
    pub session_key: Option<String>,
    /// Refresh interval in seconds
    #[arg(short, long, default_value = "2")]
    pub refresh: u64,
    /// Use local GeoIP database instead of ip-api.com API
    #[arg(long, env = "USE_LOCAL_GEOIP")]
    pub use_local_geoip: bool,
}

/// Data fetched from server.
#[derive(Default, Clone)]
pub struct FetchedData {
    pub nodes: Vec<NodeInfo>,
    pub groups: Vec<NodeGroup>,
    pub realtime: Option<RealtimeSnapshot>,
    pub connections: Vec<ConnectionRecord>,
    pub buckets: Vec<TimeBucket>,
    pub top_hosts: Vec<(String, u64)>,
    pub top_ips: Vec<(String, u64)>,
    pub relay_config: Option<RelayConfig>,
    pub relay_status: Option<RelayStatus>,
}

/// UI state.
pub struct AppState {
    pub tab_index: usize,
    pub selected_node: usize,
    pub selected_group: usize,
    pub selected_relay_target: usize,
    pub data: Option<FetchedData>,
    pub loading: bool,
    pub error: Option<String>,
    // Input dialog
    pub show_input_dialog: bool,
    pub input_mode: Option<InputDialogMode>,
    pub input_value: String,
    pub input_error: Option<String>,
    // Server switching
    pub current_server: String,
    pub switching: bool,
    pub switch_target: Option<String>,
    pub anim_frame: usize,
    // Geo cache
    pub geo_cache: HashMap<String, String>,
    pub geo_error: Option<String>,
    // Pagination
    pub page_offset: usize,
    pub page_size: usize,
    // Filter
    pub filter_input: String,
    pub show_filter: bool,
}

impl AppState {
    pub fn new(server_host: &str, server_port: u16) -> Self {
        Self {
            loading: true,
            current_server: format!("{}:{}", server_host, server_port),
            tab_index: 0,
            selected_node: 0,
            selected_group: 0,
            selected_relay_target: 0,
            data: None,
            error: None,
            show_input_dialog: false,
            input_mode: None,
            input_value: String::new(),
            input_error: None,
            switching: false,
            switch_target: None,
            anim_frame: 0,
            geo_cache: HashMap::new(),
            geo_error: None,
            page_offset: 0,
            page_size: 20,
            filter_input: String::new(),
            show_filter: false,
        }
    }
}

/// Input dialog modes for mutating operations.
#[derive(Debug, Clone)]
pub enum InputDialogMode {
    AddNode,
    CreateGroup,
    AddNodeToGroup { group_id: String },
    RemoveNodeFromGroup { group_id: String },
    AddRelayTarget,
    SetRelayConfig,
}

/// Commands from UI to data fetcher.
pub enum DataCommand {
    Refresh,
    AddNode(String),
    RemoveNode(String),
    SwitchServer(String),
    QueryGeo(Vec<String>),
    // Group management
    CreateGroup { group_id: String, name: String },
    DeleteGroup(String),
    AddNodeToGroup { group_id: String, node_id: String },
    RemoveNodeFromGroup { group_id: String, node_id: String },
    // Relay configuration
    SetRelayEnabled(bool),
    AddRelayTarget(UpstreamTarget),
    RemoveRelayTarget(usize),
    SetRelayAlgo(LoadBalanceAlgo),
    SetRelayConfig(RelayConfig),
    Shutdown,
}

/// Results from data fetcher.
///
/// # Performance
/// The `Data` variant carries a full snapshot to avoid extra allocations in
/// the render loop, so we intentionally keep the enum size larger.
#[allow(clippy::large_enum_variant)]
pub enum DataResult {
    Data(FetchedData, Option<String>),
    Geo(HashMap<String, String>),
    GeoError(String),
}
