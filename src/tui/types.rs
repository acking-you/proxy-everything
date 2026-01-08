//! TUI type definitions.

use std::collections::HashMap;

use clap::Parser;

use crate::config::SERVER_PORT;
use crate::metrics::{ConnectionRecord, RealtimeSnapshot, TimeBucket};
use crate::nodes::NodeInfo;

pub const TAB_COUNT: usize = 4;
pub const TAB_TITLES: [&str; TAB_COUNT] = ["Nodes", "Realtime", "Connections", "Top-N"];

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
    pub realtime: Option<RealtimeSnapshot>,
    pub connections: Vec<ConnectionRecord>,
    pub buckets: Vec<TimeBucket>,
    pub top_hosts: Vec<(String, u64)>,
    pub top_ips: Vec<(String, u64)>,
}

/// UI state.
pub struct AppState {
    pub tab_index: usize,
    pub selected_node: usize,
    pub data: Option<FetchedData>,
    pub loading: bool,
    pub error: Option<String>,
    // Add node dialog
    pub show_add_dialog: bool,
    pub add_node_input: String,
    pub add_node_error: Option<String>,
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
            data: None,
            error: None,
            show_add_dialog: false,
            add_node_input: String::new(),
            add_node_error: None,
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

/// Commands from UI to data fetcher.
pub enum DataCommand {
    Refresh,
    AddNode(String),
    RemoveNode(String),
    SwitchServer(String),
    QueryGeo(Vec<String>),
    Shutdown,
}

/// Results from data fetcher.
pub enum DataResult {
    Data(FetchedData, Option<String>),
    Geo(HashMap<String, String>),
    GeoError(String),
}
