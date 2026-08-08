//! C FFI interface for cross-platform integration.
//!
//! This module provides a C-compatible interface for external applications to use the proxy client.
//! It reuses the existing client module logic.

mod groups;
mod handle;
mod latency;
mod logging;
mod nodes;
mod runtime;
mod types;

pub(crate) fn init_allocator() {
    proxy_core::allocator::initialize();
}

// Re-export all public FFI functions and types
pub use groups::{proxy_free_groups_result, proxy_get_server_groups};
#[cfg(target_os = "android")]
pub use handle::proxy_start_android_tun;
pub use handle::{
    ProxyHandle, proxy_create, proxy_destroy, proxy_get_last_error, proxy_get_tun_self_process,
    proxy_is_elevated, proxy_is_running, proxy_is_tun_running, proxy_list_tun_processes,
    proxy_list_tun_processes_v2, proxy_relaunch_elevated_for_tun, proxy_set_tun_bypass_processes,
    proxy_start, proxy_start_tun, proxy_start_v2, proxy_start_v3, proxy_start_v4, proxy_start_v5,
    proxy_stop, proxy_stop_tun, proxy_switch_upstream,
};
pub use latency::{proxy_free_latency_result, proxy_test_latency};
pub use logging::{
    proxy_free_string, proxy_init_logging, proxy_set_log_callback, proxy_set_log_level,
};
pub use nodes::{proxy_free_nodes_result, proxy_get_server_nodes};
pub use types::{
    GroupsResult, LatencyResult, LogCallback, NodeGroupInfo, NodeInfoWithGeo, NodesResult,
    ProxyConfig, ProxyConfigV2, ProxyConfigV3, ProxyConfigV4, ProxyConfigV5, ProxyResult,
};
