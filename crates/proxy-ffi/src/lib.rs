//! C FFI interface for cross-platform integration.
//!
//! This module provides a C-compatible interface for external applications to use the proxy client.
//! It reuses the existing client module logic.

use std::sync::Once;

use better_mimalloc_rs::{MiMalloc, MiMallocConfig};

mod groups;
mod handle;
mod latency;
mod logging;
mod nodes;
mod types;

#[global_allocator]
static GLOBAL_ALLOCATOR: MiMalloc = MiMalloc;

static ALLOCATOR_INIT: Once = Once::new();

pub(crate) fn init_allocator() {
    ALLOCATOR_INIT.call_once(|| {
        // Aggressive RSS reclamation: prioritize faster decommit over raw throughput.
        let config = MiMallocConfig {
            eager_commit: Some(false),
            eager_commit_delay: Some(0),
            arena_eager_commit: Some(0),
            purge_decommits: Some(true),
            purge_delay: Some(0),
            arena_purge_mult: Some(1),
            purge_extend_delay: Some(0),
            generic_collect: Some(200),
        };
        MiMalloc::init_with(&config);
    });
}

// Re-export all public FFI functions and types
pub use groups::{proxy_free_groups_result, proxy_get_server_groups};
pub use handle::{
    ProxyHandle, proxy_create, proxy_destroy, proxy_get_last_error, proxy_get_tun_self_process,
    proxy_is_elevated, proxy_is_running, proxy_is_tun_running, proxy_list_tun_processes,
    proxy_list_tun_processes_v2, proxy_relaunch_elevated_for_tun, proxy_set_tun_bypass_processes,
    proxy_start, proxy_start_tun, proxy_start_v2, proxy_start_v3, proxy_stop, proxy_stop_tun,
    proxy_switch_upstream,
};
pub use latency::{proxy_free_latency_result, proxy_test_latency};
pub use logging::{proxy_free_string, proxy_init_logging, proxy_set_log_callback};
pub use nodes::{proxy_free_nodes_result, proxy_get_server_nodes};
pub use types::{
    GroupsResult, LatencyResult, LogCallback, NodeGroupInfo, NodeInfoWithGeo, NodesResult,
    ProxyConfig, ProxyConfigV2, ProxyConfigV3, ProxyResult,
};
