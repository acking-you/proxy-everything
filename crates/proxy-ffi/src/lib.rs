//! C FFI interface for cross-platform integration.
//!
//! This module provides a C-compatible interface for external applications to use the proxy client.
//! It reuses the existing client module logic.

use std::sync::Once;

use better_mimalloc_rs::{MiMalloc, MiMallocConfig};

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
pub use handle::{
    ProxyHandle, proxy_create, proxy_destroy, proxy_is_running, proxy_start, proxy_stop,
};
pub use latency::{proxy_free_latency_result, proxy_test_latency};
pub use logging::{proxy_free_string, proxy_init_logging, proxy_set_log_callback};
pub use nodes::{proxy_free_nodes_result, proxy_get_server_nodes};
pub use types::{
    LatencyResult, LogCallback, NodeInfoWithGeo, NodesResult, ProxyConfig, ProxyResult,
};
