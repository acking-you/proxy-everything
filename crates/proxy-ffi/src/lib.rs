//! C FFI interface for cross-platform integration.
//!
//! This module provides a C-compatible interface for external applications to use the proxy client.
//! It reuses the existing client module logic.

use malloc_best_effort::BEMalloc;
use std::sync::Once;

mod handle;
mod latency;
mod logging;
mod nodes;
mod types;

#[global_allocator]
static GLOBAL_ALLOCATOR: BEMalloc = BEMalloc::new();

static ALLOCATOR_INIT: Once = Once::new();

pub(crate) fn init_allocator() {
    ALLOCATOR_INIT.call_once(|| {
        BEMalloc::init();
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
