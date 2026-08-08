//! Tokio runtimes shared by the FFI surface.
//!
//! `Runtime::new()` sizes the worker pool to the core count, which on a desktop
//! with 32 logical cores spawns 32 workers for a workload that spends nearly all
//! of its time waiting on sockets, and allows up to 512 blocking threads on top.

use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

/// Workers for proxy forwarding.
///
/// Four keeps several cores reachable during a burst without paying for idle
/// workers, their local queues, and their stacks for the rest of the session.
const FORWARDING_WORKER_THREADS: usize = 4;

/// Nothing on this path needs more than a handful of blocking threads, and each
/// one reserves a stack.
const MAX_BLOCKING_THREADS: usize = 32;

/// Build a runtime for a proxy handle.
pub(crate) fn build() -> std::io::Result<Runtime> {
    Builder::new_multi_thread()
        .worker_threads(FORWARDING_WORKER_THREADS)
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
}

/// Runtime shared by the short-lived control-plane queries.
///
/// Node and group lookups used to build an entire multi-threaded runtime per
/// call, so every refresh of the node list spun up and tore down one worker
/// thread per core.
pub(crate) fn control() -> Option<&'static Runtime> {
    static CONTROL: OnceLock<Option<Runtime>> = OnceLock::new();
    CONTROL.get_or_init(|| build().ok()).as_ref()
}
