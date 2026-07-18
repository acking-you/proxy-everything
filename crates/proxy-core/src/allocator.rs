//! Process-wide allocator policy for every proxy executable and FFI library.
//!
//! Keeping the allocator here ensures the client, server, TUI, administration
//! tools, Flutter FFI, and embedded TUN stack all use one mimalloc instance and
//! one set of RSS-reclamation options.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::Once;

use better_mimalloc_rs::{MiMalloc, MiMallocConfig};

/// Global allocator used by every final artifact that links `proxy-core`.
pub struct ProxyAllocator;

static ALLOCATOR_INIT: Once = Once::new();

fn allocator_config() -> MiMallocConfig {
    // Preserve the original proxy-everything tuning exactly. These settings
    // trade some allocation throughput for prompt decommit and lower RSS after
    // traffic bursts.
    MiMallocConfig {
        eager_commit: Some(false),
        eager_commit_delay: Some(0),
        arena_eager_commit: Some(0),
        purge_decommits: Some(true),
        purge_delay: Some(0),
        arena_purge_mult: Some(1),
        purge_extend_delay: Some(0),
        generic_collect: Some(200),
    }
}

/// Apply the proxy allocator policy once for the current process or library.
///
/// The configured allocator calls this automatically before its first Rust
/// allocation. It remains public so FFI entry points can initialize the policy
/// explicitly before constructing runtimes or other allocation-heavy state.
#[inline]
pub fn initialize() {
    ALLOCATOR_INIT.call_once(|| MiMalloc::init_with(&allocator_config()));
}

unsafe impl GlobalAlloc for ProxyAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        initialize();
        unsafe { GlobalAlloc::alloc(&MiMalloc, layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        initialize();
        unsafe { GlobalAlloc::alloc_zeroed(&MiMalloc, layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        initialize();
        unsafe { GlobalAlloc::dealloc(&MiMalloc, ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        initialize();
        unsafe { GlobalAlloc::realloc(&MiMalloc, ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: ProxyAllocator = ProxyAllocator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_policy_matches_original_proxy_tuning() {
        let config = allocator_config();

        assert_eq!(config.eager_commit, Some(false));
        assert_eq!(config.eager_commit_delay, Some(0));
        assert_eq!(config.arena_eager_commit, Some(0));
        assert_eq!(config.purge_decommits, Some(true));
        assert_eq!(config.purge_delay, Some(0));
        assert_eq!(config.arena_purge_mult, Some(1));
        assert_eq!(config.purge_extend_delay, Some(0));
        assert_eq!(config.generic_collect, Some(200));
    }

    #[test]
    fn allocator_initialization_is_idempotent() {
        initialize();
        initialize();

        let mut data = Vec::with_capacity(32);
        data.extend(0..32);
        assert_eq!(data.len(), 32);
    }
}
