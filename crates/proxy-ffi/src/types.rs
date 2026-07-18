//! C-compatible type definitions for FFI interface.

use std::ffi::{c_char, c_int};

/// Log callback function type.
/// level: 0=trace, 1=debug, 2=info, 3=warn, 4=error
pub type LogCallback = extern "C" fn(level: c_int, message: *const c_char);

/// Result codes for FFI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyResult {
    Ok = 0,
    InvalidParam = -1,
    ConnectionFailed = -2,
    RuntimeError = -3,
    AlreadyRunning = -4,
    NotRunning = -5,
}

/// Proxy configuration passed from Swift/Kotlin.
#[repr(C)]
pub struct ProxyConfig {
    pub server_host: *const c_char,
    pub server_port: u16,
    pub local_port: u16,
    pub session_key: *const c_char, // can be null to use default key
    pub auto_proxy: c_int,          // 0 = disabled, 1 = enabled
    pub reverse_geo: c_int,         // 0 = CN direct, 1 = CN proxy
    pub cache_dir: *const c_char,   // cache directory for auto-proxy (required on mobile)
    pub need_codec_ips: *const c_char, // comma-separated IPs (default: null = empty list)
    pub force_codec: c_int,         // default: 0 = only specified IPs use codec
    pub set_system_proxy: c_int,    // desktop only: 0 = disabled, 1 = set system proxy
}

/// Versioned proxy configuration with SOCKS5 UDP control.
///
/// `ProxyConfig` and `proxy_start` remain unchanged so applications built
/// against the original C ABI continue to start with UDP enabled.
#[repr(C)]
pub struct ProxyConfigV2 {
    pub server_host: *const c_char,
    pub server_port: u16,
    pub local_port: u16,
    pub session_key: *const c_char,
    pub auto_proxy: c_int,
    pub reverse_geo: c_int,
    pub cache_dir: *const c_char,
    pub need_codec_ips: *const c_char,
    pub force_codec: c_int,
    pub set_system_proxy: c_int,
    pub enable_udp: c_int, // 0 = reject UDP ASSOCIATE, non-zero = accept
}

/// Result of latency test.
#[repr(C)]
pub struct LatencyResult {
    pub success: c_int,
    pub latency_ms: u64,
    pub error: *mut c_char,
}

/// Node info with geo location.
#[repr(C)]
pub struct NodeInfoWithGeo {
    pub node_id: *mut c_char,
    pub addr: *mut c_char,
    pub last_seen_ms: i64,
    pub country: *mut c_char,
    pub region: *mut c_char,
}

/// Node group information.
#[repr(C)]
pub struct NodeGroupInfo {
    pub group_id: *mut c_char,
    pub name: *mut c_char,
    pub node_ids: *mut *mut c_char,
    pub node_ids_count: usize,
    pub created_at_ms: i64,
}

/// Result of get server nodes.
#[repr(C)]
pub struct NodesResult {
    pub success: c_int,
    pub nodes: *mut NodeInfoWithGeo,
    pub count: usize,
    pub error: *mut c_char,
}

/// Result of get server groups.
#[repr(C)]
pub struct GroupsResult {
    pub success: c_int,
    pub groups: *mut NodeGroupInfo,
    pub count: usize,
    pub error: *mut c_char,
}
