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
    // Stable application cache directory; recommended on every platform.
    pub cache_dir: *const c_char,
    pub need_codec_ips: *const c_char, // comma-separated IPs (default: null = empty list)
    pub force_codec: c_int,            // default: 0 = only specified IPs use codec
    pub set_system_proxy: c_int,       // desktop only: 0 = disabled, 1 = set system proxy
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

/// Versioned proxy configuration with local TUN traffic capture.
///
/// The V1 and V2 layouts and entry points remain unchanged. TUN mode is
/// disabled for those callers, preserving their existing behavior.
#[repr(C)]
pub struct ProxyConfigV3 {
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
    pub enable_udp: c_int,
    pub enable_tun: c_int,
    /// JSON array of executable names. The current executable is always added
    /// internally and cannot be removed through this field.
    pub tun_bypass_processes: *const c_char,
}

/// Versioned proxy configuration with explicit TUN UDP fallback policy.
///
/// V1-V3 callers retain direct UDP fallback when SOCKS5 UDP is disabled.
#[repr(C)]
pub struct ProxyConfigV4 {
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
    pub enable_udp: c_int,
    pub enable_tun: c_int,
    pub tun_bypass_processes: *const c_char,
    /// 0 blocks captured non-DNS UDP when UDP proxying is disabled; non-zero
    /// relays it directly.
    pub tun_udp_direct_fallback: c_int,
}

/// Versioned proxy configuration with explicit local listener exposure.
///
/// V1-V4 callers remain loopback-only. V5 callers may opt into listening on
/// all IPv4 interfaces so trusted LAN devices can use the local proxy.
#[repr(C)]
pub struct ProxyConfigV5 {
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
    pub enable_udp: c_int,
    pub enable_tun: c_int,
    pub tun_bypass_processes: *const c_char,
    pub tun_udp_direct_fallback: c_int,
    /// 0 listens on 127.0.0.1; non-zero listens on 0.0.0.0.
    pub allow_lan: c_int,
}

/// Version 7 selects legacy (0) or zero-RTT v3 (3).
#[repr(C)]
pub struct ProxyConfigV7 {
    pub base: ProxyConfigV5,
    pub wire_protocol: c_int,
}

/// Result of latency test.
#[repr(C)]
pub struct LatencyResult {
    pub success: c_int,
    pub latency_ms: u64,
    pub error: *mut c_char,
}

/// What a node's traffic actually looks like from the outside.
///
/// The catalogue reports where a node is registered, which is not necessarily
/// where its traffic leaves from. This carries the egress address observed by
/// asking an echo service through the node itself.
#[repr(C)]
pub struct NodeProbeResult {
    pub success: c_int,
    /// ISO 3166-1 alpha-2, empty when the probe failed.
    pub country_code: *mut c_char,
    /// The address the echo service saw, empty when the probe failed.
    pub egress_ip: *mut c_char,
    /// Round trip through the node, including the echo request.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_config_layouts_preserve_legacy_field_offsets() {
        macro_rules! assert_same_offset {
            ($left:ty, $right:ty, $field:ident) => {
                assert_eq!(
                    std::mem::offset_of!($left, $field),
                    std::mem::offset_of!($right, $field),
                    "offset changed for {}",
                    stringify!($field)
                );
            };
        }

        assert_eq!(std::mem::offset_of!(ProxyConfigV7, base), 0);
        assert_eq!(
            std::mem::offset_of!(ProxyConfigV7, wire_protocol),
            std::mem::size_of::<ProxyConfigV5>()
        );

        assert_same_offset!(ProxyConfig, ProxyConfigV2, server_host);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, server_port);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, local_port);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, session_key);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, auto_proxy);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, reverse_geo);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, cache_dir);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, need_codec_ips);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, force_codec);
        assert_same_offset!(ProxyConfig, ProxyConfigV2, set_system_proxy);

        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, server_host);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, server_port);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, local_port);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, session_key);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, auto_proxy);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, reverse_geo);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, cache_dir);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, need_codec_ips);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, force_codec);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, set_system_proxy);
        assert_same_offset!(ProxyConfigV2, ProxyConfigV3, enable_udp);

        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, server_host);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, server_port);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, local_port);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, session_key);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, auto_proxy);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, reverse_geo);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, cache_dir);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, need_codec_ips);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, force_codec);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, set_system_proxy);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, enable_udp);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, enable_tun);
        assert_same_offset!(ProxyConfigV3, ProxyConfigV4, tun_bypass_processes);

        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, server_host);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, server_port);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, local_port);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, session_key);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, auto_proxy);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, reverse_geo);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, cache_dir);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, need_codec_ips);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, force_codec);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, set_system_proxy);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, enable_udp);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, enable_tun);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, tun_bypass_processes);
        assert_same_offset!(ProxyConfigV4, ProxyConfigV5, tun_udp_direct_fallback);
    }
}
