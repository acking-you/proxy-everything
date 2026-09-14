//! C ABI for the system-hosted packet tunnel. Swift owns the opaque handle.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use proxy_client::client::packet_tunnel::{
    PACKET_MTU, PacketTunnelConfig, PacketTunnelRuntime, PacketWrite,
};

/// Start the extension's local proxy and IP forwarding workers.
///
/// # Safety
/// `json` and `cache_dir` must be valid NUL-terminated UTF-8 strings; `error`
/// must be writable. Free a returned error with `proxy_free_string`. The handle
/// must be destroyed exactly once after all concurrent reads/writes finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_create(
    json: *const c_char,
    cache_dir: *const c_char,
    error: *mut *mut c_char,
) -> *mut PacketTunnelRuntime {
    if error.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        *error = ptr::null_mut();
    }
    let result = (|| -> Result<PacketTunnelRuntime, String> {
        if json.is_null() || cache_dir.is_null() {
            return Err("missing tunnel configuration".into());
        }
        let json = unsafe { CStr::from_ptr(json) }
            .to_str()
            .map_err(|_| "configuration is not UTF-8")?;
        if json.len() > 65536 {
            return Err("tunnel configuration is too large".into());
        }
        let mut config: PacketTunnelConfig =
            serde_json::from_str(json).map_err(|_| "invalid tunnel configuration")?;
        // The Store edition does not send destinations to a geographic service,
        // including configurations restored from older Keychain entries.
        config.auto_proxy = false;
        config.reverse_geo = false;
        let cache_dir = unsafe { CStr::from_ptr(cache_dir) }
            .to_str()
            .map_err(|_| "invalid cache directory")?;
        if !PathBuf::from(cache_dir).is_absolute() {
            return Err("cache directory must be absolute".into());
        }
        crate::init_process_policy();
        let runtime = crate::runtime::build().map_err(|error| error.to_string())?;
        PacketTunnelRuntime::start(config, PathBuf::from(cache_dir), runtime)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(message) => {
            unsafe {
                *error = CString::new(message.replace('\0', " "))
                    .expect("NUL removed")
                    .into_raw();
            }
            ptr::null_mut()
        }
    }
}

/// Enqueue one complete IP packet: 0 queued, 1 congestion drop, -1 stopped,
/// -2 invalid input. The input bytes are copied before this function returns.
///
/// # Safety
/// `handle` must remain live; `bytes` must name `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_write(
    handle: *const PacketTunnelRuntime,
    bytes: *const u8,
    len: usize,
) -> c_int {
    if handle.is_null() || bytes.is_null() || len == 0 || len > usize::from(PACKET_MTU) {
        return -2;
    }
    match unsafe { &*handle }.write_packet(unsafe { std::slice::from_raw_parts(bytes, len) }) {
        Ok(PacketWrite::Queued) => 0,
        Ok(PacketWrite::Congested) => 1,
        Ok(PacketWrite::Closed) => -1,
        Err(_) => -2,
    }
}

/// Read one IP packet: positive length, 0 after a 250 ms timeout, -1 stopped,
/// -2 invalid output buffer. Only one native reader may call this at a time.
///
/// # Safety
/// `handle` must remain live and `bytes` must name `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_read(
    handle: *const PacketTunnelRuntime,
    bytes: *mut u8,
    capacity: usize,
) -> c_int {
    if handle.is_null() || bytes.is_null() || capacity < usize::from(PACKET_MTU) {
        return -2;
    }
    match unsafe { &*handle }.read_packet(Duration::from_millis(250)) {
        Ok(Some(packet)) => {
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), bytes, packet.len());
            }
            packet.len() as c_int
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

/// Cancel workers and wake the native packet reader. Does not free the handle.
///
/// # Safety
/// `handle` must be null or point to a live tunnel.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_cancel(handle: *const PacketTunnelRuntime) {
    if let Some(handle) = unsafe { handle.as_ref() } {
        handle.cancel();
    }
}

/// Return an owned error string, or null. Free with `proxy_free_string`.
///
/// # Safety
/// `handle` must be null or point to a live tunnel.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_last_error(
    handle: *const PacketTunnelRuntime,
) -> *mut c_char {
    unsafe { handle.as_ref() }
        .and_then(PacketTunnelRuntime::last_error)
        .and_then(|error| CString::new(error.replace('\0', " ")).ok())
        .map_or(ptr::null_mut(), CString::into_raw)
}

/// Cancel and join workers, then free the opaque handle.
///
/// # Safety
/// No other caller may access `handle` during or after this call. It must be
/// null or a pointer returned by `proxy_packet_tunnel_create`, freed once only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_packet_tunnel_destroy(handle: *mut PacketTunnelRuntime) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}
