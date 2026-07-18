//! ProxyHandle and lifecycle management.

use std::ffi::{CStr, c_int};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use proxy_client::cli_config::SystemProxyGuard;
use proxy_client::client::{ClientConfig, run_client_with_listener};
use proxy_core::util::error_report;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::logging::send_log;
use crate::types::{ProxyConfig, ProxyConfigV2, ProxyResult};

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    pub(crate) runtime: Runtime,
    pub(crate) cancel_token: Option<CancellationToken>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) local_port: u16,
    pub(crate) http_client: Mutex<Option<reqwest::Client>>,
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    _system_proxy_guard: Option<SystemProxyGuard>,
}

/// Create a new proxy handle.
///
/// # Safety
/// Returns a pointer to ProxyHandle that must be freed with `proxy_destroy`.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_create() -> *mut ProxyHandle {
    crate::init_allocator();
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            send_log(4, &format!("Failed to create runtime: {}", e));
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(ProxyHandle {
        runtime,
        cancel_token: None,
        running: Arc::new(AtomicBool::new(false)),
        local_port: 0,
        http_client: Mutex::new(None),
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        _system_proxy_guard: None,
    }))
}

/// Start the proxy with the given configuration.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `config` fields must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start(
    handle: *mut ProxyHandle,
    config: *const ProxyConfig,
) -> ProxyResult {
    if handle.is_null() || config.is_null() {
        return ProxyResult::InvalidParam;
    }

    let config = unsafe { &*config };
    proxy_start_inner(handle, config, true)
}

/// Start the proxy with the version 2 configuration.
///
/// The versioned entry point adds explicit SOCKS5 UDP control without changing
/// the layout consumed by legacy `proxy_start` callers.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `config` fields must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_v2(
    handle: *mut ProxyHandle,
    config: *const ProxyConfigV2,
) -> ProxyResult {
    if handle.is_null() || config.is_null() {
        return ProxyResult::InvalidParam;
    }

    let config = unsafe { &*config };
    let legacy_config = ProxyConfig {
        server_host: config.server_host,
        server_port: config.server_port,
        local_port: config.local_port,
        session_key: config.session_key,
        auto_proxy: config.auto_proxy,
        reverse_geo: config.reverse_geo,
        cache_dir: config.cache_dir,
        need_codec_ips: config.need_codec_ips,
        force_codec: config.force_codec,
        set_system_proxy: config.set_system_proxy,
    };
    proxy_start_inner(handle, &legacy_config, config.enable_udp != 0)
}

fn proxy_start_inner(
    handle: *mut ProxyHandle,
    config: &ProxyConfig,
    enable_udp: bool,
) -> ProxyResult {
    if config.server_host.is_null() {
        return ProxyResult::InvalidParam;
    }

    let handle = unsafe { &mut *handle };

    if handle.running.load(Ordering::SeqCst) {
        return ProxyResult::AlreadyRunning;
    }

    // Parse config
    let server_host = match unsafe { CStr::from_ptr(config.server_host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ProxyResult::InvalidParam,
    };

    // session_key is optional, use default if null
    let session_key = if config.session_key.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(config.session_key) }.to_str() {
            Ok(s) if s.len() == 32 => Some(s.to_string()),
            Ok(s) => {
                send_log(4, &format!("Session key must be 32 bytes, got {}", s.len()));
                return ProxyResult::InvalidParam;
            }
            Err(_) => return ProxyResult::InvalidParam,
        }
    };

    // cache_dir is optional
    let cache_dir = if config.cache_dir.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(config.cache_dir) }.to_str() {
            Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
            _ => None,
        }
    };

    // need_codec_ips: null or empty = empty list (no codec IPs), otherwise comma-separated
    let need_codec_ips = if config.need_codec_ips.is_null() {
        Some(vec![]) // default: empty list
    } else {
        match unsafe { CStr::from_ptr(config.need_codec_ips) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s.split(',').map(|ip| ip.trim().to_string()).collect()),
            _ => Some(vec![]), // empty string = empty list
        }
    };

    let server_port = config.server_port;
    let local_port = config.local_port;
    let reverse_geo = config.reverse_geo != 0;
    let enable_auto_proxy = config.auto_proxy != 0;
    let force_codec = config.force_codec != 0;
    let set_system_proxy = config.set_system_proxy != 0;

    // Initialize runtime config directly (no env vars needed)
    proxy_core::config::runtime::init_config(
        server_host.clone(),
        server_port,
        reverse_geo,
        need_codec_ips.clone().unwrap_or_default(),
        session_key.clone(),
    );

    // Build ClientConfig for runtime options
    let client_config = ClientConfig {
        enable_auto_proxy,
        enable_udp,
        cache_dir,
    };

    // Bind listener synchronously before reporting start success.
    // This prevents false-positive "running" state when the port is already in use.
    let listener = match handle
        .runtime
        .block_on(async { TcpListener::bind(("127.0.0.1", local_port)).await })
    {
        Ok(listener) => listener,
        Err(e) => {
            send_log(
                4,
                &format!(
                    "Failed to bind listener on 127.0.0.1:{}: {}",
                    local_port,
                    error_report(&e)
                ),
            );
            return ProxyResult::ConnectionFailed;
        }
    };

    // Set system proxy only after local listener is confirmed available.
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        handle._system_proxy_guard = if set_system_proxy {
            SystemProxyGuard::new(local_port)
        } else {
            None
        };
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let _ = set_system_proxy;

    let cancel_token = CancellationToken::new();
    handle.cancel_token = Some(cancel_token.clone());
    handle.running.store(true, Ordering::SeqCst);
    handle.local_port = local_port;
    let running_flag = Arc::clone(&handle.running);
    if let Ok(mut http_client) = handle.http_client.lock() {
        *http_client = None;
    }

    // Spawn proxy task using existing client logic
    handle.runtime.spawn(async move {
        tracing::info!(
            local_port,
            remote_host = %server_host,
            remote_port = server_port,
            reverse_geo,
            enable_auto_proxy,
            enable_udp,
            force_codec,
            "proxy started"
        );

        // Use force_codec to determine NEED_CODEC constant
        if force_codec {
            run_client_with_listener::<true>(listener, cancel_token, None, Some(client_config))
                .await;
        } else {
            run_client_with_listener::<false>(listener, cancel_token, None, Some(client_config))
                .await;
        }

        running_flag.store(false, Ordering::SeqCst);
        tracing::info!("Proxy stopped");
    });

    ProxyResult::Ok
}

/// Stop the proxy.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_stop(handle: *mut ProxyHandle) -> ProxyResult {
    if handle.is_null() {
        return ProxyResult::InvalidParam;
    }

    let handle = unsafe { &mut *handle };

    if !handle.running.load(Ordering::SeqCst) {
        return ProxyResult::NotRunning;
    }

    if let Some(token) = handle.cancel_token.take() {
        token.cancel();
        handle.running.store(false, Ordering::SeqCst);
        if let Ok(mut http_client) = handle.http_client.lock() {
            *http_client = None;
        }

        // Clear system proxy guard to restore system proxy settings
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            handle._system_proxy_guard = None;
        }

        ProxyResult::Ok
    } else {
        ProxyResult::NotRunning
    }
}

/// Destroy the proxy handle and free resources.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create` and must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_destroy(handle: *mut ProxyHandle) {
    if !handle.is_null() {
        let handle = unsafe { Box::from_raw(handle) };
        if let Some(token) = &handle.cancel_token {
            token.cancel();
        }
        drop(handle);
    }
}

/// Check if proxy is running.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_is_running(handle: *const ProxyHandle) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let handle = unsafe { &*handle };
    if handle.running.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}
