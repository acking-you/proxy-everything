//! ProxyHandle and lifecycle management.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use proxy_client::cli_config::SystemProxyGuard;
use proxy_client::client::tun::{
    TunBypassController, TunConfig, current_process_name, running_process_names,
};
use proxy_client::client::{
    ClientConfig, ClientRuntimeConfig, run_client_with_listener_runtime_config,
};
use proxy_core::util::error_report;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::logging::send_log;
use crate::types::{ProxyConfig, ProxyConfigV2, ProxyConfigV3, ProxyResult};

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    pub(crate) runtime: Runtime,
    pub(crate) cancel_token: Option<CancellationToken>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) local_port: u16,
    pub(crate) http_client: Mutex<Option<reqwest::Client>>,
    tun_bypass: Arc<Mutex<Option<TunBypassController>>>,
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    system_proxy_guard: Arc<Mutex<Option<SystemProxyGuard>>>,
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
        tun_bypass: Arc::new(Mutex::new(None)),
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        system_proxy_guard: Arc::new(Mutex::new(None)),
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
    proxy_start_inner(handle, config, true, false, Vec::new())
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
    proxy_start_inner(
        handle,
        &legacy_config,
        config.enable_udp != 0,
        false,
        Vec::new(),
    )
}

/// Start the proxy with the version 3 configuration.
///
/// This additive entry point enables local TUN capture while preserving the
/// V1 and V2 ABI. The current executable is forcibly added to the process
/// bypass policy to prevent the proxy's outbound traffic from looping back
/// through its own TUN interface.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `config` fields must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_v3(
    handle: *mut ProxyHandle,
    config: *const ProxyConfigV3,
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
    let bypass_processes = match parse_process_names(config.tun_bypass_processes) {
        Ok(names) => names,
        Err(result) => return result,
    };
    proxy_start_inner(
        handle,
        &legacy_config,
        config.enable_udp != 0,
        config.enable_tun != 0,
        bypass_processes,
    )
}

fn parse_process_names(value: *const c_char) -> Result<Vec<String>, ProxyResult> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let value = unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| ProxyResult::InvalidParam)?;
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.starts_with('[') {
        return serde_json::from_str::<Vec<String>>(value).map_err(|_| ProxyResult::InvalidParam);
    }
    // Accept comma-separated input as a convenience for native callers that
    // adopted the V3 preview before the JSON contract was finalized.
    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect())
}

fn proxy_start_inner(
    handle: *mut ProxyHandle,
    config: &ProxyConfig,
    enable_udp: bool,
    enable_tun: bool,
    tun_bypass_processes: Vec<String>,
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

    let tun_config = if enable_tun {
        match TunConfig::new(tun_bypass_processes) {
            Ok(config) => Some(config),
            Err(error) => {
                send_log(
                    4,
                    &format!("Failed to initialize TUN process bypass: {error}"),
                );
                return ProxyResult::RuntimeError;
            }
        }
    } else {
        None
    };

    // Build ClientRuntimeConfig for listener and optional TUN options.
    let client_config = ClientRuntimeConfig {
        client: ClientConfig {
            enable_auto_proxy,
            enable_udp,
            cache_dir,
        },
        upstream_proxy: None,
        tun: tun_config.clone(),
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
        let Ok(mut guard) = handle.system_proxy_guard.lock() else {
            send_log(4, "Failed to lock the system proxy cleanup guard");
            return ProxyResult::RuntimeError;
        };
        *guard = if set_system_proxy {
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
    let tun_bypass_cleanup = Arc::clone(&handle.tun_bypass);
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    let system_proxy_cleanup = Arc::clone(&handle.system_proxy_guard);
    if let Ok(mut http_client) = handle.http_client.lock() {
        *http_client = None;
    }
    if let Ok(mut tun_bypass) = handle.tun_bypass.lock() {
        *tun_bypass = tun_config.map(|config| config.bypass);
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
            enable_tun,
            force_codec,
            "proxy started"
        );

        // Use force_codec to determine NEED_CODEC constant
        if force_codec {
            run_client_with_listener_runtime_config::<true>(
                listener,
                cancel_token,
                None,
                Some(client_config),
            )
            .await;
        } else {
            run_client_with_listener_runtime_config::<false>(
                listener,
                cancel_token,
                None,
                Some(client_config),
            )
            .await;
        }

        if let Ok(mut tun_bypass) = tun_bypass_cleanup.lock() {
            *tun_bypass = None;
        }
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        if let Ok(mut guard) = system_proxy_cleanup.lock() {
            *guard = None;
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
        if let Ok(mut tun_bypass) = handle.tun_bypass.lock() {
            *tun_bypass = None;
        }

        // Clear system proxy guard to restore system proxy settings
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            if let Ok(mut guard) = handle.system_proxy_guard.lock() {
                *guard = None;
            }
        }

        ProxyResult::Ok
    } else {
        ProxyResult::NotRunning
    }
}

/// Replace the user-selected process bypass list of an active TUN session.
///
/// The current executable remains mandatory even when `processes` is null or
/// empty. The replacement affects newly observed sessions; established relays
/// retain their original routing decision.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `processes` must be null or a valid UTF-8 JSON string array
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_set_tun_bypass_processes(
    handle: *mut ProxyHandle,
    processes: *const c_char,
) -> ProxyResult {
    if handle.is_null() {
        return ProxyResult::InvalidParam;
    }
    let processes = match parse_process_names(processes) {
        Ok(names) => names,
        Err(result) => return result,
    };
    let handle = unsafe { &*handle };
    if !handle.running.load(Ordering::SeqCst) {
        return ProxyResult::NotRunning;
    }
    let tun_bypass = match handle.tun_bypass.lock() {
        Ok(tun_bypass) => tun_bypass,
        Err(_) => return ProxyResult::RuntimeError,
    };
    let Some(controller) = tun_bypass.as_ref() else {
        return ProxyResult::NotRunning;
    };
    controller.set_user_processes(processes);
    ProxyResult::Ok
}

/// Return running Windows process names as a JSON string.
///
/// The caller must release the returned pointer with `proxy_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_list_tun_processes() -> *mut c_char {
    crate::init_allocator();
    let json = match serde_json::to_string(&running_process_names()) {
        Ok(json) => json,
        Err(error) => {
            send_log(
                4,
                &format!("Failed to serialize running process list: {error}"),
            );
            return ptr::null_mut();
        }
    };
    CString::new(json).map_or(ptr::null_mut(), CString::into_raw)
}

/// Return the normalized executable name that is always excluded from TUN.
///
/// The caller must release the returned pointer with `proxy_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_get_tun_self_process() -> *mut c_char {
    crate::init_allocator();
    current_process_name()
        .ok()
        .and_then(|name| CString::new(name).ok())
        .map_or(ptr::null_mut(), CString::into_raw)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_name_parser_accepts_json_and_legacy_comma_separated_values() {
        assert!(parse_process_names(ptr::null()).unwrap().is_empty());

        let value = CString::new(" browser.exe, , downloader ").unwrap();
        assert_eq!(
            parse_process_names(value.as_ptr()).unwrap(),
            vec!["browser.exe".to_string(), "downloader".to_string()]
        );

        let json = CString::new(r#"["name,with,commas.exe","browser"]"#).unwrap();
        assert_eq!(
            parse_process_names(json.as_ptr()).unwrap(),
            vec!["name,with,commas.exe".to_string(), "browser".to_string()]
        );
    }
}
