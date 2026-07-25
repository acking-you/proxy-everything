//! ProxyHandle and lifecycle management.

use std::ffi::{CStr, CString, c_char, c_int};
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, ptr};

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use proxy_client::cli_config::SystemProxyGuard;
#[cfg(target_os = "android")]
use proxy_client::client::tun::run_with_ready_on_fd;
use proxy_client::client::tun::{
    TunBypassController, TunConfig, TunVirtualDnsState, current_process_name, run_with_ready,
    running_process_names, running_processes,
};
use proxy_client::client::{
    ClientConfig, ClientRuntimeConfig, run_client_with_listener_runtime_config,
};
use proxy_core::util::error_report;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::logging::send_log;
use crate::types::{
    ProxyConfig, ProxyConfigV2, ProxyConfigV3, ProxyConfigV4, ProxyConfigV5, ProxyResult,
};

const LOOPBACK_LISTEN_HOST: &str = "127.0.0.1";
const LAN_LISTEN_HOST: &str = "0.0.0.0";

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    pub(crate) runtime: Runtime,
    pub(crate) cancel_token: Option<CancellationToken>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) local_port: u16,
    pub(crate) http_client: Mutex<Option<reqwest::Client>>,
    tun_bypass: Arc<Mutex<Option<TunBypassController>>>,
    tun_lifecycle: Mutex<TunLifecycle>,
    tun_running: Arc<AtomicBool>,
    tun_generation: Arc<AtomicU64>,
    tun_virtual_dns: TunVirtualDnsState,
    force_proxy: Arc<AtomicBool>,
    remote_endpoint: Mutex<Option<(String, u16)>>,
    last_error: Arc<Mutex<Option<String>>>,
    udp_enabled: AtomicBool,
    tun_udp_direct_fallback: AtomicBool,
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    system_proxy_guard: Arc<Mutex<Option<SystemProxyGuard>>>,
}

#[derive(Clone, Copy, Debug)]
struct TunOutboundPolicy {
    force_proxy: bool,
}

#[derive(Default)]
struct TunLifecycle {
    cancel_token: Option<CancellationToken>,
    stopped: Option<tokio::sync::oneshot::Receiver<()>>,
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
        tun_lifecycle: Mutex::new(TunLifecycle::default()),
        tun_running: Arc::new(AtomicBool::new(false)),
        tun_generation: Arc::new(AtomicU64::new(0)),
        tun_virtual_dns: TunVirtualDnsState::default(),
        force_proxy: Arc::new(AtomicBool::new(false)),
        remote_endpoint: Mutex::new(None),
        last_error: Arc::new(Mutex::new(None)),
        udp_enabled: AtomicBool::new(true),
        tun_udp_direct_fallback: AtomicBool::new(true),
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
    proxy_start_inner(handle, config, true, false, true, false, Vec::new())
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
        true,
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
        true,
        false,
        bypass_processes,
    )
}

/// Start the proxy with the version 4 configuration.
///
/// V4 adds a TUN-only policy for non-DNS UDP when SOCKS5 UDP is disabled.
/// Older entry points keep direct fallback enabled for compatibility.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `config` fields must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_v4(
    handle: *mut ProxyHandle,
    config: *const ProxyConfigV4,
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
        config.tun_udp_direct_fallback != 0,
        false,
        bypass_processes,
    )
}

/// Start the proxy with the version 5 configuration.
///
/// V5 allows the local HTTP/SOCKS5 listener to be exposed on all IPv4
/// interfaces. Older entry points remain loopback-only.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `config` fields must be valid C strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_v5(
    handle: *mut ProxyHandle,
    config: *const ProxyConfigV5,
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
        config.tun_udp_direct_fallback != 0,
        config.allow_lan != 0,
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
    tun_udp_direct_fallback: bool,
    allow_lan: bool,
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

    if let Some(cache_dir) = &cache_dir {
        match handle
            .runtime
            .block_on(handle.tun_virtual_dns.enable_persistence_in(cache_dir))
        {
            Ok(entries) => tracing::info!(
                entries,
                cache_dir = %cache_dir.display(),
                "loaded persistent TUN virtual DNS mappings"
            ),
            Err(error) => tracing::warn!(
                cache_dir = %cache_dir.display(),
                %error,
                "TUN virtual DNS mappings will not survive a process restart"
            ),
        }
    }

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
    let listen_host = local_listen_host(allow_lan);

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
            Ok(config) => Some(
                config
                    .with_udp_enabled(enable_udp)
                    .with_udp_direct_fallback(tun_udp_direct_fallback)
                    .with_virtual_dns_state(handle.tun_virtual_dns.clone())
                    .with_remote_endpoint(server_host.clone(), server_port),
            ),
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
        force_proxy: Some(Arc::clone(&handle.force_proxy)),
    };

    // Bind listener synchronously before reporting start success.
    // This prevents false-positive "running" state when the port is already in use.
    let listener = match handle
        .runtime
        .block_on(async { TcpListener::bind((listen_host, local_port)).await })
    {
        Ok(listener) => listener,
        Err(e) => {
            send_log(
                4,
                &format!(
                    "Failed to bind listener on {}:{}: {}",
                    listen_host,
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
    if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
        if let Some(token) = lifecycle.cancel_token.take() {
            token.cancel();
        }
        lifecycle.stopped = None;
    }
    handle.cancel_token = Some(cancel_token.clone());
    handle.running.store(true, Ordering::SeqCst);
    handle.local_port = local_port;
    handle.udp_enabled.store(enable_udp, Ordering::Release);
    handle
        .tun_udp_direct_fallback
        .store(tun_udp_direct_fallback, Ordering::Release);
    if let Ok(mut endpoint) = handle.remote_endpoint.lock() {
        *endpoint = Some((server_host.clone(), server_port));
    }
    handle.force_proxy.store(enable_tun, Ordering::Release);
    handle.tun_running.store(enable_tun, Ordering::Release);
    let running_flag = Arc::clone(&handle.running);
    let tun_bypass_cleanup = Arc::clone(&handle.tun_bypass);
    let tun_running_cleanup = Arc::clone(&handle.tun_running);
    let force_proxy_cleanup = Arc::clone(&handle.force_proxy);
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
            tun_udp_direct_fallback,
            allow_lan,
            listen_host,
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
        tun_running_cleanup.store(false, Ordering::Release);
        force_proxy_cleanup.store(false, Ordering::Release);
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        if let Ok(mut guard) = system_proxy_cleanup.lock() {
            *guard = None;
        }
        running_flag.store(false, Ordering::SeqCst);
        tracing::info!("Proxy stopped");
    });

    ProxyResult::Ok
}

fn local_listen_host(allow_lan: bool) -> &'static str {
    if allow_lan {
        LAN_LISTEN_HOST
    } else {
        LOOPBACK_LISTEN_HOST
    }
}

/// Atomically replace the remote proxy endpoint without rebinding the local
/// HTTP/SOCKS5 listener.
///
/// TUN must be stopped first because its operating-system route bypass was
/// resolved from the previous endpoint. Callers can immediately start TUN
/// again after this function returns; existing TUN relays are already drained
/// by `proxy_stop_tun`, while the local listener remains available throughout.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `server_host` must be a valid, non-empty UTF-8 C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_switch_upstream(
    handle: *mut ProxyHandle,
    server_host: *const c_char,
    server_port: u16,
) -> ProxyResult {
    if handle.is_null() || server_host.is_null() || server_port == 0 {
        return ProxyResult::InvalidParam;
    }
    let handle = unsafe { &*handle };
    clear_last_error(handle);
    if !handle.running.load(Ordering::Acquire) {
        record_error(
            handle,
            "Start the local proxy listener before switching its upstream endpoint",
        );
        return ProxyResult::NotRunning;
    }
    if handle.tun_running.load(Ordering::Acquire) {
        record_error(
            handle,
            "Stop TUN capture before switching upstream so its route bypass can be refreshed",
        );
        return ProxyResult::RuntimeError;
    }

    let server_host = match unsafe { CStr::from_ptr(server_host) }.to_str() {
        Ok(host) if !host.trim().is_empty() => host.trim().to_string(),
        _ => return ProxyResult::InvalidParam,
    };
    let mut endpoint = match handle.remote_endpoint.lock() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            record_error(handle, "Failed to lock the active upstream endpoint");
            return ProxyResult::RuntimeError;
        }
    };
    let previous = endpoint.clone();

    // Client connection paths load this host/port pair from one ArcSwap
    // snapshot, so accepts racing this call see either complete generation.
    proxy_core::config::runtime::set_server_endpoint(server_host.clone(), server_port);
    *endpoint = Some((server_host.clone(), server_port));
    if let Ok(mut http_client) = handle.http_client.lock() {
        *http_client = None;
    }

    tracing::info!(
        previous_host = previous.as_ref().map(|(host, _)| host.as_str()),
        previous_port = previous.as_ref().map(|(_, port)| *port),
        remote_host = %server_host,
        remote_port = server_port,
        "proxy upstream switched without rebinding the local listener"
    );
    ProxyResult::Ok
}

/// Start TUN capture after the local HTTP/SOCKS5 listener is confirmed active.
///
/// Captured packets are always forwarded to `socks5://127.0.0.1:<local_port>`.
/// The remote proxy endpoint is installed as an explicit route bypass, the
/// current executable remains in the process bypass list, and auto-proxy direct
/// connections are suppressed while desktop TUN is active. Together these
/// invariants prevent client-owned outbound connections from returning to the
/// local listener.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `processes` must be null or a valid UTF-8 JSON string array
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_tun(
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
    clear_last_error(handle);
    if !handle.running.load(Ordering::Acquire) || handle.local_port == 0 {
        record_error(
            handle,
            "Start the local proxy listener before enabling TUN mode",
        );
        return ProxyResult::NotRunning;
    }
    if handle.tun_running.load(Ordering::Acquire) {
        return ProxyResult::AlreadyRunning;
    }

    #[cfg(target_os = "windows")]
    match proxy_client::client::tun::is_elevated() {
        Ok(true) => {}
        Ok(false) => {
            record_error(
                handle,
                "TUN mode requires administrator privileges; request UAC elevation first",
            );
            return ProxyResult::RuntimeError;
        }
        Err(error) => {
            record_error(
                handle,
                &format!("Failed to inspect Windows elevation state: {error}"),
            );
            return ProxyResult::RuntimeError;
        }
    }

    let endpoint = match handle.remote_endpoint.lock() {
        Ok(endpoint) => endpoint.clone(),
        Err(_) => return ProxyResult::RuntimeError,
    };
    let Some((remote_host, remote_port)) = endpoint else {
        record_error(
            handle,
            "Remote proxy endpoint is unavailable for mandatory TUN route bypass",
        );
        return ProxyResult::RuntimeError;
    };
    let config = match TunConfig::new(processes) {
        Ok(config) => config
            .with_udp_enabled(handle.udp_enabled.load(Ordering::Acquire))
            .with_udp_direct_fallback(handle.tun_udp_direct_fallback.load(Ordering::Acquire))
            .with_virtual_dns_state(handle.tun_virtual_dns.clone())
            .with_remote_endpoint(remote_host.clone(), remote_port),
        Err(error) => {
            record_error(
                handle,
                &format!("Failed to initialize TUN process bypass: {error}"),
            );
            return ProxyResult::RuntimeError;
        }
    };

    start_tun_runtime(
        handle,
        config,
        // Desktop TUN cannot exclude this process at the OS package boundary,
        // so direct sockets would be captured and loop into the listener.
        TunOutboundPolicy { force_proxy: true },
        run_with_ready,
        format!(
            "TUN ready: device traffic -> socks5://127.0.0.1:{}; remote endpoint \
             {remote_host}:{remote_port} bypasses TUN",
            handle.local_port
        ),
    )
}

/// Start forwarding an Android `VpnService` interface.
///
/// The Java service retains its `ParcelFileDescriptor`; native code duplicates
/// it synchronously and owns only the duplicate. Android's per-application VPN
/// policy must exclude this package (or omit it from an allow-list) so the
/// local proxy's upstream sockets cannot loop back into the TUN. Because that
/// exclusion is enforced by Android before routing, the local listener keeps
/// its configured auto-proxy/direct decisions while VPN capture is active.
///
/// # Safety
/// - `handle` must be a valid pointer returned by `proxy_create`
/// - `tun_fd` must name a live TUN descriptor in the current process
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_android_tun(
    handle: *mut ProxyHandle,
    tun_fd: c_int,
    mtu: u16,
) -> ProxyResult {
    use std::os::fd::{FromRawFd, OwnedFd};

    if handle.is_null() || tun_fd < 0 || !(1280..=9000).contains(&mtu) {
        return ProxyResult::InvalidParam;
    }
    let handle = unsafe { &*handle };
    clear_last_error(handle);
    if !handle.running.load(Ordering::Acquire) || handle.local_port == 0 {
        record_error(
            handle,
            "Start the local proxy listener before enabling Android VPN capture",
        );
        return ProxyResult::NotRunning;
    }
    if handle.tun_running.load(Ordering::Acquire) {
        return ProxyResult::AlreadyRunning;
    }

    let duplicated = unsafe { libc::dup(tun_fd) };
    if duplicated < 0 {
        let error = io::Error::last_os_error();
        record_error(
            handle,
            &format!("Failed to duplicate Android VPN TUN descriptor: {error}"),
        );
        return ProxyResult::RuntimeError;
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(duplicated) };

    let config = match TunConfig::new(Vec::<String>::new()) {
        Ok(config) => config
            .with_udp_enabled(handle.udp_enabled.load(Ordering::Acquire))
            .with_udp_direct_fallback(handle.tun_udp_direct_fallback.load(Ordering::Acquire))
            .with_ipv6_enabled(true)
            .with_mtu(mtu)
            .with_virtual_dns_state(handle.tun_virtual_dns.clone()),
        Err(error) => {
            record_error(
                handle,
                &format!("Failed to initialize Android TUN forwarding: {error}"),
            );
            return ProxyResult::RuntimeError;
        }
    };

    let local_port = handle.local_port;
    start_tun_runtime(
        handle,
        config,
        // VpnService excludes this package before routing. Preserve the same
        // auto-proxy decisions used when an external TUN forwards here.
        TunOutboundPolicy { force_proxy: false },
        move |port, config, shutdown_token, ready| {
            run_with_ready_on_fd(port, config, owned_fd, shutdown_token, ready)
        },
        format!("Android VPN ready: IPv4/IPv6 device traffic -> socks5://127.0.0.1:{local_port}"),
    )
}

fn start_tun_runtime<Runner, RunnerFuture>(
    handle: &ProxyHandle,
    config: TunConfig,
    outbound_policy: TunOutboundPolicy,
    runner: Runner,
    ready_message: String,
) -> ProxyResult
where
    Runner: FnOnce(
            u16,
            TunConfig,
            CancellationToken,
            Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
        ) -> RunnerFuture
        + Send
        + 'static,
    RunnerFuture: Future<Output = io::Result<usize>> + Send + 'static,
{
    let (previous, stopped) = match handle.tun_lifecycle.lock() {
        Ok(mut lifecycle) => (lifecycle.cancel_token.take(), lifecycle.stopped.take()),
        Err(_) => return ProxyResult::RuntimeError,
    };
    if let Some(previous) = previous {
        previous.cancel();
    }
    if let Some(stopped) = stopped {
        let _ = handle.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), stopped).await
        });
    }
    let Some(proxy_token) = handle.cancel_token.as_ref() else {
        handle.force_proxy.store(false, Ordering::Release);
        return ProxyResult::NotRunning;
    };
    // TUN may be stopped independently, but it must never outlive the local
    // listener it forwards into. Cancelling the proxy parent token therefore
    // always cancels this child as well.
    let shutdown_token = proxy_token.child_token();
    if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
        lifecycle.cancel_token = Some(shutdown_token.clone());
    } else {
        return ProxyResult::RuntimeError;
    }
    handle
        .force_proxy
        .store(outbound_policy.force_proxy, Ordering::Release);
    tracing::info!(?outbound_policy, "applying TUN outbound routing policy");
    if let Ok(mut bypass) = handle.tun_bypass.lock() {
        *bypass = Some(config.bypass.clone());
    } else {
        handle.force_proxy.store(false, Ordering::Release);
        if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
            lifecycle.cancel_token = None;
        }
        return ProxyResult::RuntimeError;
    }

    let local_port = handle.local_port;
    let generation = handle.tun_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let generation_state = Arc::clone(&handle.tun_generation);
    let running = Arc::clone(&handle.tun_running);
    let force_proxy = Arc::clone(&handle.force_proxy);
    let bypass_cleanup = Arc::clone(&handle.tun_bypass);
    let last_error = Arc::clone(&handle.last_error);
    let (setup_sender, setup_receiver) = tokio::sync::oneshot::channel();
    let (caller_sender, caller_receiver) = tokio::sync::oneshot::channel();
    let (stopped_sender, stopped_receiver) = tokio::sync::oneshot::channel();
    if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
        lifecycle.stopped = Some(stopped_receiver);
    } else {
        shutdown_token.cancel();
        handle.force_proxy.store(false, Ordering::Release);
        if let Ok(mut bypass) = handle.tun_bypass.lock() {
            *bypass = None;
        }
        return ProxyResult::RuntimeError;
    }
    handle.runtime.spawn(async move {
        let ready_running = Arc::clone(&running);
        let ready_generation = Arc::clone(&generation_state);
        let readiness_task = tokio::spawn(async move {
            let readiness = setup_receiver.await.unwrap_or_else(|_| {
                Err("TUN setup task ended without reporting readiness".to_string())
            });
            let setup_succeeded = readiness.is_ok();
            if setup_succeeded && ready_generation.load(Ordering::Acquire) == generation {
                ready_running.store(true, Ordering::Release);
            }
            let _ = caller_sender.send(readiness);
            setup_succeeded
        });

        let result = runner(local_port, config, shutdown_token, Some(setup_sender)).await;
        let setup_succeeded = readiness_task.await.unwrap_or(false);
        // A stop followed immediately by a new start can leave the old async
        // task finishing after the replacement has begun. Only the current
        // generation may clear shared state for loop prevention.
        if generation_state.load(Ordering::Acquire) == generation {
            running.store(false, Ordering::Release);
            force_proxy.store(false, Ordering::Release);
            if let Ok(mut bypass) = bypass_cleanup.lock() {
                *bypass = None;
            }
        }
        match result {
            Ok(sessions) => {
                tracing::info!(remaining_sessions = sessions, "TUN traffic capture stopped")
            }
            Err(error) if setup_succeeded => {
                let message = format!("TUN traffic capture failed after startup: {error}");
                match last_error.lock() {
                    Ok(mut current) => *current = Some(message.clone()),
                    Err(poisoned) => *poisoned.into_inner() = Some(message.clone()),
                }
                tracing::error!(%error, "TUN traffic capture failed")
            }
            Err(error) => tracing::error!(%error, "TUN traffic capture setup failed"),
        }
        let _ = stopped_sender.send(());
    });

    let readiness = handle.runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(20), caller_receiver).await
    });
    match readiness {
        Ok(Ok(Ok(()))) => {
            send_log(2, &ready_message);
            ProxyResult::Ok
        }
        Ok(Ok(Err(error))) => fail_tun_start(handle, &error),
        Ok(Err(_)) => fail_tun_start(handle, "TUN readiness channel closed unexpectedly"),
        Err(_) => fail_tun_start(handle, "Timed out waiting for TUN adapter and route setup"),
    }
}

fn fail_tun_start(handle: &ProxyHandle, error: &str) -> ProxyResult {
    handle.tun_generation.fetch_add(1, Ordering::AcqRel);
    if let Ok(mut lifecycle) = handle.tun_lifecycle.lock()
        && let Some(token) = lifecycle.cancel_token.take()
    {
        token.cancel();
    }
    handle.tun_running.store(false, Ordering::Release);
    handle.force_proxy.store(false, Ordering::Release);
    if let Ok(mut bypass) = handle.tun_bypass.lock() {
        *bypass = None;
    }
    record_error(handle, &format!("Failed to start TUN mode: {error}"));
    ProxyResult::RuntimeError
}

fn clear_last_error(handle: &ProxyHandle) {
    match handle.last_error.lock() {
        Ok(mut error) => *error = None,
        Err(poisoned) => *poisoned.into_inner() = None,
    }
}

fn record_error(handle: &ProxyHandle, message: &str) {
    match handle.last_error.lock() {
        Ok(mut error) => *error = Some(message.to_string()),
        Err(poisoned) => *poisoned.into_inner() = Some(message.to_string()),
    }
    send_log(4, message);
}

/// Stop only TUN capture while keeping the local HTTP/SOCKS5 listener active.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_stop_tun(handle: *mut ProxyHandle) -> ProxyResult {
    if handle.is_null() {
        return ProxyResult::InvalidParam;
    }
    let handle = unsafe { &*handle };
    let (token, stopped) = match handle.tun_lifecycle.lock() {
        Ok(mut lifecycle) => (lifecycle.cancel_token.take(), lifecycle.stopped.take()),
        Err(_) => return ProxyResult::RuntimeError,
    };
    let Some(token) = token else {
        return ProxyResult::NotRunning;
    };
    handle.tun_generation.fetch_add(1, Ordering::AcqRel);
    token.cancel();
    handle.tun_running.store(false, Ordering::Release);
    handle.force_proxy.store(false, Ordering::Release);
    if let Ok(mut bypass) = handle.tun_bypass.lock() {
        *bypass = None;
    }
    if let Some(stopped) = stopped
        && handle
            .runtime
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(5), stopped).await
            })
            .is_err()
    {
        send_log(3, "Timed out waiting for TUN route cleanup to finish");
        return ProxyResult::RuntimeError;
    }
    send_log(2, "TUN stop requested; local proxy listener remains active");
    ProxyResult::Ok
}

/// Check whether TUN adapter and route setup has completed successfully.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_is_tun_running(handle: *const ProxyHandle) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let handle = unsafe { &*handle };
    i32::from(handle.tun_running.load(Ordering::Acquire))
}

/// Return whether the current process can change Windows TUN routes without a
/// UAC relaunch. Non-Windows platforms return true because their elevation
/// mechanism is not managed by the Flutter Windows client.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_is_elevated() -> c_int {
    #[cfg(target_os = "windows")]
    {
        proxy_client::client::tun::is_elevated().map_or(-1, i32::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        1
    }
}

/// Relaunch the current Windows GUI with `--enable-tun` through ShellExecute's
/// `runas` verb. The new process is a GUI process, so no terminal window is
/// created. The caller remains alive when UAC is cancelled.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_relaunch_elevated_for_tun() -> ProxyResult {
    #[cfg(target_os = "windows")]
    {
        match proxy_client::client::tun::relaunch_elevated_for_tun() {
            Ok(()) => ProxyResult::Ok,
            Err(error) => {
                send_log(4, &format!("Failed to request TUN elevation: {error}"));
                ProxyResult::RuntimeError
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        ProxyResult::InvalidParam
    }
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
        if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
            if let Some(tun_token) = lifecycle.cancel_token.take() {
                tun_token.cancel();
            }
            lifecycle.stopped = None;
        }
        handle.tun_generation.fetch_add(1, Ordering::AcqRel);
        handle.tun_running.store(false, Ordering::Release);
        handle.force_proxy.store(false, Ordering::Release);
        return ProxyResult::NotRunning;
    }

    if let Some(token) = handle.cancel_token.take() {
        if let Ok(mut lifecycle) = handle.tun_lifecycle.lock() {
            if let Some(tun_token) = lifecycle.cancel_token.take() {
                tun_token.cancel();
            }
            lifecycle.stopped = None;
        }
        handle.tun_generation.fetch_add(1, Ordering::AcqRel);
        token.cancel();
        handle.running.store(false, Ordering::SeqCst);
        handle.tun_running.store(false, Ordering::Release);
        handle.force_proxy.store(false, Ordering::Release);
        if let Ok(mut endpoint) = handle.remote_endpoint.lock() {
            *endpoint = None;
        }
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
/// empty. Established relays whose decision changes are closed so their source
/// application reconnects through the newly selected route.
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
    clear_last_error(handle);
    ProxyResult::Ok
}

/// Return live and registered Windows executable names as a JSON string.
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

/// Return grouped live and registered application details as JSON.
///
/// This is additive to `proxy_list_tun_processes`, which retains its original
/// string-array ABI for existing native consumers. The caller must release the
/// returned pointer with `proxy_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_list_tun_processes_v2() -> *mut c_char {
    crate::init_allocator();
    let json = match serde_json::to_string(&running_processes()) {
        Ok(json) => json,
        Err(error) => {
            send_log(
                4,
                &format!("Failed to serialize detailed running process list: {error}"),
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

/// Return the most recent detailed error associated with this handle.
///
/// Result codes remain stable for ABI compatibility; this additive accessor
/// lets UI clients display the native operation and OS detail instead of a
/// generic `RuntimeError`. The caller must use `proxy_free_string`.
///
/// # Safety
/// `handle` must be null or a valid pointer returned by `proxy_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_get_last_error(handle: *const ProxyHandle) -> *mut c_char {
    crate::init_allocator();
    if handle.is_null() {
        return ptr::null_mut();
    }
    let handle = unsafe { &*handle };
    let error = match handle.last_error.lock() {
        Ok(error) => error.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    error
        .and_then(|error| CString::new(error).ok())
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
        if let Ok(lifecycle) = handle.tun_lifecycle.lock()
            && let Some(token) = &lifecycle.cancel_token
        {
            token.cancel();
        }
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
    fn lan_exposure_is_explicit_and_legacy_safe() {
        assert_eq!(local_listen_host(false), "127.0.0.1");
        assert_eq!(local_listen_host(true), "0.0.0.0");
    }

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

    #[test]
    fn tun_cannot_start_before_local_listener() {
        let handle = proxy_create();
        assert!(!handle.is_null());
        assert_eq!(
            unsafe { proxy_start_tun(handle, ptr::null()) },
            ProxyResult::NotRunning
        );
        assert_eq!(unsafe { proxy_is_tun_running(handle) }, 0);
        let error = unsafe { proxy_get_last_error(handle) };
        assert!(!error.is_null());
        assert!(
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .contains("Start the local proxy listener")
        );
        unsafe { crate::logging::proxy_free_string(error) };
        assert_eq!(unsafe { proxy_stop_tun(handle) }, ProxyResult::NotRunning);
        unsafe { proxy_destroy(handle) };
    }

    #[test]
    fn upstream_switch_requires_running_listener_and_stopped_tun() {
        let handle = proxy_create();
        assert!(!handle.is_null());
        let host = CString::new("new.example").unwrap();
        let original_runtime_endpoint = proxy_core::config::runtime::server_endpoint();

        assert_eq!(
            unsafe { proxy_switch_upstream(handle, host.as_ptr(), 2081) },
            ProxyResult::NotRunning
        );

        let state = unsafe { &*handle };
        state.running.store(true, Ordering::Release);
        state.tun_running.store(true, Ordering::Release);
        assert_eq!(
            unsafe { proxy_switch_upstream(handle, host.as_ptr(), 2081) },
            ProxyResult::RuntimeError
        );

        state.tun_running.store(false, Ordering::Release);
        assert_eq!(
            unsafe { proxy_switch_upstream(handle, host.as_ptr(), 2081) },
            ProxyResult::Ok
        );
        assert_eq!(
            state.remote_endpoint.lock().unwrap().as_ref(),
            Some(&("new.example".to_string(), 2081))
        );
        let runtime_endpoint = proxy_core::config::runtime::server_endpoint();
        assert_eq!(runtime_endpoint.host, "new.example");
        assert_eq!(runtime_endpoint.port, 2081);

        proxy_core::config::runtime::set_server_endpoint(
            original_runtime_endpoint.host.clone(),
            original_runtime_endpoint.port,
        );
        state.running.store(false, Ordering::Release);
        unsafe { proxy_destroy(handle) };
    }
}
