//! C FFI interface for cross-platform integration.
//!
//! This module provides a C-compatible interface for external applications to use the proxy client.
//! It reuses the existing client module logic.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use crate::cli_config::SystemProxyGuard;
use crate::client::{ClientConfig, run_client_with_listener};

/// Log callback function type.
/// level: 0=trace, 1=debug, 2=info, 3=warn, 4=error
pub type LogCallback = extern "C" fn(level: c_int, message: *const c_char);

/// Global log callback
static LOG_CALLBACK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    runtime: Runtime,
    cancel_token: Option<CancellationToken>,
    running: AtomicBool,
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    _system_proxy_guard: Option<SystemProxyGuard>,
}

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

/// Set log callback function.
///
/// # Safety
/// `callback` must be a valid function pointer or null to disable logging.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_set_log_callback(callback: Option<LogCallback>) {
    let ptr = callback.map(|f| f as *mut ()).unwrap_or(ptr::null_mut());
    LOG_CALLBACK.store(ptr, Ordering::SeqCst);
}

/// Internal function to send log to callback
fn send_log(level: c_int, message: &str) {
    let ptr = LOG_CALLBACK.load(Ordering::SeqCst);
    if !ptr.is_null()
        && let Ok(c_msg) = CString::new(message)
    {
        let callback: LogCallback = unsafe { std::mem::transmute(ptr) };
        // Leak the string - caller must free it via proxy_free_string
        let leaked = c_msg.into_raw();
        callback(level, leaked);
    }
}

/// Free a string allocated by the library (e.g., from log callback).
///
/// # Safety
/// `s` must be a valid pointer returned from a log callback, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Custom tracing layer that forwards logs to FFI callback
struct FfiLogLayer;

impl<S> tracing_subscriber::Layer<S> for FfiLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            tracing::Level::TRACE => 0,
            tracing::Level::DEBUG => 1,
            tracing::Level::INFO => 2,
            tracing::Level::WARN => 3,
            tracing::Level::ERROR => 4,
        };

        // Format the event message
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = format!(
            "[{}] {}",
            event.metadata().target(),
            visitor.message.unwrap_or_default()
        );
        send_log(level, &message);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        } else if self.message.is_none() {
            self.message = Some(format!("{}: {:?}", field.name(), value));
        } else if let Some(msg) = self.message.take() {
            self.message = Some(format!("{}, {}: {:?}", msg, field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else if self.message.is_none() {
            self.message = Some(format!("{}: {}", field.name(), value));
        } else if let Some(msg) = self.message.take() {
            self.message = Some(format!("{}, {}: {}", msg, field.name(), value));
        }
    }
}

/// Create a new proxy handle.
///
/// # Safety
/// Returns a pointer to ProxyHandle that must be freed with `proxy_destroy`.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_create() -> *mut ProxyHandle {
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
        running: AtomicBool::new(false),
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        _system_proxy_guard: None,
    }))
}

/// Initialize (or update) runtime config without starting the local proxy listener.
///
/// This is primarily used by VPN mode to configure server host/port/session key
/// before starting the TUN handler.
///
/// # Safety
/// - `config` must be a valid pointer to [`ProxyConfig`].
/// - `config.server_host` must be a valid, non-null C string.
/// - Other string fields may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_init_config(config: *const ProxyConfig) -> ProxyResult {
    if config.is_null() {
        return ProxyResult::InvalidParam;
    }

    let config = unsafe { &*config };

    if config.server_host.is_null() {
        send_log(4, "server_host is null");
        return ProxyResult::InvalidParam;
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

    // need_codec_ips: null or empty = empty list (no codec IPs), otherwise comma-separated
    let need_codec_ips = if config.need_codec_ips.is_null() {
        vec![]
    } else {
        match unsafe { CStr::from_ptr(config.need_codec_ips) }.to_str() {
            Ok(s) if !s.is_empty() => s.split(',').map(|ip| ip.trim().to_string()).collect(),
            _ => vec![],
        }
    };

    let server_port = config.server_port;
    let reverse_geo = config.reverse_geo != 0;

    crate::config::runtime::init_config(
        server_host.clone(),
        server_port,
        reverse_geo,
        need_codec_ips,
        session_key,
    );

    ProxyResult::Ok
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

    let handle = unsafe { &mut *handle };
    let config = unsafe { &*config };

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

    // Set system proxy for desktop platforms
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

    // Initialize runtime config directly (no env vars needed)
    crate::config::runtime::init_config(
        server_host.clone(),
        server_port,
        reverse_geo,
        need_codec_ips.clone().unwrap_or_default(),
        session_key.clone(),
    );

    // Build ClientConfig for runtime options
    let client_config = ClientConfig {
        enable_auto_proxy,
        cache_dir,
    };

    let cancel_token = CancellationToken::new();
    handle.cancel_token = Some(cancel_token.clone());
    handle.running.store(true, Ordering::SeqCst);

    // Spawn proxy task using existing client logic
    handle.runtime.spawn(async move {
        tracing::info!(
            "Starting proxy: local:{} -> {}:{} (reverse_geo={}, auto_proxy={}, force_codec={})",
            local_port,
            server_host,
            server_port,
            reverse_geo,
            enable_auto_proxy,
            force_codec
        );

        let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind listener: {}", e);
                return;
            }
        };

        // Use force_codec to determine NEED_CODEC constant
        if force_codec {
            run_client_with_listener::<true>(listener, cancel_token, None, Some(client_config))
                .await;
        } else {
            run_client_with_listener::<false>(listener, cancel_token, None, Some(client_config))
                .await;
        }

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

/// Initialize logging with FFI callback support.
///
/// # Safety
/// Can be called multiple times safely.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_init_logging() {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(FfiLogLayer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive("http_proxy=info".parse().expect("valid directive")),
                ),
        )
        .try_init();
}

// ============================================================================
// VPN-related FFI functions
// ============================================================================

#[cfg(feature = "vpn")]
use std::sync::RwLock;

#[cfg(feature = "vpn")]
static PROTECT_CALLBACK: RwLock<Option<ProtectCallback>> = RwLock::new(None);

#[cfg(all(feature = "vpn", target_os = "android"))]
use std::sync::OnceLock;

#[cfg(all(feature = "vpn", target_os = "android"))]
use jni::{JNIEnv, JavaVM, objects::JClass};

#[cfg(all(feature = "vpn", target_os = "android"))]
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Socket protection callback type for VPN.
/// Returns true if socket was successfully protected.
pub type ProtectCallback = extern "C" fn(fd: i32) -> bool;

/// Called by Android to register the `protect()` bridge for the current process.
///
/// Kotlin side: `ProxyVpnService.nativeRegisterProtectCallback()`.
#[cfg(all(feature = "vpn", target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_proxyui_proxy_1ui_ProxyVpnService_nativeRegisterProtectCallback(
    env: JNIEnv,
    _class: JClass,
) {
    if JAVA_VM.get().is_none() {
        match env.get_java_vm() {
            Ok(vm) => {
                let _ = JAVA_VM.set(vm);
            }
            Err(err) => {
                tracing::error!("Failed to get JavaVM: {}", err);
                return;
            }
        }
    }

    proxy_register_protect_callback(Some(android_protect_socket));
}

#[cfg(all(feature = "vpn", target_os = "android"))]
extern "C" fn android_protect_socket(fd: i32) -> bool {
    let Some(vm) = JAVA_VM.get() else {
        return false;
    };

    let Ok(env) = vm.attach_current_thread() else {
        return false;
    };

    let Ok(class) = env.find_class("com/proxyui/proxy_ui/ProxyVpnService") else {
        return false;
    };

    let Ok(result) = env.call_static_method(class, "protectSocketFromJNI", "(I)Z", &[fd.into()])
    else {
        return false;
    };

    result.z().unwrap_or(false)
}

/// Register socket protection callback for VPN mode.
///
/// # Safety
/// `callback` must be a valid function pointer or null to disable protection.
#[cfg(feature = "vpn")]
#[unsafe(no_mangle)]
pub extern "C" fn proxy_register_protect_callback(callback: Option<ProtectCallback>) {
    let mut guard = match PROTECT_CALLBACK.write() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    *guard = callback;
    tracing::info!(
        "Socket protection callback registered: {}",
        callback.is_some()
    );
}

#[cfg(not(feature = "vpn"))]
#[unsafe(no_mangle)]
pub extern "C" fn proxy_register_protect_callback(_callback: Option<ProtectCallback>) {
    tracing::warn!("VPN feature not enabled, protect callback ignored");
}

/// Call the registered socket protection callback.
///
/// # Safety
/// Should only be called from within the proxy library.
#[cfg(feature = "vpn")]
pub fn protect_socket(fd: i32) -> bool {
    let callback = match PROTECT_CALLBACK.read() {
        Ok(g) => *g,
        Err(e) => *e.into_inner(),
    };
    callback.map(|cb| cb(fd)).unwrap_or(false)
}

#[cfg(not(feature = "vpn"))]
pub fn protect_socket(_fd: i32) -> bool {
    false
}

/// Start VPN mode with TUN device.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create`
/// - `tun_fd` must be a valid file descriptor from Android VpnService
/// - `protect_callback` must be a valid function pointer
#[cfg(feature = "vpn")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_vpn(
    handle: *mut ProxyHandle,
    tun_fd: i32,
    protect_callback: Option<ProtectCallback>,
) -> ProxyResult {
    if handle.is_null() {
        return ProxyResult::InvalidParam;
    }

    let handle = unsafe { &mut *handle };

    if handle.running.load(Ordering::SeqCst) {
        return ProxyResult::AlreadyRunning;
    }

    let cancel_token = CancellationToken::new();

    // Register protect callback only when provided.
    if protect_callback.is_some() {
        proxy_register_protect_callback(protect_callback);
    }

    // Resolve effective callback (explicit argument wins; otherwise use previously registered one).
    let effective_protect_callback = protect_callback.or_else(|| {
        let guard = match PROTECT_CALLBACK.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *guard
    });

    // Create TUN handler
    let tun_handler =
        match crate::tun::TunHandler::new(tun_fd, effective_protect_callback, cancel_token.clone())
        {
            Ok(h) => h,
            Err(e) => {
                send_log(4, &format!("Failed to create TUN handler: {}", e));
                return ProxyResult::RuntimeError;
            }
        };

    handle.cancel_token = Some(cancel_token.clone());
    handle.running.store(true, Ordering::SeqCst);

    // Start TUN handler
    handle.runtime.spawn(async move {
        tracing::info!("Starting VPN mode with TUN FD: {}", tun_fd);

        if let Err(e) = tun_handler.start().await {
            tracing::error!("TUN handler error: {}", e);
        }

        tracing::info!("VPN mode stopped");
    });

    ProxyResult::Ok
}

#[cfg(not(feature = "vpn"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_start_vpn(
    _handle: *mut ProxyHandle,
    _tun_fd: i32,
    _protect_callback: Option<ProtectCallback>,
) -> ProxyResult {
    send_log(4, "VPN feature not enabled");
    ProxyResult::RuntimeError
}
