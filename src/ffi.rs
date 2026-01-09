//! C FFI interface for iOS/mobile integration.
//!
//! This module provides a C-compatible interface for mobile apps to use the proxy client.
//! It reuses the existing client module logic.

use std::ffi::{CStr, c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::client::run_client_with_listener;

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    runtime: Runtime,
    cancel_token: Option<CancellationToken>,
    running: AtomicBool,
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
    pub session_key: *const c_char,
    pub auto_proxy: c_int,   // 0 = disabled, 1 = enabled
    pub reverse_geo: c_int,  // 0 = CN direct, 1 = CN proxy
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
            tracing::error!("Failed to create runtime: {}", e);
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(ProxyHandle {
        runtime,
        cancel_token: None,
        running: AtomicBool::new(false),
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

    let session_key = match unsafe { CStr::from_ptr(config.session_key) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ProxyResult::InvalidParam,
    };

    // Validate session key length (must be 32 bytes for AES-256)
    if session_key.len() != 32 {
        tracing::error!("Session key must be 32 bytes, got {}", session_key.len());
        return ProxyResult::InvalidParam;
    }

    let server_port = config.server_port;
    let local_port = config.local_port;
    let reverse_geo = config.reverse_geo != 0;

    // Set environment variables for client module
    // SAFETY: Called before spawning async tasks, single-threaded at this point
    unsafe {
        std::env::set_var("SERVER_HOST", &server_host);
        std::env::set_var("SERVER_PORT", server_port.to_string());
        std::env::set_var("SECRET_KEY", &session_key);
        if reverse_geo {
            std::env::set_var("REVERSE_GEO_PROXY", "true");
        }
    }

    let cancel_token = CancellationToken::new();
    handle.cancel_token = Some(cancel_token.clone());
    handle.running.store(true, Ordering::SeqCst);

    // Spawn proxy task using existing client logic
    handle.runtime.spawn(async move {
        tracing::info!(
            "Starting proxy: local:{} -> {}:{} (reverse_geo={})",
            local_port,
            server_host,
            server_port,
            reverse_geo
        );

        let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind listener: {}", e);
                return;
            }
        };

        // Use existing client logic with NEED_CODEC=true for encrypted proxy
        run_client_with_listener::<true>(listener, cancel_token, None).await;

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

/// Initialize logging.
///
/// # Safety
/// Can be called multiple times safely.
#[unsafe(no_mangle)]
pub extern "C" fn proxy_init_logging() {
    use tracing_subscriber::EnvFilter;

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("http_proxy=info".parse().unwrap()),
        )
        .try_init();
}
