//! C FFI interface for iOS/mobile integration.
//!
//! This module provides a C-compatible interface for mobile apps to use the proxy client.
//! It creates a simple HTTP proxy that forwards traffic through the configured server.

use std::ffi::{CStr, c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::codec::{AsyncReader, AsyncReaderWriterRef, AsyncWriter};
use crate::config::gen_random_key;
use crate::geo::query_geo_single;
use crate::{
    Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader, client_proxy_with_cryptor_codec, set_data_size,
};

/// Opaque handle to the proxy client.
pub struct ProxyHandle {
    runtime: Runtime,
    shutdown_tx: Option<mpsc::Sender<()>>,
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
        shutdown_tx: None,
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

    let server_port = config.server_port;
    let local_port = config.local_port;
    let auto_proxy = config.auto_proxy != 0;
    let reverse_geo = config.reverse_geo != 0;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    handle.shutdown_tx = Some(shutdown_tx);
    handle.running.store(true, Ordering::SeqCst);

    // Spawn proxy task
    handle.runtime.spawn(async move {
        tracing::info!(
            "Starting proxy: local:{} -> {}:{} (auto_proxy={}, reverse_geo={})",
            local_port,
            server_host,
            server_port,
            auto_proxy,
            reverse_geo
        );

        let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind listener: {}", e);
                return;
            }
        };

        // Use session_key in the loop
        let session_key = session_key;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((client_stream, addr)) => {
                            tracing::debug!("Accepted connection from {}", addr);
                            let server_host = server_host.clone();
                            let session_key = session_key.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    client_stream,
                                    &server_host,
                                    server_port,
                                    &session_key,
                                    auto_proxy,
                                    reverse_geo,
                                ).await {
                                    tracing::error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Proxy shutdown requested");
                    break;
                }
            }
        }
    });

    ProxyResult::Ok
}

/// Handle a single connection with auto-proxy support.
async fn handle_connection(
    mut client_stream: TcpStream,
    server_host: &str,
    server_port: u16,
    session_key: &str,
    auto_proxy: bool,
    reverse_geo: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, copy_bidirectional};

    // Read initial request to determine target
    let mut buf = [0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // Parse HTTP CONNECT or get host from request
    let request = String::from_utf8_lossy(&buf[..n]);
    let (target_host, target_port) = parse_target_from_request(&request)?;

    // Determine if we should use proxy based on geo location
    let should_proxy = if auto_proxy {
        // Skip geo check for these domains to avoid circular dependency
        let direct_domains = ["ip-api.com", "captive.apple.com", "apple.com/library/test"];
        if direct_domains.iter().any(|d| target_host.contains(d)) {
            tracing::info!("Direct connection for whitelisted domain: {}", target_host);
            false
        } else {
            match query_geo_single(&target_host).await {
                Ok(country_code) => {
                    let is_cn = country_code == "CN";
                    let result = if reverse_geo { is_cn } else { !is_cn };
                    tracing::info!(
                        "Geo check: {} -> {} (reverse_geo={}, should_proxy={})",
                        target_host, country_code, reverse_geo, result
                    );
                    result
                }
                Err(e) => {
                    tracing::warn!("Geo query failed for {}: {}, defaulting to proxy", target_host, e);
                    true // Default to proxy when geo query fails
                }
            }
        }
    } else {
        true // Always proxy if auto_proxy is disabled
    };

    if !should_proxy {
        // Direct connection
        tracing::info!("Direct connection to {}:{}", target_host, target_port);
        let mut target_stream = TcpStream::connect((&*target_host, target_port)).await?;

        if request.starts_with("CONNECT") {
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        } else {
            // Forward the initial request for non-CONNECT
            target_stream.write_all(&buf[..n]).await?;
        }

        copy_bidirectional(&mut client_stream, &mut target_stream).await?;
        return Ok(());
    }

    tracing::info!("Proxying to {}:{}", target_host, target_port);

    // Connect to proxy server
    let mut server_stream = TcpStream::connect((server_host, server_port)).await?;

    // Generate random key for this session
    let msg_key = gen_random_key();

    // Send proxy header
    let proxy_header = ProxyHeader {
        host: target_host.clone().into(),
        port: target_port,
        key: Some(msg_key.clone().into()),
    };

    let mut header_bytes = serde_json::to_string(&proxy_header)?.into_bytes();
    let mut cryption = Aes256GcmCryption::try_new(session_key.as_bytes())
        .map_err(|e| format!("Crypto error: {}", e))?;

    // Encrypt header
    let tag = cryption
        .encrypt(&mut header_bytes)
        .map_err(|e| format!("Encrypt error: {}", e))?;
    let len = (header_bytes.len() + tag.as_ref().len()) as u32;

    // Send header length + encrypted header + tag
    let mut server_ref = AsyncReaderWriterRef::new(&mut server_stream);
    set_data_size(&mut server_ref, len).await?;
    server_ref.write_all(&header_bytes).await?;
    server_ref.write_all(tag.as_ref()).await?;

    // For CONNECT requests, send 200 OK to client
    if request.starts_with("CONNECT") {
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    // Split streams
    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    // Start bidirectional proxy with encryption
    client_proxy_with_cryptor_codec(
        &target_host,
        &msg_key,
        AsyncReader::new(client_read),
        AsyncReader::new(server_read),
        AsyncWriter::new(client_write),
        AsyncWriter::new(server_write),
    )
    .await?;

    Ok(())
}

/// Parse target host and port from HTTP request.
fn parse_target_from_request(
    request: &str,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let first_line = request.lines().next().ok_or("Empty request")?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err("Invalid request format".into());
    }

    let method = parts[0];
    let target = parts[1];

    if method == "CONNECT" {
        // CONNECT host:port HTTP/1.1
        let host_port: Vec<&str> = target.split(':').collect();
        if host_port.len() == 2 {
            let host = host_port[0].to_string();
            let port = host_port[1].parse::<u16>().unwrap_or(443);
            return Ok((host, port));
        }
    }

    // Try to parse from Host header
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host_value = line[5..].trim();
            let host_port: Vec<&str> = host_value.split(':').collect();
            let host = host_port[0].to_string();
            let port = if host_port.len() > 1 {
                host_port[1].parse::<u16>().unwrap_or(80)
            } else {
                80
            };
            return Ok((host, port));
        }
    }

    Err("Could not determine target host".into())
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

    match handle.shutdown_tx.take() {
        Some(tx) => {
            let _ = handle.runtime.block_on(tx.send(()));
            handle.running.store(false, Ordering::SeqCst);
            ProxyResult::Ok
        }
        None => ProxyResult::NotRunning,
    }
}

/// Destroy the proxy handle and free resources.
///
/// # Safety
/// `handle` must be a valid pointer from `proxy_create` and must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_destroy(handle: *mut ProxyHandle) {
    if !handle.is_null() {
        let mut handle = unsafe { Box::from_raw(handle) };
        if let Some(tx) = handle.shutdown_tx.take() {
            let _ = handle.runtime.block_on(tx.send(()));
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
