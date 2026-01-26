//! Server nodes query API.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::time::Duration;

use proxy_core::config::DEFAULT_SECRET_KEY;
use proxy_core::control::ControlClient;
use proxy_core::geo::query_geo_batch;
use proxy_core::util::error_report;
use tokio::runtime::Runtime;

use crate::latency::DEFAULT_TIMEOUT_MS;
use crate::types::{NodeInfoWithGeo, NodesResult};

/// Get all nodes from a server with geo location info.
///
/// # Safety
/// - `server_host` must be a valid C string
/// - `session_key` can be null to use default key
/// - Caller must free the result with `proxy_free_nodes_result`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_get_server_nodes(
    server_host: *const c_char,
    server_port: u16,
    session_key: *const c_char,
    timeout_ms: u32,
) -> NodesResult {
    if server_host.is_null() {
        tracing::error!("proxy_get_server_nodes: invalid server host");
        return NodesResult {
            success: 0,
            nodes: ptr::null_mut(),
            count: 0,
            error: CString::new("Invalid server host").unwrap().into_raw(),
        };
    }

    let host = match unsafe { CStr::from_ptr(server_host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::error!("proxy_get_server_nodes: invalid server host encoding");
            return NodesResult {
                success: 0,
                nodes: ptr::null_mut(),
                count: 0,
                error: CString::new("Invalid server host encoding")
                    .unwrap()
                    .into_raw(),
            };
        }
    };

    // Use default key if session_key is null or empty
    let key = if session_key.is_null() {
        Some(DEFAULT_SECRET_KEY.to_string())
    } else {
        match unsafe { CStr::from_ptr(session_key) }.to_str() {
            Ok("") => Some(DEFAULT_SECRET_KEY.to_string()),
            Ok(s) => Some(s.to_string()),
            Err(_) => Some(DEFAULT_SECRET_KEY.to_string()),
        }
    };

    let timeout = Duration::from_millis(if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    } as u64);

    // Create a temporary runtime for this operation
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(
                "proxy_get_server_nodes: failed to create runtime: {}",
                error_report(&e)
            );
            return NodesResult {
                success: 0,
                nodes: ptr::null_mut(),
                count: 0,
                error: CString::new(format!("Failed to create runtime: {}", error_report(&e)))
                    .unwrap()
                    .into_raw(),
            };
        }
    };

    runtime.block_on(async {
        // Connect to server with timeout
        let connect_result = tokio::time::timeout(
            timeout,
            ControlClient::connect(&host, server_port, key.clone()),
        )
        .await;

        let mut client = match connect_result {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::error!(
                    "proxy_get_server_nodes: connection failed to {}:{}: {}",
                    host,
                    server_port,
                    error_report(&e)
                );
                return NodesResult {
                    success: 0,
                    nodes: ptr::null_mut(),
                    count: 0,
                    error: CString::new(format!("Connection failed: {}", error_report(&e)))
                        .unwrap()
                        .into_raw(),
                };
            }
            Err(_) => {
                tracing::error!(
                    "proxy_get_server_nodes: connection timeout to {}:{}",
                    host,
                    server_port
                );
                return NodesResult {
                    success: 0,
                    nodes: ptr::null_mut(),
                    count: 0,
                    error: CString::new("Connection timeout").unwrap().into_raw(),
                };
            }
        };

        // Get nodes list
        let nodes = match client.list_nodes(key.clone()).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(
                    "proxy_get_server_nodes: failed to list nodes: {}",
                    error_report(&e)
                );
                return NodesResult {
                    success: 0,
                    nodes: ptr::null_mut(),
                    count: 0,
                    error: CString::new(format!("Failed to list nodes: {}", error_report(&e)))
                        .unwrap()
                        .into_raw(),
                };
            }
        };

        if nodes.is_empty() {
            return NodesResult {
                success: 1,
                nodes: ptr::null_mut(),
                count: 0,
                error: ptr::null_mut(),
            };
        }

        // Extract IPs from node addresses for geo query
        let ips: Vec<String> = nodes
            .iter()
            .filter_map(|n| n.addr.split(':').next().map(|s| s.to_string()))
            .collect();

        // Query geo info
        let geo_map = query_geo_batch(&ips).await.unwrap_or_default();

        // Convert to C-compatible format
        let mut c_nodes: Vec<NodeInfoWithGeo> = Vec::with_capacity(nodes.len());
        for node in &nodes {
            let ip = node.addr.split(':').next().unwrap_or("");
            let country = geo_map.get(ip).cloned().unwrap_or_default();

            c_nodes.push(NodeInfoWithGeo {
                node_id: CString::new(node.node_id.clone()).unwrap().into_raw(),
                addr: CString::new(node.addr.clone()).unwrap().into_raw(),
                last_seen_ms: node.last_seen_ms,
                country: CString::new(country).unwrap().into_raw(),
                region: CString::new("").unwrap().into_raw(),
            });
        }

        let count = c_nodes.len();
        let ptr = c_nodes.as_mut_ptr();
        std::mem::forget(c_nodes);

        NodesResult {
            success: 1,
            nodes: ptr,
            count,
            error: ptr::null_mut(),
        }
    })
}

/// Free a NodesResult.
///
/// # Safety
/// `result` must be a valid pointer to a NodesResult returned from `proxy_get_server_nodes`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_nodes_result(result: *mut NodesResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.error.is_null() {
        unsafe { drop(CString::from_raw(result.error)) };
        result.error = ptr::null_mut();
    }

    if !result.nodes.is_null() && result.count > 0 {
        let nodes = unsafe { Vec::from_raw_parts(result.nodes, result.count, result.count) };
        for node in nodes {
            if !node.node_id.is_null() {
                unsafe { drop(CString::from_raw(node.node_id)) };
            }
            if !node.addr.is_null() {
                unsafe { drop(CString::from_raw(node.addr)) };
            }
            if !node.country.is_null() {
                unsafe { drop(CString::from_raw(node.country)) };
            }
            if !node.region.is_null() {
                unsafe { drop(CString::from_raw(node.region)) };
            }
        }
        result.nodes = ptr::null_mut();
        result.count = 0;
    }
}
