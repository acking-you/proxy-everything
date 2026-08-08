//! Server node groups query API.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::time::Duration;

use proxy_core::config::DEFAULT_SECRET_KEY;
use proxy_core::control::ControlClient;
use proxy_core::util::error_report;

use crate::latency::DEFAULT_TIMEOUT_MS;
use crate::types::{GroupsResult, NodeGroupInfo};

/// Get all node groups from a server.
///
/// # Safety
/// - `server_host` must be a valid C string
/// - `session_key` can be null to use default key
/// - Caller must free the result with `proxy_free_groups_result`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_get_server_groups(
    server_host: *const c_char,
    server_port: u16,
    session_key: *const c_char,
    timeout_ms: u32,
) -> GroupsResult {
    if server_host.is_null() {
        tracing::error!("proxy_get_server_groups: invalid server host");
        return GroupsResult {
            success: 0,
            groups: ptr::null_mut(),
            count: 0,
            error: CString::new("Invalid server host").unwrap().into_raw(),
        };
    }

    let host = match unsafe { CStr::from_ptr(server_host) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::error!("proxy_get_server_groups: invalid server host encoding");
            return GroupsResult {
                success: 0,
                groups: ptr::null_mut(),
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

    // Shared with the other control-plane queries; see `nodes.rs`.
    let Some(runtime) = crate::runtime::control() else {
        tracing::error!("proxy_get_server_groups: control runtime unavailable");
        return GroupsResult {
            success: 0,
            groups: ptr::null_mut(),
            count: 0,
            error: CString::new("Failed to create runtime").unwrap().into_raw(),
        };
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
                    "proxy_get_server_groups: connection failed to {}:{}: {}",
                    host,
                    server_port,
                    error_report(&e)
                );
                return GroupsResult {
                    success: 0,
                    groups: ptr::null_mut(),
                    count: 0,
                    error: CString::new(format!("Connection failed: {}", error_report(&e)))
                        .unwrap()
                        .into_raw(),
                };
            }
            Err(_) => {
                tracing::error!(
                    "proxy_get_server_groups: connection timeout to {}:{}",
                    host,
                    server_port
                );
                return GroupsResult {
                    success: 0,
                    groups: ptr::null_mut(),
                    count: 0,
                    error: CString::new("Connection timeout").unwrap().into_raw(),
                };
            }
        };

        // Get groups list
        let groups = match client.list_groups(key.clone()).await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(
                    "proxy_get_server_groups: failed to list groups: {}",
                    error_report(&e)
                );
                return GroupsResult {
                    success: 0,
                    groups: ptr::null_mut(),
                    count: 0,
                    error: CString::new(format!("Failed to list groups: {}", error_report(&e)))
                        .unwrap()
                        .into_raw(),
                };
            }
        };

        if groups.is_empty() {
            return GroupsResult {
                success: 1,
                groups: ptr::null_mut(),
                count: 0,
                error: ptr::null_mut(),
            };
        }

        let mut c_groups: Vec<NodeGroupInfo> = Vec::with_capacity(groups.len());
        for group in groups {
            let node_ids_count = group.node_ids.len();
            let mut node_id_ptrs: Vec<*mut c_char> = Vec::with_capacity(node_ids_count);
            for node_id in group.node_ids {
                node_id_ptrs.push(CString::new(node_id).unwrap().into_raw());
            }

            let node_ids = if node_ids_count == 0 {
                ptr::null_mut()
            } else {
                let boxed = node_id_ptrs.into_boxed_slice();
                let ptr = boxed.as_ptr() as *mut *mut c_char;
                std::mem::forget(boxed);
                ptr
            };

            c_groups.push(NodeGroupInfo {
                group_id: CString::new(group.group_id).unwrap().into_raw(),
                name: CString::new(group.name).unwrap().into_raw(),
                node_ids,
                node_ids_count,
                created_at_ms: group.created_at_ms,
            });
        }

        let count = c_groups.len();
        let ptr = c_groups.as_mut_ptr();
        std::mem::forget(c_groups);

        GroupsResult {
            success: 1,
            groups: ptr,
            count,
            error: ptr::null_mut(),
        }
    })
}

/// Free a GroupsResult.
///
/// # Safety
/// `result` must be a valid pointer to a GroupsResult returned from `proxy_get_server_groups`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_groups_result(result: *mut GroupsResult) {
    if result.is_null() {
        return;
    }

    let result = unsafe { &mut *result };

    if !result.error.is_null() {
        unsafe { drop(CString::from_raw(result.error)) };
        result.error = ptr::null_mut();
    }

    if !result.groups.is_null() && result.count > 0 {
        let groups = unsafe { Vec::from_raw_parts(result.groups, result.count, result.count) };
        for group in groups {
            if !group.group_id.is_null() {
                unsafe { drop(CString::from_raw(group.group_id)) };
            }
            if !group.name.is_null() {
                unsafe { drop(CString::from_raw(group.name)) };
            }
            if !group.node_ids.is_null() && group.node_ids_count > 0 {
                let node_ids = unsafe {
                    Vec::from_raw_parts(group.node_ids, group.node_ids_count, group.node_ids_count)
                };
                for node_id in node_ids {
                    if !node_id.is_null() {
                        unsafe { drop(CString::from_raw(node_id)) };
                    }
                }
            }
        }
        result.groups = ptr::null_mut();
        result.count = 0;
    }
}
