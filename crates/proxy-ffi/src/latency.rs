//! Latency test API.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use proxy_core::util::error_report;

use crate::handle::ProxyHandle;
use crate::types::LatencyResult;

pub(crate) const DEFAULT_TEST_URL: &str = "https://www.google.com/generate_204";
pub(crate) const DEFAULT_TIMEOUT_MS: u32 = 10000; // 10 seconds

/// Test proxy latency by sending HTTPS request through the proxy.
///
/// # Safety
/// - `handle` must be a valid pointer from `proxy_create` and proxy must be running
/// - `test_url` can be null to use default URL (https://www.google.com/generate_204)
/// - Caller must free the result with `proxy_free_latency_result`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_test_latency(
    handle: *const ProxyHandle,
    test_url: *const c_char,
    timeout_ms: u32,
) -> LatencyResult {
    if handle.is_null() {
        tracing::error!("proxy_test_latency: invalid handle");
        return LatencyResult {
            success: 0,
            latency_ms: 0,
            error: CString::new("Invalid handle").unwrap().into_raw(),
        };
    }

    let handle = unsafe { &*handle };
    if !handle.running.load(Ordering::SeqCst) {
        tracing::error!("proxy_test_latency: proxy not running");
        return LatencyResult {
            success: 0,
            latency_ms: 0,
            error: CString::new("Proxy not running").unwrap().into_raw(),
        };
    }

    let url = if test_url.is_null() {
        DEFAULT_TEST_URL.to_string()
    } else {
        match unsafe { CStr::from_ptr(test_url) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                tracing::error!("proxy_test_latency: invalid test URL encoding");
                return LatencyResult {
                    success: 0,
                    latency_ms: 0,
                    error: CString::new("Invalid test URL").unwrap().into_raw(),
                };
            }
        }
    };

    let timeout = Duration::from_millis(if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    } as u64);

    // Get or create cached HTTP client
    let client = {
        let mut guard = handle.http_client.lock().unwrap();
        if guard.is_none() {
            let proxy_url = format!("http://127.0.0.1:{}", handle.local_port);
            match reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url).expect("valid proxy URL"))
                .build()
            {
                Ok(c) => *guard = Some(c),
                Err(e) => {
                    tracing::error!(
                        "proxy_test_latency: failed to create client: {}",
                        error_report(&e)
                    );
                    return LatencyResult {
                        success: 0,
                        latency_ms: 0,
                        error: CString::new(format!(
                            "Failed to create client: {}",
                            error_report(&e)
                        ))
                        .unwrap()
                        .into_raw(),
                    };
                }
            }
        }
        guard.clone().unwrap()
    };

    handle.runtime.block_on(async {
        let start = Instant::now();
        match client.head(&url).timeout(timeout).send().await {
            Ok(_) => LatencyResult {
                success: 1,
                latency_ms: start.elapsed().as_millis() as u64,
                error: ptr::null_mut(),
            },
            Err(e) => {
                tracing::warn!("proxy_test_latency: request failed: {}", error_report(&e));
                LatencyResult {
                    success: 0,
                    latency_ms: start.elapsed().as_millis() as u64,
                    error: CString::new(format!("Request failed: {}", error_report(&e)))
                        .unwrap()
                        .into_raw(),
                }
            }
        }
    })
}

/// Free a LatencyResult.
///
/// # Safety
/// `result` must be a valid pointer to a LatencyResult returned from `proxy_test_latency`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_latency_result(result: *mut LatencyResult) {
    if !result.is_null() {
        let result = unsafe { &mut *result };
        if !result.error.is_null() {
            unsafe { drop(CString::from_raw(result.error)) };
            result.error = ptr::null_mut();
        }
    }
}
