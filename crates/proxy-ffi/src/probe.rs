//! Egress verification for a single node.
//!
//! The node catalogue reports where a server is registered, which is not
//! necessarily where its traffic leaves from: a node can be fronted, relayed, or
//! simply mislabelled. The only way to know is to ask an echo service through
//! the node and see which address answers.

use std::borrow::Cow;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::time::{Duration, Instant};

use proxy_core::config::gen_random_key;
use proxy_core::transport::{change_msg_key, get_tcp_proxy_stream};
use proxy_core::util::error_report;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::latency::DEFAULT_TIMEOUT_MS;
use crate::types::NodeProbeResult;

/// Plain HTTP on purpose: the request travels inside the node tunnel, and the
/// same service already backs geo lookups elsewhere in the workspace.
const ECHO_HOST: &str = "ip-api.com";
const ECHO_PORT: u16 = 80;

/// Line mode returns one value per line in the order requested, which avoids
/// pulling a JSON parser into this path.
const ECHO_REQUEST: &str = concat!(
    "GET /line/?fields=status,countryCode,query HTTP/1.1\r\n",
    "Host: ip-api.com\r\n",
    "User-Agent: proxy-everything\r\n",
    "Connection: close\r\n",
    "\r\n"
);

/// Enough for the echo response; anything larger is not the service answering.
const MAX_ECHO_RESPONSE: usize = 8 * 1024;

fn failure(message: impl AsRef<str>, latency_ms: u64) -> NodeProbeResult {
    NodeProbeResult {
        success: 0,
        country_code: CString::new("").unwrap().into_raw(),
        egress_ip: CString::new("").unwrap().into_raw(),
        latency_ms,
        error: CString::new(message.as_ref())
            .unwrap_or_else(|_| CString::new("Probe failed").unwrap())
            .into_raw(),
    }
}

/// Verify where a node's traffic egresses.
///
/// # Safety
/// - `server_host` must be a valid C string.
/// - `session_key` may be null.
/// - The caller must free the result with `proxy_free_node_probe_result`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_probe_node(
    server_host: *const c_char,
    server_port: u16,
    force_codec: c_int,
    timeout_ms: u32,
) -> NodeProbeResult {
    if server_host.is_null() {
        return failure("Invalid server host", 0);
    }
    let Ok(host) = (unsafe { CStr::from_ptr(server_host) }).to_str() else {
        return failure("Invalid server host encoding", 0);
    };
    let host = host.to_string();

    let timeout = Duration::from_millis(if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    } as u64);

    let Some(runtime) = crate::runtime::control() else {
        return failure("Runtime unavailable", 0);
    };

    runtime.block_on(async move {
        let start = Instant::now();
        match tokio::time::timeout(timeout, probe(&host, server_port, force_codec != 0)).await {
            Ok(Ok((country_code, egress_ip))) => NodeProbeResult {
                success: 1,
                country_code: CString::new(country_code).unwrap().into_raw(),
                egress_ip: CString::new(egress_ip).unwrap().into_raw(),
                latency_ms: start.elapsed().as_millis() as u64,
                error: ptr::null_mut(),
            },
            Ok(Err(message)) => failure(message, start.elapsed().as_millis() as u64),
            Err(_) => failure("Probe timed out", start.elapsed().as_millis() as u64),
        }
    })
}

/// Returns `(country_code, egress_ip)` or a human-readable failure.
async fn probe(host: &str, port: u16, force_codec: bool) -> Result<(String, String), String> {
    // Mirror what a real connection through this node would negotiate, so a
    // node that only accepts encrypted sessions is probed the same way it is
    // used. A forced session key matches the client's force-codec setting.
    let msg_key = if force_codec {
        Some(Cow::Owned(gen_random_key()))
    } else {
        change_msg_key(host, None)
    };

    let mut stream = get_tcp_proxy_stream(ECHO_HOST, ECHO_PORT, host, port, msg_key, "node probe")
        .await
        .map_err(|e| format!("Cannot reach the node: {}", error_report(&e)))?;

    stream
        .write_all(ECHO_REQUEST.as_bytes())
        .await
        .map_err(|e| format!("Node accepted the connection but dropped it: {}", error_report(&e)))?;

    let mut response = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("No answer through the node: {}", error_report(&e)))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_ECHO_RESPONSE {
            return Err("Unexpected response through the node".to_string());
        }
    }

    parse_echo(&response)
}

fn parse_echo(response: &[u8]) -> Result<(String, String), String> {
    let text = String::from_utf8_lossy(response);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "Malformed response through the node".to_string())?;

    let mut lines = body.lines().map(str::trim).filter(|line| !line.is_empty());
    let status = lines.next().unwrap_or_default();
    if status != "success" {
        return Err(format!("Echo service rejected the request: {status}"));
    }

    let country_code = lines.next().unwrap_or_default().to_uppercase();
    let egress_ip = lines.next().unwrap_or_default().to_string();
    if country_code.len() != 2 || egress_ip.is_empty() {
        return Err("Echo service returned an unusable answer".to_string());
    }
    Ok((country_code, egress_ip))
}

/// Free a `NodeProbeResult`.
///
/// # Safety
/// `result` must come from `proxy_probe_node`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_free_node_probe_result(result: *mut NodeProbeResult) {
    if result.is_null() {
        return;
    }
    let result = unsafe { &mut *result };
    for slot in [
        &mut result.country_code,
        &mut result.egress_ip,
        &mut result.error,
    ] {
        if !slot.is_null() {
            unsafe { drop(CString::from_raw(*slot)) };
            *slot = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_echo;

    #[test]
    fn reads_status_country_and_address() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsuccess\nJP\n203.0.113.7\n";
        let (country, ip) = parse_echo(response).expect("a successful echo parses");
        assert_eq!(country, "JP");
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn rejects_a_failed_lookup() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nfail\nprivate range\n";
        assert!(parse_echo(response).is_err());
    }

    #[test]
    fn rejects_a_truncated_body() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nsuccess\nJP\n";
        assert!(parse_echo(response).is_err());
    }

    #[test]
    fn rejects_a_response_without_headers() {
        assert!(parse_echo(b"success\nJP\n203.0.113.7\n").is_err());
    }
}
