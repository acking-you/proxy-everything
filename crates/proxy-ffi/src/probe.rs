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

/// Where a probe stopped.
///
/// Each stage clears a different suspect, which is the whole value of the
/// reading: reaching the node rules out routing and capture policy, the node
/// accepting the tunnel rules out the session negotiation, and bytes coming
/// back rule out the node's own upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeStage {
    /// Opening the tunnel to the node.
    Connect,
    /// Sending the echo request into an accepted tunnel.
    Request,
    /// Reading the answer back out of it.
    Response,
    /// Understanding what came back.
    Decode,
}

impl ProbeStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Request => "request",
            Self::Response => "response",
            Self::Decode => "decode",
        }
    }
}

impl std::fmt::Display for ProbeStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
struct ProbeError {
    stage: ProbeStage,
    detail: String,
}

impl ProbeError {
    fn new(stage: ProbeStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    /// The message surfaced to the caller, which is read by a person deciding
    /// whether a node is usable.
    fn user_message(&self) -> String {
        format!("{}: {}", self.stage, self.detail)
    }
}

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

/// Measure a real round trip through a node and report where it egresses.
///
/// `force_codec` mirrors the client's force-encryption setting so the node is
/// probed the way it is used.
///
/// # Safety
/// - `server_host` must be a valid C string.
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
        let outcome =
            tokio::time::timeout(timeout, probe(&host, server_port, force_codec != 0)).await;
        let elapsed = start.elapsed().as_millis() as u64;

        // A probe traverses whatever routing and capture policy is active, so
        // the stage it stopped at is the diagnosis. Record it: the result
        // reaches the user as a transient message that cannot be read later.
        match outcome {
            Ok(Ok((country_code, egress_ip))) => {
                tracing::info!(
                    node = %host,
                    port = server_port,
                    country_code = %country_code,
                    egress_ip = %egress_ip,
                    latency_ms = elapsed,
                    "node probe completed"
                );
                NodeProbeResult {
                    success: 1,
                    country_code: CString::new(country_code).unwrap().into_raw(),
                    egress_ip: CString::new(egress_ip).unwrap().into_raw(),
                    latency_ms: elapsed,
                    error: ptr::null_mut(),
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    node = %host,
                    port = server_port,
                    stage = %error.stage,
                    detail = %error.detail,
                    latency_ms = elapsed,
                    "node probe failed"
                );
                failure(error.user_message(), elapsed)
            }
            Err(_) => {
                tracing::warn!(
                    node = %host,
                    port = server_port,
                    stage = %ProbeStage::Response,
                    latency_ms = elapsed,
                    "node probe timed out before an answer returned"
                );
                failure("timed out waiting for an answer through the node", elapsed)
            }
        }
    })
}

/// Returns `(country_code, egress_ip)`, or the stage the probe stopped at.
async fn probe(host: &str, port: u16, force_codec: bool) -> Result<(String, String), ProbeError> {
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
        .map_err(|e| ProbeError::new(ProbeStage::Connect, error_report(&e)))?;

    stream
        .write_all(ECHO_REQUEST.as_bytes())
        .await
        .map_err(|e| ProbeError::new(ProbeStage::Request, error_report(&e)))?;

    let mut response = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|e| ProbeError::new(ProbeStage::Response, error_report(&e)))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_ECHO_RESPONSE {
            return Err(ProbeError::new(
                ProbeStage::Response,
                "the node returned more than an echo answer can be",
            ));
        }
    }

    if response.is_empty() {
        return Err(ProbeError::new(
            ProbeStage::Response,
            "the node closed the tunnel without sending anything",
        ));
    }

    parse_echo(&response)
}

fn parse_echo(response: &[u8]) -> Result<(String, String), ProbeError> {
    let text = String::from_utf8_lossy(response);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| ProbeError::new(ProbeStage::Decode, "no HTTP header ended the response"))?;

    let mut lines = body.lines().map(str::trim).filter(|line| !line.is_empty());
    let status = lines.next().unwrap_or_default();
    if status != "success" {
        return Err(ProbeError::new(
            ProbeStage::Decode,
            format!("the echo service rejected the request: {status}"),
        ));
    }

    let country_code = lines.next().unwrap_or_default().to_uppercase();
    let egress_ip = lines.next().unwrap_or_default().to_string();
    if country_code.len() != 2 || egress_ip.is_empty() {
        return Err(ProbeError::new(
            ProbeStage::Decode,
            "the echo service answered without a country and address",
        ));
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
    use super::{ProbeError, ProbeStage, parse_echo};

    fn expect_error(response: &[u8]) -> ProbeError {
        parse_echo(response).expect_err("this response must not parse")
    }

    #[test]
    fn reads_status_country_and_address() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsuccess\nJP\n203.0.113.7\n";
        let (country, ip) = parse_echo(response).expect("a successful echo parses");
        assert_eq!(country, "JP");
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn rejects_a_failed_lookup() {
        let error = expect_error(b"HTTP/1.1 200 OK\r\n\r\nfail\nprivate range\n");
        assert_eq!(error.stage, ProbeStage::Decode);
    }

    #[test]
    fn rejects_a_truncated_body() {
        let error = expect_error(b"HTTP/1.1 200 OK\r\n\r\nsuccess\nJP\n");
        assert_eq!(error.stage, ProbeStage::Decode);
    }

    #[test]
    fn rejects_a_response_without_headers() {
        let error = expect_error(b"success\nJP\n203.0.113.7\n");
        assert_eq!(error.stage, ProbeStage::Decode);
    }

    #[test]
    fn a_failure_names_its_stage_to_the_caller() {
        // The stage is the diagnosis, so it has to survive into the message the
        // user sees, not only into the log.
        let error = ProbeError::new(ProbeStage::Connect, "connection refused");
        assert_eq!(error.user_message(), "connect: connection refused");
    }
}
