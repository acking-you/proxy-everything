//! Egress verification for a single node.
//!
//! The node catalogue reports where a server is registered, which is not
//! necessarily where its traffic leaves from: a node can be fronted, relayed, or
//! simply mislabelled. The only way to know is to ask an echo service through
//! the node and see which address answers.

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::time::{Duration, Instant};

use proxy_core::codec::{
    AsyncDecryptCodec, AsyncNormalCodec, AsyncReader, AsyncReaderWriterRef, AsyncWriter,
};
use proxy_core::diagnostics::{self, ConnectionTrace};
use proxy_core::protocol::FrameWriter;
use proxy_core::secure_transport::{ProxyStream, WireProtocol};
use proxy_core::session::NativeSession;
use proxy_core::util::error_report;
use proxy_core::{Aes256GcmDecryptor, MyAsyncCodecReader, MyAsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};

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
/// Stages describe completed local I/O, not remote acceptance. Writing a proxy
/// header succeeds before the server validates it, and a TCP reset alone cannot
/// identify whether the server or an intervening filter rejected the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeStage {
    /// Opening the tunnel to the node.
    Connect,
    /// Sending the echo request after writing the proxy header.
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
    os_error: Option<i32>,
    is_connection_reset: bool,
}

impl ProbeError {
    fn new(stage: ProbeStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
            os_error: None,
            is_connection_reset: false,
        }
    }

    fn from_error(stage: ProbeStage, error: &(dyn std::error::Error + 'static)) -> Self {
        let mut source = Some(error);
        let mut os_error = None;
        let mut is_connection_reset = false;
        while let Some(error) = source {
            if let Some(error) = error.downcast_ref::<std::io::Error>() {
                is_connection_reset |= error.kind() == std::io::ErrorKind::ConnectionReset;
                if let Some(code) = error.raw_os_error() {
                    os_error = Some(code);
                    break;
                }
            }
            source = error.source();
        }
        Self {
            stage,
            detail: error_report(error),
            os_error,
            is_connection_reset,
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
/// `force_codec` is retained for ABI compatibility. Native TCP connections now
/// always use session encryption, including probes with this flag set to zero.
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
    let protocol = match WireProtocol::configured() {
        Ok(protocol) => protocol,
        Err(error) => return failure(error.to_string(), 0),
    };
    unsafe { probe_node_inner(server_host, server_port, force_codec, timeout_ms, protocol) }
}

/// Probe a specific wire version without changing the active client's protocol.
///
/// # Safety
/// `server_host` must be a valid C string; free the result with the matching free function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_probe_node_v3(
    server_host: *const c_char,
    server_port: u16,
    force_codec: c_int,
    timeout_ms: u32,
    wire_protocol: c_int,
) -> NodeProbeResult {
    let protocol = match WireProtocol::from_version(wire_protocol) {
        Ok(protocol) => protocol,
        Err(_) => return failure("Invalid wire protocol", 0),
    };
    unsafe { probe_node_inner(server_host, server_port, force_codec, timeout_ms, protocol) }
}

unsafe fn probe_node_inner(
    server_host: *const c_char,
    server_port: u16,
    _force_codec: c_int,
    timeout_ms: u32,
    protocol: WireProtocol,
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
        let diagnostic = ConnectionTrace::default();
        let outcome = tokio::time::timeout(
            timeout,
            diagnostic.scope(probe(&host, server_port, protocol)),
        )
        .await;
        let elapsed = start.elapsed().as_millis() as u64;

        // A probe traverses whatever routing and capture policy is active, so
        // the stage it stopped at is the diagnosis. Record it: the result
        // reaches the user as a transient message that cannot be read later.
        match outcome {
            Ok(Ok((country_code, egress_ip))) => {
                tracing::info!(
                    connection_id = diagnostic.id(),
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
                    connection_id = diagnostic.id(),
                    node = %host,
                    port = server_port,
                    stage = %error.stage,
                    detail = %error.detail,
                    os_error = error.os_error,
                    connection_phase = diagnostic.phase(),
                    reset_origin = if error.is_connection_reset { Some("unattributed; requires packet/event correlation") } else { None },
                    latency_ms = elapsed,
                    "node probe failed"
                );
                failure(error.user_message(), elapsed)
            }
            Err(_) => {
                tracing::warn!(
                    connection_id = diagnostic.id(),
                    node = %host,
                    port = server_port,
                    connection_phase = diagnostic.phase(),
                    latency_ms = elapsed,
                    "node probe timed out before an answer returned"
                );
                failure("timed out waiting for an answer through the node", elapsed)
            }
        }
    })
}

struct ObservedProbeSocket {
    stream: ProxyStream,
    outcome: &'static str,
}

impl Drop for ObservedProbeSocket {
    fn drop(&mut self) {
        // TaskLocalFuture drops its inner future within the diagnostic scope,
        // including when the outer timeout cancels the response read. Observe
        // the live socket before its field is dropped, without extending I/O.
        self.stream.record_diagnostics(self.outcome);
    }
}

/// Returns `(country_code, egress_ip)`, or the stage the probe stopped at.
async fn probe(
    host: &str,
    port: u16,
    protocol: WireProtocol,
) -> Result<(String, String), ProbeError> {
    let (stream, msg_key) = NativeSession::connect_with_protocol(
        ECHO_HOST,
        ECHO_PORT,
        host,
        port,
        proxy_core::ProxyTransport::Tcp,
        protocol,
    )
    .await
    .map_err(|e| ProbeError::from_error(ProbeStage::Connect, &e))?
    .into_parts();
    let mut observed = ObservedProbeSocket {
        stream,
        outcome: "probe_cancelled",
    };
    tracing::info!(
        node = host,
        port,
        local_addr = ?observed.stream.local_addr().ok(),
        peer_addr = ?observed.stream.peer_addr().ok(),
        wire_protocol = ?protocol,
        "node probe socket connected; proxy header written, awaiting response"
    );
    let result = exchange_probe(&mut observed.stream, msg_key.as_deref()).await;
    observed.outcome = if result.is_ok() {
        "probe_succeeded"
    } else {
        "probe_failed"
    };
    result
}

async fn exchange_probe<S: AsyncRead + AsyncWrite + Send + Unpin>(
    mut stream: S,
    msg_key: Option<&str>,
) -> Result<(String, String), ProbeError> {
    diagnostics::phase("request_prepare");
    if let Some(key) = msg_key {
        let mut writer = FrameWriter::new(
            AsyncWriter::new(&mut stream),
            Some(key),
            MAX_ECHO_RESPONSE + 16,
        )
        .map_err(|e| ProbeError::from_error(ProbeStage::Request, &e))?;
        writer
            .prepare()
            .map_err(|e| ProbeError::from_error(ProbeStage::Request, &e))?
            .extend_from_slice(ECHO_REQUEST.as_bytes());
        diagnostics::phase("request_write");
        writer
            .send()
            .await
            .map_err(|e| ProbeError::from_error(ProbeStage::Request, &e))?;
        let decryptor = Aes256GcmDecryptor::try_new(key.as_bytes())
            .map_err(|e| ProbeError::new(ProbeStage::Response, e.to_string()))?;
        read_probe_response(AsyncDecryptCodec::with_limit(
            AsyncReader::new(stream),
            decryptor,
            MAX_ECHO_RESPONSE + 16,
        ))
        .await
    } else {
        // v3 already protects these bytes; do not double-encrypt the payload.
        diagnostics::phase("request_write");
        AsyncReaderWriterRef::new(&mut stream)
            .write_all(ECHO_REQUEST.as_bytes())
            .await
            .map_err(|e| ProbeError::from_error(ProbeStage::Request, &e))?;
        read_probe_response(AsyncNormalCodec::new(AsyncReader::new(stream))).await
    }
}

async fn read_probe_response<R: MyAsyncCodecReader + Send + Unpin>(
    mut reader: R,
) -> Result<(String, String), ProbeError> {
    diagnostics::phase("response_wait");
    let mut response = Vec::with_capacity(512);
    loop {
        let first = response.is_empty();
        let received = reader
            .codec_and_write(&mut AsyncWriter::new(&mut response))
            .await
            .map_err(|e| ProbeError::from_error(ProbeStage::Response, &e))?;
        if received == 0 {
            break;
        }
        if first && !response.is_empty() {
            diagnostics::phase("response_body");
        }
        if response.len() > MAX_ECHO_RESPONSE {
            return Err(ProbeError::new(
                ProbeStage::Response,
                "the node returned more than an echo answer can be",
            ));
        }
        // Stop at a complete answer instead of waiting for the peer to close.
        // `Connection: close` makes the close arrive promptly over a direct
        // socket, but through a tunnel the FIN has to traverse the node, the
        // relay and the user-space stack, and waiting for it turned an answer
        // that had already arrived into a timeout.
        //
        // The trailing newline is what makes the last line safe to read: without
        // it a split segment could present a truncated address as a whole one.
        if response.ends_with(b"\n")
            && let Ok(answer) = parse_echo(&response)
        {
            return Ok(answer);
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
    #[test]
    fn reset_classification_does_not_depend_on_a_windows_numeric_code() {
        let error = super::ProbeError::from_error(
            super::ProbeStage::Response,
            &std::io::Error::new(std::io::ErrorKind::ConnectionReset, "fixture reset"),
        );
        assert!(error.is_connection_reset);
        assert_eq!(error.os_error, None);
        assert!(
            !super::ProbeError::new(super::ProbeStage::Decode, "invalid reply").is_connection_reset
        );
    }

    #[tokio::test]
    async fn default_probe_negotiates_legacy_session_encryption_with_historical_peer() {
        use proxy_core::protocol::get_check_sum;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let checksum = stream.read_u32().await.unwrap();
            let len = stream.read_u32().await.unwrap();
            assert_eq!(checksum, get_check_sum(len));
            assert!(len < 4096);
            let mut header = vec![0; len as usize];
            stream.read_exact(&mut header).await.unwrap();
            let mut cipher = proxy_core::crypto::configured_cryption().unwrap();
            let header: serde_json::Value =
                serde_json::from_slice(cipher.decrypt_with_tag(&mut header).unwrap()).unwrap();
            assert_eq!(header["host"], super::ECHO_HOST);
            assert_eq!(header["port"], super::ECHO_PORT);
            assert_eq!(header.as_object().unwrap().len(), 3);
            let key = header["key"]
                .as_str()
                .expect("probes follow the TCP encryption policy");
            let mut cipher = proxy_core::Aes256GcmCryption::try_new(key.as_bytes()).unwrap();
            let checksum = stream.read_u32().await.unwrap();
            let len = stream.read_u32().await.unwrap();
            assert_eq!(checksum, get_check_sum(len));
            assert!(len < 4096);
            let mut request = vec![0; len as usize];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(
                cipher.decrypt_with_tag(&mut request).unwrap(),
                super::ECHO_REQUEST.as_bytes()
            );
            let mut response = b"HTTP/1.1 200 OK\r\n\r\nsuccess\nSG\n203.0.113.1\n".to_vec();
            let tag = cipher.encrypt(&mut response).unwrap();
            response.extend_from_slice(tag.as_ref());
            let len = response.len() as u32;
            stream.write_u32(get_check_sum(len)).await.unwrap();
            stream.write_u32(len).await.unwrap();
            for chunk in response.chunks(3) {
                stream.write_all(chunk).await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let ((), answer) = tokio::join!(
                peer,
                super::probe("127.0.0.1", port, super::WireProtocol::Legacy)
            );
            assert_eq!(answer.unwrap(), ("SG".into(), "203.0.113.1".into()));
        })
        .await
        .unwrap();
    }

    #[test]
    fn socket_reset_keeps_its_native_code_without_attributing_its_origin() {
        let error = super::ProbeError::from_error(
            super::ProbeStage::Response,
            &std::io::Error::from_raw_os_error(10054),
        );
        assert_eq!(error.os_error, Some(10054));
        assert_eq!(error.stage, super::ProbeStage::Response);
        assert!(error.user_message().contains("10054"));
    }

    #[test]
    fn wrapped_transport_reset_retains_the_error_chain_and_native_code() {
        let cause = proxy_core::transport::TransportError::Io {
            uri: Some("127.0.0.1:1081".into()),
            detail: "fixture header write",
            source: std::io::Error::from_raw_os_error(10054),
        };
        let error = super::ProbeError::from_error(super::ProbeStage::Connect, &cause);
        assert_eq!(error.os_error, Some(10054));
        assert!(error.user_message().contains("fixture header write"));
        assert!(error.user_message().contains("127.0.0.1:1081"));
        assert!(error.user_message().contains("10054"));
        #[cfg(windows)]
        assert!(error.is_connection_reset);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_exchange_retains_phase_and_live_socket_observations() {
        use std::sync::{Arc, Mutex};

        use tokio::net::{TcpListener, TcpStream};

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let capture = Capture(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || capture.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let client = client.unwrap();
        let (mut server, _) = server.unwrap();
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let trace = proxy_core::diagnostics::ConnectionTrace::default();
        let consume = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut request = vec![0; super::ECHO_REQUEST.len()];
            server.read_exact(&mut request).await.unwrap();
            std::future::pending::<()>().await;
        });
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(25),
            trace.scope(async move {
                let mut observed = super::ObservedProbeSocket {
                    stream: client.into(),
                    outcome: "probe_cancelled",
                };
                super::exchange_probe(&mut observed.stream, None).await
            }),
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(trace.phase(), "response_wait");
        consume.abort();
        let _ = consume.await;
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let endpoints = output
            .lines()
            .find(|line| line.contains("socket endpoints") && line.contains("probe_cancelled"))
            .expect("timeout must log the live socket while its trace is installed");
        assert!(endpoints.contains(&format!("connection_id={}", trace.id())));
        assert!(endpoints.contains(&format!("local_addr=Some({local})")));
        assert!(endpoints.contains(&format!("peer_addr=Some({peer})")));
    }

    #[tokio::test]
    async fn secure_node_probe_flushes_request_under_backpressure() {
        use proxy_core::secure_transport::{accept_v3, connect_v3};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let key = b"01234567890123456789012345678901";
        // One byte of capacity forces the request to remain buffered in v3.
        let (client, mut server) = tokio::io::duplex(1);
        let exchange = async {
            let serve = async {
                let mut preface = [0; 8];
                server.read_exact(&mut preface).await.unwrap();
                let (mut server, control) = accept_v3(server, key, preface).await.unwrap();
                assert!(!control);
                let mut request = vec![0; super::ECHO_REQUEST.len()];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, super::ECHO_REQUEST.as_bytes());
                server
                    .write_all(b"HTTP/1.1 200 OK\r\n\r\nsuccess\nSG\n203.0.113.1\n")
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            };
            let probe = super::exchange_probe(connect_v3(client, key, false).unwrap(), None);
            let ((), answer) = tokio::join!(serve, probe);
            assert_eq!(answer.unwrap(), ("SG".into(), "203.0.113.1".into()));
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), exchange)
            .await
            .expect("the buffered request must reach the peer before waiting for a reply");
    }

    #[tokio::test]
    async fn encrypted_node_probe_uses_the_negotiated_codec() {
        use proxy_core::codec::AsyncReaderWriterRef;
        use proxy_core::{MyAsyncWriteExt, get_data_size, set_data_size};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        let key = "01234567890123456789012345678901";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = get_data_size(&mut AsyncReaderWriterRef::new(&mut stream))
                .await
                .unwrap();
            let mut request = vec![0; size as usize];
            stream.read_exact(&mut request).await.unwrap();
            let mut crypto = proxy_core::Aes256GcmCryption::try_new(key.as_bytes()).unwrap();
            assert_eq!(
                crypto.decrypt_with_tag(&mut request).unwrap(),
                super::ECHO_REQUEST.as_bytes()
            );
            for payload in [
                b"HTTP/1.1 200 OK\r\n\r\nsuc".as_slice(),
                b"cess\nSG\n203.0.113.1\n",
            ] {
                let mut response = payload.to_vec();
                let tag = crypto.encrypt(&mut response).unwrap();
                response.extend_from_slice(tag.as_ref());
                let mut writer = AsyncReaderWriterRef::new(&mut stream);
                set_data_size(&mut writer, response.len() as u32)
                    .await
                    .unwrap();
                MyAsyncWriteExt::write_all(&mut writer, &response)
                    .await
                    .unwrap();
            }
            stream.shutdown().await.unwrap();
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            super::exchange_probe(stream, Some(key)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(answer, ("SG".into(), "203.0.113.1".into()));
        server.await.unwrap();
    }

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
    fn a_partial_body_is_not_mistaken_for_an_answer() {
        // The read loop parses as bytes arrive so it never waits for a close
        // that a tunnel may not deliver. A body split mid-address must not
        // satisfy it, or the probe would report a truncated egress address.
        assert!(parse_echo(b"HTTP/1.1 200 OK\r\n\r\nsuccess\n").is_err());
        let (_, ip) = parse_echo(b"HTTP/1.1 200 OK\r\n\r\nsuccess\nJP\n203.0.113.7\n")
            .expect("a whole body parses");
        assert_eq!(ip, "203.0.113.7");
    }

    #[test]
    fn a_failure_names_its_stage_to_the_caller() {
        // The stage is the diagnosis, so it has to survive into the message the
        // user sees, not only into the log.
        let error = ProbeError::new(ProbeStage::Connect, "connection refused");
        assert_eq!(error.user_message(), "connect: connection refused");
    }
}
