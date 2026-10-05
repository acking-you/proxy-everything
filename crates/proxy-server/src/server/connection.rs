//! Connection handling for proxy server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_core::codec::{
    AsyncDecryptCodec, AsyncEncryptCodec, AsyncNormalCodec, AsyncReader, AsyncWriter,
};
use proxy_core::control::{ControlCodec, is_control_target};
use proxy_core::metrics::{ConnectionRecord, MetricsStore, current_time_ms};
use proxy_core::relay::RelayRoute;
use proxy_core::secure_transport::{MAGIC, ProxyStream, accept_v3};
use proxy_core::transport::get_tcp_external_proxy_stream;
use proxy_core::util::{display_report, error_report};
use proxy_core::{
    Aes256GcmCryption, Aes256GcmDecryptor, Aes256GcmEncryptor, DataSize, MyAsyncCodecReader,
    MyAsyncReadExt, MyAsyncWriteExt, ProxyHeader, ProxyTransport, get_data_size, set_data_size,
};
use smallvec::{SmallVec, smallvec};
use snafu::ResultExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::{Instrument, field};

use super::control::handle_control_session;
use super::udp::proxy_udp_association;
use super::{
    ControlSnafu, IoSnafu, MAX_HEADER_SIZE, ProxySnafu, ReadHeaderSnafu, Result, ServerContext,
    ServerError, TransportSnafu,
};

static HEADER_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(512);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

struct ActiveConnection<'a>(&'a MetricsStore);
impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.0.dec_active();
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct TransferStats {
    pub(super) bytes_up: u64,
    pub(super) bytes_down: u64,
    pub(super) latency_ms: Option<u64>,
}

async fn copy_with_metrics<R, W>(
    mut reader: R,
    mut writer: W,
    mut first_byte_tx: Option<oneshot::Sender<Duration>>,
    start: Instant,
) -> proxy_core::Result<DataSize>
where
    R: MyAsyncCodecReader + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
{
    let mut total: DataSize = 0;
    loop {
        match reader.codec_and_write(&mut writer).await {
            Ok(n) => {
                if n == 0 {
                    let _ = writer.shutdown().await;
                    break;
                }
                if let Some(tx) = first_byte_tx.take() {
                    let _ = tx.send(start.elapsed());
                }
                total = total.saturating_add(n);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(total)
}

async fn proxy_with_metrics_normal<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<TransferStats> {
    let (tx, rx) = oneshot::channel();
    let start = Instant::now();
    let client_to_server = copy_with_metrics(
        AsyncNormalCodec::new(client_reader),
        server_writer,
        None,
        start,
    );
    let server_to_client = copy_with_metrics(
        AsyncNormalCodec::new(server_reader),
        client_writer,
        Some(tx),
        start,
    );
    // Authentication/I/O errors cancel the other direction immediately. A
    // normal EOF still half-closes its writer and lets the peer drain.
    let (bytes_up, bytes_down) =
        tokio::try_join!(client_to_server, server_to_client).context(ProxySnafu)?;
    Ok(TransferStats {
        bytes_up: bytes_up as u64,
        bytes_down: bytes_down as u64,
        latency_ms: rx.await.ok().map(|v| v.as_millis() as u64),
    })
}

async fn proxy_with_metrics_cryptor<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    key: &str,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<TransferStats> {
    let client_codec = AsyncDecryptCodec::new(
        client_reader,
        Aes256GcmDecryptor::try_new(key.as_bytes()).map_err(|e| ServerError::Decryption {
            detail: e.to_string(),
        })?,
    );
    let server_codec = AsyncEncryptCodec::new(
        server_reader,
        Aes256GcmEncryptor::try_new(key.as_bytes()).map_err(|e| ServerError::Decryption {
            detail: e.to_string(),
        })?,
    );

    let (tx, rx) = oneshot::channel();
    let start = Instant::now();
    let client_to_server = copy_with_metrics(client_codec, server_writer, None, start);
    let server_to_client = copy_with_metrics(server_codec, client_writer, Some(tx), start);
    // Authentication/I/O errors cancel the other direction immediately. A
    // normal EOF still half-closes its writer and lets the peer drain.
    let (bytes_up, bytes_down) =
        tokio::try_join!(client_to_server, server_to_client).context(ProxySnafu)?;
    Ok(TransferStats {
        bytes_up: bytes_up as u64,
        bytes_down: bytes_down as u64,
        latency_ms: rx.await.ok().map(|v| v.as_millis() as u64),
    })
}

/// Handle a new TCP connection with a per-connection tracing span.
///
/// This attaches a `trace_id` to all logs emitted during the connection's
/// lifecycle to simplify troubleshooting.
pub(super) async fn handle_connect(
    conn: TcpStream,
    peer_addr: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    let trace_id = ctx.allocate_trace_id();
    let span = tracing::info_span!(
        "proxy_connection",
        trace_id,
        peer = %peer_addr,
        dest = field::Empty,
        mode = field::Empty
    );
    async move {
        tracing::info!("connection accepted");
        ctx.metrics.inc_active();
        let _active = ActiveConnection(&ctx.metrics);
        let result = handle_connect_inner(conn, peer_addr, ctx.clone(), trace_id).await;
        if let Err(err) = &result {
            tracing::error!("connection error: {}", error_report(err));
        }
        result
    }
    .instrument(span)
    .await
}

async fn handle_connect_inner(
    conn: TcpStream,
    peer_addr: SocketAddr,
    ctx: Arc<ServerContext>,
    trace_id: u64,
) -> Result<()> {
    let started_at_ms = current_time_ms();
    let peer_ip = peer_addr.ip().to_string();
    let mut dest_host = "unknown".to_string();
    let mut dest_port: u16 = 0;

    let _header_permit = HEADER_SLOTS.try_acquire().map_err(|_| ServerError::Io {
        detail: "too many pending proxy headers".into(),
        source: std::io::Error::from(std::io::ErrorKind::WouldBlock),
    })?;
    let deadline = tokio::time::Instant::now() + HEADER_TIMEOUT;
    let relay_target = ctx.relay.select();
    conn.set_nodelay(true).context(IoSnafu {
        detail: "set client TCP_NODELAY",
    })?;
    let mut conn = conn;
    let mut magic = [0u8; 8];
    tokio::time::timeout_at(
        deadline,
        tokio::io::AsyncReadExt::read_exact(&mut conn, &mut magic),
    )
    .await
    .map_err(|_| ServerError::Io {
        detail: "protocol preface timeout".into(),
        source: std::io::ErrorKind::TimedOut.into(),
    })?
    .context(IoSnafu {
        detail: "read protocol preface",
    })?;
    // The second word in a valid legacy header is at most MAX_HEADER_SIZE.
    // V3 reserves a larger value, even if its magic collides with a checksum.
    let legacy_length = u32::from_be_bytes(magic[4..8].try_into().unwrap_or_default());
    let secure = magic[..4] == MAGIC && legacy_length > MAX_HEADER_SIZE;
    let mut control_hello = false;
    let conn = if secure {
        if magic[4] != 3 || magic[5] > 1 || magic[6..8] != [0, 0] {
            return Err(ServerError::Decryption {
                detail: "invalid v3 version or flags".into(),
            });
        }
        if magic[5] == 0
            && let Some(target) = relay_target.as_ref()
            && let RelayRoute::ProxyServer { addr } = &target.route
        {
            let mut upstream = tokio::time::timeout_at(deadline, TcpStream::connect(addr))
                .await
                .map_err(|_| ServerError::Io {
                    detail: "v3 relay connect timeout".into(),
                    source: std::io::ErrorKind::TimedOut.into(),
                })?
                .context(IoSnafu {
                    detail: "connect v3 relay",
                })?;
            upstream.set_nodelay(true).context(IoSnafu {
                detail: "set relay TCP_NODELAY",
            })?;
            tokio::io::AsyncWriteExt::write_all(&mut upstream, &magic)
                .await
                .context(IoSnafu {
                    detail: "relay v3 preface",
                })?;
            drop(_header_permit);
            ctx.relay.on_connect(&target.id);
            let (cr, cw) = ProxyStream::from(conn).into_split();
            let (sr, sw) = ProxyStream::from(upstream).into_split();
            let result = proxy_with_metrics_normal(
                AsyncReader::new(cr),
                AsyncReader::new(sr),
                AsyncWriter::new(cw),
                AsyncWriter::new(sw),
            )
            .await;
            ctx.relay.on_disconnect(&target.id);
            record_connection(
                &ctx,
                &peer_ip,
                &format!("relay:{}", target.addr),
                0,
                started_at_ms,
                trace_id,
                &result,
            );
            return result.map(|_| ());
        }
        let key = proxy_core::config::runtime::with_secret_key(|key, _| <[u8; 32]>::try_from(key))
            .map_err(|error| ServerError::Decryption {
                detail: error.to_string(),
            })?;
        let (stream, control) = tokio::time::timeout_at(deadline, accept_v3(conn, &key, magic))
            .await
            .map_err(|_| ServerError::Io {
                detail: "v3 handshake timeout".into(),
                source: std::io::ErrorKind::TimedOut.into(),
            })?
            .context(IoSnafu {
                detail: "accept v3 handshake",
            })?;
        control_hello = control;
        ProxyStream::Secure(Box::new(stream))
    } else {
        if ctx.require_secure_transport {
            return Err(ServerError::Decryption {
                detail: "legacy transport disabled; v3 required".into(),
            });
        }
        tracing::debug!(wire_protocol = "legacy", "accepted legacy proxy transport");
        ProxyStream::legacy_with_prefix(conn, magic.to_vec())
    };
    let (r, w) = conn.into_split();
    let (mut client_reader, client_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let (msg_len, mut header_buf) = tokio::time::timeout_at(deadline, async {
        let msg_len = get_data_size(&mut client_reader)
            .await
            .context(ReadHeaderSnafu)?;
        if msg_len > MAX_HEADER_SIZE {
            return Err(ServerError::HeaderSize { size: msg_len });
        }

        const STACK_SIZE: usize = MAX_HEADER_SIZE as usize / 2;
        let mut header_buf: SmallVec<u8, STACK_SIZE> = smallvec![0u8; msg_len as usize];
        client_reader
            .read_exact(&mut header_buf)
            .await
            .context(IoSnafu {
                detail: "Read Header(addr,tag)",
            })?;

        Ok::<_, ServerError>((msg_len, header_buf))
    })
    .await
    .map_err(|_| ServerError::Io {
        detail: "proxy header deadline exceeded".into(),
        source: std::io::Error::from(std::io::ErrorKind::TimedOut),
    })??;
    drop(_header_permit);

    // Get relay context before mutate
    let relay_context = relay_target.map(|v| (v, header_buf.clone()));

    // Attempt to decode header for control handling.
    let mut header = if secure {
        let header =
            serde_json::from_slice::<ProxyHeader>(&header_buf).context(super::SerdeJsonSnafu)?;
        if control_hello != is_control_target(&header.host, header.port) {
            return Err(ServerError::Decryption {
                detail: "v3 authenticated route mismatch".into(),
            });
        }
        Some(header)
    } else {
        match Aes256GcmCryption::try_new_with_default_key() {
            Ok(mut cryption) => match cryption.decrypt_with_tag(&mut header_buf) {
                Ok(payload) => match serde_json::from_slice::<ProxyHeader>(payload) {
                    Ok(header) => Some(header),
                    Err(err) => {
                        tracing::warn!("parse header failed: {}", error_report(&err));
                        None
                    }
                },
                Err(err) => {
                    tracing::warn!("decrypt header failed: {}", display_report(err));
                    None
                }
            },
            Err(err) => {
                tracing::warn!("init decryptor failed: {}", display_report(err));
                None
            }
        }
    };

    if let Some(header) = header.as_ref() {
        // `transport` is safe to log, but the optional session key is not. A
        // boolean still makes encrypted/plain session mismatches visible.
        tracing::debug!(
            destination_host = %header.host,
            destination_port = header.port,
            transport = ?header.transport,
            session_encrypted = header.key.is_some(),
            "decoded proxy connection header"
        );
        dest_host = header.host.clone();
        dest_port = header.port;
        if is_control_target(&header.host, header.port) {
            tracing::Span::current().record("mode", "control");
            tracing::Span::current().record("dest", field::display(&header.host));
            let session_key = header.key.as_ref().map(|k| k.as_ref());
            if ctx.require_control_encryption && session_key.is_none() {
                tracing::warn!("control connection rejected: encryption required");
                return Ok(());
            }
            if let Some(expected) = ctx.control_session_key.as_deref() {
                if session_key != Some(expected) {
                    tracing::warn!("control connection rejected: session key mismatch");
                    return Ok(());
                }
            } else if ctx.require_control_encryption {
                tracing::warn!("control connection rejected: server has no session key");
                return Ok(());
            }
            let codec = ControlCodec::new(
                client_reader,
                client_writer,
                if secure { None } else { session_key },
            )
            .context(ControlSnafu)?;
            return handle_control_session(codec, ctx).await;
        }
    }

    if secure && let Some(header) = header.as_mut() {
        header.key = None;
    }

    if let Some(header) = header.as_ref()
        && header.transport == ProxyTransport::UdpAssociate
    {
        tracing::info!(
            peer = %peer_addr,
            datagram_encryption = header.key.is_some(),
            relay_enabled = relay_context.is_some(),
            "received proxy UDP association request"
        );
        let external_relay = relay_context
            .as_ref()
            .and_then(|(target, _)| match &target.route {
                RelayRoute::ExternalProxy(proxy) => Some((target, proxy)),
                RelayRoute::ProxyServer { .. } => None,
            });

        if relay_context.is_none() || external_relay.is_some() {
            let (mode, destination, upstream_proxy) = match external_relay {
                Some((target, proxy)) => {
                    ctx.relay.on_connect(&target.id);
                    (
                        "udp-relay",
                        format!("udp:relay:{}", target.addr),
                        Some(proxy),
                    )
                }
                None => ("udp", "udp-associate".to_string(), None),
            };
            tracing::Span::current().record("mode", mode);
            tracing::Span::current().record("dest", field::display(&destination));
            let result = proxy_udp_association(
                client_reader,
                client_writer,
                header.key.as_deref(),
                upstream_proxy,
            )
            .await;
            if let Some((target, _)) = external_relay {
                ctx.relay.on_disconnect(&target.id);
            }
            record_connection(
                &ctx,
                &peer_ip,
                &destination,
                0,
                started_at_ms,
                trace_id,
                &result,
            );
            return result.map(|_| ());
        }
    }

    if let Some((relay_target, header_buf)) = relay_context {
        tracing::Span::current().record("mode", "relay");
        tracing::Span::current().record("dest", field::display(&relay_target.addr));

        match &relay_target.route {
            RelayRoute::ProxyServer { addr } => {
                let relay_stream =
                    tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(addr))
                        .await
                        .map_err(|_| ServerError::Io {
                            detail: "relay connection deadline exceeded".into(),
                            source: std::io::Error::from(std::io::ErrorKind::TimedOut),
                        })?
                        .context(IoSnafu {
                            detail: format!("Connect to relay_server:{addr}"),
                        })?;
                relay_stream.set_nodelay(true).context(IoSnafu {
                    detail: "set relay TCP_NODELAY",
                })?;
                ctx.relay.on_connect(&relay_target.id);
                let (r, w) = ProxyStream::from(relay_stream).into_split();
                let (server_reader, mut server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
                set_data_size(&mut server_writer, msg_len)
                    .await
                    .context(ProxySnafu)?;
                server_writer
                    .write_all(&header_buf)
                    .await
                    .context(IoSnafu {
                        detail: "Write To Relay Server Header(addr,tag)",
                    })?;
                let result = proxy_with_metrics_normal(
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await;
                ctx.relay.on_disconnect(&relay_target.id);
                record_connection(
                    &ctx,
                    &peer_ip,
                    &format!("relay:{}", relay_target.addr),
                    0,
                    started_at_ms,
                    trace_id,
                    &result,
                );
                return result.map(|_| ());
            }
            RelayRoute::ExternalProxy(proxy) => {
                let header = header.ok_or_else(|| ServerError::Decryption {
                    detail: "decrypt header failed".to_string(),
                })?;
                let server_stream = get_tcp_external_proxy_stream(
                    proxy,
                    header.host.as_str(),
                    header.port,
                    "connect to external relay proxy",
                )
                .await
                .context(TransportSnafu)?;
                ctx.relay.on_connect(&relay_target.id);
                let (r, w) = ProxyStream::from(server_stream).into_split();
                let (server_reader, server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
                let result = if let Some(key) = header.key.as_ref() {
                    proxy_with_metrics_cryptor(
                        key.as_ref(),
                        client_reader,
                        server_reader,
                        client_writer,
                        server_writer,
                    )
                    .await
                } else {
                    proxy_with_metrics_normal(
                        client_reader,
                        server_reader,
                        client_writer,
                        server_writer,
                    )
                    .await
                };
                ctx.relay.on_disconnect(&relay_target.id);
                record_connection(
                    &ctx,
                    &peer_ip,
                    &format!("relay:{}", relay_target.addr),
                    0,
                    started_at_ms,
                    trace_id,
                    &result,
                );
                return result.map(|_| ());
            }
        }
    }

    // Non-relay mode requires a valid header.
    let header = header.ok_or_else(|| ServerError::Decryption {
        detail: "decrypt header failed".to_string(),
    })?;
    tracing::Span::current().record("mode", "direct");
    tracing::Span::current().record(
        "dest",
        field::display(format!("{}:{}", header.host, header.port)),
    );
    let dest_stream = proxy_core::transport::connect_tcp_host(header.host.as_str(), header.port)
        .await
        .context(IoSnafu {
            detail: format!("Connect to `dest_server({})`", header),
        })?;
    let (r, w) = ProxyStream::from(dest_stream).into_split();
    let (server_reader, server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let result = if let Some(key) = header.key.as_ref() {
        proxy_with_metrics_cryptor(
            key.as_ref(),
            client_reader,
            server_reader,
            client_writer,
            server_writer,
        )
        .await
    } else {
        proxy_with_metrics_normal(client_reader, server_reader, client_writer, server_writer).await
    };

    record_connection(
        &ctx,
        &peer_ip,
        &dest_host,
        dest_port,
        started_at_ms,
        trace_id,
        &result,
    );
    result.map(|_| ())
}

fn record_connection(
    ctx: &ServerContext,
    peer_ip: &str,
    dest_host: &str,
    dest_port: u16,
    started_at_ms: i64,
    trace_id: u64,
    result: &Result<TransferStats>,
) {
    let (stats, error_msg) = match result {
        Ok(stats) => (*stats, None),
        Err(e) => {
            let report = error_report(e);
            tracing::error!(
                "connection to {}:{} from {} failed: {}",
                dest_host,
                dest_port,
                peer_ip,
                report
            );
            (TransferStats::default(), Some(report))
        }
    };
    let ended_at_ms = current_time_ms();
    let duration_ms = (ended_at_ms - started_at_ms).max(0);
    let record = ConnectionRecord {
        id: trace_id,
        client_ip: peer_ip.to_string(),
        dest_host: dest_host.to_string(),
        dest_port,
        bytes_up: stats.bytes_up,
        bytes_down: stats.bytes_down,
        latency_ms: stats.latency_ms,
        duration_ms,
        started_at_ms,
        ended_at_ms,
        error: error_msg,
    };
    ctx.metrics.record_connection(record);
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Reader(bool);
    impl MyAsyncReadExt for Reader {
        async fn read_u32(&mut self) -> std::io::Result<u32> {
            unreachable!()
        }

        async fn read_exact(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            unreachable!()
        }

        async fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                Err(std::io::ErrorKind::ConnectionReset.into())
            } else {
                std::future::pending().await
            }
        }
    }
    #[tokio::test]
    async fn forwarding_error_does_not_wait_for_a_silent_peer() {
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            proxy_with_metrics_normal(
                Reader(true),
                Reader(false),
                AsyncWriter::new(Vec::new()),
                AsyncWriter::new(Vec::new()),
            ),
        )
        .await
        .expect("peer direction must be cancelled");
        assert!(result.is_err());
    }
}
