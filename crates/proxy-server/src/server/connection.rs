//! Connection handling for proxy server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_core::codec::{
    AsyncDecryptCodec, AsyncEncryptCodec, AsyncNormalCodec, AsyncReader, AsyncWriter,
};
use proxy_core::control::{ControlCodec, is_control_target};
use proxy_core::metrics::{ConnectionRecord, current_time_ms};
use proxy_core::util::{display_report, error_report};
use proxy_core::{
    Aes256GcmCryption, Aes256GcmDecryptor, Aes256GcmEncryptor, DataSize, MyAsyncCodecReader,
    MyAsyncReadExt, MyAsyncWriteExt, ProxyHeader, get_data_size, set_data_size,
};
use snafu::ResultExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::{Instrument, field};

use super::control::handle_control_session;
use super::{
    ControlSnafu, IoSnafu, MAX_HEADER_SIZE, ProxySnafu, ReadHeaderSnafu, Result, ServerContext,
    ServerError,
};

#[derive(Debug, Default, Clone, Copy)]
struct TransferStats {
    bytes_up: u64,
    bytes_down: u64,
    latency_ms: Option<u64>,
}

#[derive(Debug)]
struct CopyOutcome {
    bytes: DataSize,
    error: Option<proxy_core::ProxyError>,
}

async fn copy_with_metrics<R, W>(
    mut reader: R,
    mut writer: W,
    mut first_byte_tx: Option<oneshot::Sender<Duration>>,
    start: Instant,
) -> CopyOutcome
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
            Err(err) => {
                let _ = writer.shutdown().await;
                return CopyOutcome {
                    bytes: total,
                    error: Some(err),
                };
            }
        }
    }
    CopyOutcome {
        bytes: total,
        error: None,
    }
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
    let (client_to_server, server_to_client) = tokio::join!(client_to_server, server_to_client);
    let first_byte_latency = rx.await.ok().map(|v| v.as_millis() as u64);
    let bytes_up = client_to_server.bytes;
    let bytes_down = server_to_client.bytes;
    let error = client_to_server.error.or(server_to_client.error);
    match error {
        Some(err) => Err(ServerError::Proxy { source: err }),
        None => Ok(TransferStats {
            bytes_up: bytes_up as u64,
            bytes_down: bytes_down as u64,
            latency_ms: first_byte_latency,
        }),
    }
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
    let (client_to_server, server_to_client) = tokio::join!(client_to_server, server_to_client);
    let first_byte_latency = rx.await.ok().map(|v| v.as_millis() as u64);
    let bytes_up = client_to_server.bytes;
    let bytes_down = server_to_client.bytes;
    let error = client_to_server.error.or(server_to_client.error);
    match error {
        Some(err) => Err(ServerError::Proxy { source: err }),
        None => Ok(TransferStats {
            bytes_up: bytes_up as u64,
            bytes_down: bytes_down as u64,
            latency_ms: first_byte_latency,
        }),
    }
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
        let result = handle_connect_inner(conn, peer_addr, ctx.clone(), trace_id).await;
        ctx.metrics.dec_active();
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

    let (r, w) = conn.into_split();
    let (mut client_reader, client_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let msg_len = get_data_size(&mut client_reader)
        .await
        .context(ReadHeaderSnafu)?;
    if msg_len > MAX_HEADER_SIZE {
        return Err(ServerError::HeaderSize { size: msg_len });
    }

    let mut header_buf = vec![0u8; msg_len as usize];
    client_reader
        .read_exact(&mut header_buf)
        .await
        .context(IoSnafu {
            detail: "Read Header(addr,tag)",
        })?;

    // Attempt to decode header for control handling.
    let header = match Aes256GcmCryption::try_new_with_default_key() {
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
    };

    if let Some(header) = header.as_ref() {
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
            let codec = ControlCodec::new(client_reader, client_writer, session_key)
                .context(ControlSnafu)?;
            return handle_control_session(codec, ctx).await;
        }
    }

    // Relay selection after control handling.
    let relay_target = ctx.relay.select();

    if let Some(relay_server) = relay_target {
        tracing::Span::current().record("mode", "relay");
        tracing::Span::current().record("dest", field::display(&relay_server));
        let relay_stream = TcpStream::connect(&relay_server).await.context(IoSnafu {
            detail: format!("Connect to relay_server:{}", relay_server),
        })?;
        ctx.relay.on_connect(&relay_server);
        let (r, w) = relay_stream.into_split();
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
        let result =
            proxy_with_metrics_normal(client_reader, server_reader, client_writer, server_writer)
                .await;
        ctx.relay.on_disconnect(&relay_server);
        record_connection(
            &ctx,
            &peer_ip,
            &format!("relay:{}", relay_server),
            0,
            started_at_ms,
            trace_id,
            &result,
        );
        return result.map(|_| ());
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
    let dest_stream = TcpStream::connect((header.host.as_str(), header.port))
        .await
        .context(IoSnafu {
            detail: format!("Connect to `dest_server({})`", header),
        })?;
    let (r, w) = dest_stream.into_split();
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
