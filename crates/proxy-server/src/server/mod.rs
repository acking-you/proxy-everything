//! Server-side proxy implementation.
//!
//! This module provides the server-side proxy functionality. The server receives
//! encrypted connections from clients, decrypts the proxy header, and forwards
//! traffic to the destination.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Server Architecture                              │
//! │                                                                         │
//! │  Client ──► [encrypted] ──► Server (1081) ──► Destination              │
//! │                                  │                                      │
//! │                                  ▼                                      │
//! │                         ┌─────────────────┐                            │
//! │                         │ Decrypt Header  │                            │
//! │                         │ (AES-256-GCM)   │                            │
//! │                         └─────────────────┘                            │
//! │                                  │                                      │
//! │                                  ▼                                      │
//! │                         ┌─────────────────┐                            │
//! │                         │ Parse ProxyHeader│                           │
//! │                         │ {host, port, key}│                           │
//! │                         └─────────────────┘                            │
//! │                                  │                                      │
//! │                    ┌─────────────┴─────────────┐                       │
//! │                    ▼                           ▼                        │
//! │            With Session Key            Without Key                     │
//! │            (encrypted stream)          (plain stream)                  │
//! │                    │                           │                        │
//! │                    └───────────┬───────────────┘                       │
//! │                                ▼                                        │
//! │                    ┌─────────────────────┐                             │
//! │                    │  Bidirectional      │                             │
//! │                    │  Forwarding         │                             │
//! │                    │  (with metrics)     │                             │
//! │                    └─────────────────────┘                             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Control Plane
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Control Plane Integration                           │
//! │                                                                         │
//! │  ProxyHeader{host:"__control__", port:0} triggers control mode:        │
//! │                                                                         │
//! │  ┌──────────┐    ┌──────────────┐    ┌─────────────────────────────┐   │
//! │  │  Client  │───►│ Control      │───►│ Operations:                 │   │
//! │  │  (TUI)   │◄───│ Session      │◄───│ - Ping/Pong                 │   │
//! │  └──────────┘    └──────────────┘    │ - ListNodes/SyncNodes       │   │
//! │                                      │ - GetRealtimeStats          │   │
//! │                                      │ - GetRecentConnections      │   │
//! │                                      │ - GetTimeBuckets            │   │
//! │                                      │ - GetTopN (hosts/ips)       │   │
//! │                                      │ - Relay config management   │   │
//! │                                      └─────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Transparent Proxy Chain
//!
//! When `TURELY_PROXY_SERVER` is configured or relay is enabled, the server
//! acts as a transparent relay, forwarding all traffic to another proxy server.

mod relay;

pub use relay::RelayManager;

use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use proxy_core::MyAsyncWriteExt;
use proxy_core::config::{
    CONTROL_ADMIN_TOKEN, CONTROL_REQUIRE_ENCRYPTION, CONTROL_SESSION_KEY, DEFAULT_KEY,
    NODE_ADVERTISE_ADDR, NODE_ID, TURELY_PROXY_SERVER,
};
use proxy_core::control::{
    ControlCodec, ControlOp, ControlRequest, ControlResponse, ControlResult, TopNEntry,
    is_control_target,
};
use proxy_core::metrics::{ConnectionRecord, MetricsStore, current_time_ms};
use proxy_core::nodes::{NodeInfo, NodeStore};
use tracing::{Instrument, field};

#[derive(Debug, Snafu)]
pub enum ServerError {
    #[snafu(display("Io Error occur: {detail}"))]
    Io {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Decryption Error occur!,detail:{detail}"))]
    Decryption { detail: String },
    #[snafu(display("SerdeJson Error occur!"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("Server read header fail:{source}"))]
    ReadHeader { source: proxy_core::ProxyError },
    #[snafu(display(
        "Exceeded the maximum supported header length({MAX_HEADER_SIZE}). size:{size}"
    ))]
    HeaderSize { size: DataSize },
    #[snafu(display("Proxy error happen!"))]
    Proxy { source: proxy_core::ProxyError },
    #[snafu(display("Control error: {source}"))]
    Control {
        source: proxy_core::control::ControlError,
    },
}

use proxy_core::codec::{
    AsyncDecryptCodec, AsyncEncryptCodec, AsyncNormalCodec, AsyncReader, AsyncWriter,
};
use proxy_core::util::{GracefulShutdownManager, GracefulShutdownManagerImpl};
use proxy_core::{
    Aes256GcmCryption, Aes256GcmDecryptor, Aes256GcmEncryptor, DataSize, MyAsyncCodecReader,
    MyAsyncReadExt, ProxyHeader, get_data_size, set_data_size,
};

type Result<T> = std::result::Result<T, ServerError>;

pub const MAX_HEADER_SIZE: DataSize = 8 * 128;

struct ServerContext {
    metrics: Arc<MetricsStore>,
    nodes: Arc<NodeStore>,
    relay: Arc<RelayManager>,
    admin_token: Option<String>,
    require_control_encryption: bool,
    control_session_key: Option<String>,
    self_node_id: Option<String>,
    /// Monotonic trace id seed used to tag logs for each connection.
    trace_id_seed: AtomicU64,
}

impl ServerContext {
    /// Allocate a per-connection tracing id.
    ///
    /// The id is monotonically increasing for easier correlation across logs
    /// and metrics snapshots.
    fn allocate_trace_id(&self) -> u64 {
        self.trace_id_seed.fetch_add(1, Ordering::Relaxed)
    }
}

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
    let start = Instant::now();
    let (tx, rx) = oneshot::channel();
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
    let (client_outcome, server_outcome) = tokio::join!(client_to_server, server_to_client);
    let latency_ms = rx.await.ok().map(|d| d.as_millis() as u64);
    if let Some(err) = client_outcome.error.or(server_outcome.error) {
        return Err(ServerError::Proxy { source: err });
    }
    Ok(TransferStats {
        bytes_up: client_outcome.bytes as u64,
        bytes_down: server_outcome.bytes as u64,
        latency_ms,
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
    let start = Instant::now();
    let (tx, rx) = oneshot::channel();
    let decryptor =
        Aes256GcmDecryptor::try_new(key.as_bytes()).map_err(|e| ServerError::Decryption {
            detail: e.to_string(),
        })?;
    let encryptor =
        Aes256GcmEncryptor::try_new(key.as_bytes()).map_err(|e| ServerError::Decryption {
            detail: e.to_string(),
        })?;
    let client_codec = AsyncDecryptCodec::new(client_reader, decryptor);
    let server_codec = AsyncEncryptCodec::new(server_reader, encryptor);
    let client_to_server = copy_with_metrics(client_codec, server_writer, None, start);
    let server_to_client = copy_with_metrics(server_codec, client_writer, Some(tx), start);
    let (client_outcome, server_outcome) = tokio::join!(client_to_server, server_to_client);
    let latency_ms = rx.await.ok().map(|d| d.as_millis() as u64);
    if let Some(err) = client_outcome.error.or(server_outcome.error) {
        return Err(ServerError::Proxy { source: err });
    }
    Ok(TransferStats {
        bytes_up: client_outcome.bytes as u64,
        bytes_down: server_outcome.bytes as u64,
        latency_ms,
    })
}

async fn handle_control_session(
    mut codec: ControlCodec<
        AsyncReader<tokio::net::tcp::OwnedReadHalf>,
        AsyncWriter<tokio::net::tcp::OwnedWriteHalf>,
    >,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    loop {
        let request = match codec.read_request().await.context(ControlSnafu)? {
            Some(req) => req,
            None => break,
        };
        let response = handle_control_request(request, ctx.clone());
        codec
            .write_response(&response)
            .await
            .context(ControlSnafu)?;
    }
    Ok(())
}

fn handle_control_request(request: ControlRequest, ctx: Arc<ServerContext>) -> ControlResponse {
    if let Some(expected) = ctx.admin_token.as_ref()
        && request.token.as_deref() != Some(expected.as_str())
    {
        return ControlResponse {
            ok: false,
            error: Some("unauthorized".to_string()),
            result: None,
        };
    }

    match request.op {
        ControlOp::Ping => ControlResponse {
            ok: true,
            error: None,
            result: Some(ControlResult::Pong),
        },
        ControlOp::AddNode { addr } => {
            if ctx.self_node_id.is_none() {
                return ControlResponse {
                    ok: false,
                    error: Some(
                        "NODE_ADVERTISE_ADDR not set and bind address cannot be used for node sync"
                            .to_string(),
                    ),
                    result: None,
                };
            }
            ctx.nodes.unblock_peer(&addr);
            let node = NodeInfo {
                node_id: addr.clone(),
                addr,
                last_seen_ms: current_time_ms(),
            };
            ctx.nodes.upsert_peer(node);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {err}");
            }
            let ctx_clone = ctx.clone();
            tokio::spawn(async move {
                broadcast_nodes(ctx_clone).await;
            });
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::RemoveNode { node_id } => {
            if ctx.self_node_id.as_deref() == Some(node_id.as_str()) {
                return ControlResponse {
                    ok: false,
                    error: Some("cannot remove self node".to_string()),
                    result: None,
                };
            }
            ctx.nodes.block_peer(&node_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {err}");
            }
            let ctx_clone = ctx.clone();
            tokio::spawn(async move {
                broadcast_nodes(ctx_clone).await;
            });
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::ListNodes => {
            let nodes = ctx.nodes.list_all_nodes();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Nodes { nodes }),
            }
        }
        ControlOp::SyncNodes { nodes, blocked } => {
            ctx.nodes.merge_blocked(blocked);
            ctx.nodes.upsert_peers(nodes);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {err}");
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::GetRealtimeStats => {
            let stats = ctx.metrics.get_realtime_snapshot();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RealtimeStats { stats }),
            }
        }
        ControlOp::GetRecentConnections => {
            let connections = ctx.metrics.get_recent_connections(100);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Connections { connections }),
            }
        }
        ControlOp::GetTimeBuckets { granularity } => {
            let buckets = ctx.metrics.get_time_buckets(granularity, 60);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::TimeBuckets { buckets }),
            }
        }
        ControlOp::GetTopN { category } => {
            let entries = ctx
                .metrics
                .get_top_n(category, 100)
                .into_iter()
                .map(|(key, stats)| TopNEntry { key, stats })
                .collect();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::TopN { entries }),
            }
        }
        // Group management
        ControlOp::CreateGroup { group_id, name } => {
            if ctx.nodes.create_group(group_id, name) {
                if let Err(err) = ctx.nodes.save() {
                    tracing::warn!("save nodes failed: {err}");
                }
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("group already exists".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::DeleteGroup { group_id } => {
            ctx.nodes.delete_group(&group_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {err}");
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::ListGroups => {
            let groups = ctx.nodes.list_groups();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Groups { groups }),
            }
        }
        ControlOp::AddNodeToGroup { group_id, node_id } => {
            if ctx.nodes.add_node_to_group(&group_id, node_id) {
                if let Err(err) = ctx.nodes.save() {
                    tracing::warn!("save nodes failed: {err}");
                }
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("group not found".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::RemoveNodeFromGroup { group_id, node_id } => {
            ctx.nodes.remove_node_from_group(&group_id, &node_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {err}");
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        // Relay configuration
        ControlOp::GetRelayConfig => {
            let config = ctx.relay.get_config();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RelayConfig { config }),
            }
        }
        ControlOp::SetRelayConfig { config } => {
            ctx.relay.set_config(config);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::SetRelayEnabled { enabled } => {
            ctx.relay.set_enabled(enabled);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::AddRelayTarget { target } => {
            ctx.relay.add_target(target);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::RemoveRelayTarget { index } => {
            if ctx.relay.remove_target(index) {
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("invalid target index".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::SetRelayAlgo { algo } => {
            ctx.relay.set_algo(algo);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::GetRelayStatus => {
            let status = ctx.relay.get_status();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RelayStatus { status }),
            }
        }
    }
}

fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Some((socket.ip().to_string(), socket.port()));
    }
    if let Some(bracket_end) = addr.find("]:") {
        let host = addr.get(1..bracket_end)?;
        let port = addr.get(bracket_end + 2..)?.trim().parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    let idx = addr.rfind(':')?;
    let host = addr[..idx].trim();
    let port = addr[idx + 1..].trim().parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn auto_advertise_addr(host: &str, port: u16) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host == "0.0.0.0" || host == "::" || host == "[::]" {
        return None;
    }
    if host == "localhost" {
        return Some(format_ip_addr(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }
    let ip = host.parse::<IpAddr>().ok()?;
    if ip.is_unspecified() {
        return None;
    }
    Some(format_ip_addr(ip, port))
}

fn format_ip_addr(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(_) => format!("{}:{}", ip, port),
        IpAddr::V6(_) => format!("[{}]:{}", ip, port),
    }
}

fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // This does not send packets, but lets the OS pick an outbound interface.
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip();
    if ip.is_unspecified() { None } else { Some(ip) }
}

/// Detect public IP by querying external services.
fn detect_public_ip() -> Option<IpAddr> {
    const SERVICES: &[&str] = &[
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    let agent = ureq::Agent::new_with_defaults();
    for url in SERVICES {
        if let Ok(body) = agent
            .get(*url)
            .call()
            .and_then(|mut r| r.body_mut().read_to_string())
            && let Ok(ip) = body.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}

fn parse_addr_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

async fn broadcast_nodes(ctx: Arc<ServerContext>) {
    if let Some(id) = ctx.self_node_id.as_deref() {
        ctx.nodes.update_peer_seen(id);
    }
    let nodes = ctx.nodes.list_all_nodes();
    let blocked = ctx.nodes.blocked_list();
    for node in nodes.iter() {
        if ctx.self_node_id.as_deref() == Some(node.node_id.as_str()) {
            continue;
        }
        if ctx.nodes.is_self_addr(&node.addr) {
            continue;
        }
        let Some((host, port)) = split_host_port(&node.addr) else {
            tracing::warn!("invalid node addr: {}", node.addr);
            continue;
        };
        let session_key = ctx.control_session_key.clone();
        let mut client =
            match proxy_core::control::ControlClient::connect(&host, port, session_key).await {
                Ok(client) => client,
                Err(err) => {
                    tracing::debug!("sync connect {} failed: {err}", node.addr);
                    continue;
                }
            };
        let request = ControlRequest {
            token: ctx.admin_token.clone(),
            op: ControlOp::SyncNodes {
                nodes: nodes.clone(),
                blocked: blocked.clone(),
            },
        };
        match client.request(request).await {
            Ok(_) => {
                ctx.nodes.update_peer_seen(&node.node_id);
            }
            Err(err) => {
                tracing::debug!("sync nodes to {} failed: {err}", node.addr);
            }
        }
    }
    if let Err(err) = ctx.nodes.save() {
        tracing::warn!("save nodes failed: {err}");
    }
}

fn control_session_key_fallback() -> (Option<String>, bool) {
    if let Some(key) = (*CONTROL_SESSION_KEY).clone() {
        return (Some(key), false);
    }
    if let Ok(key) = std::env::var("SECRET_KEY") {
        return (Some(key), false);
    }
    let default_key = String::from_utf8_lossy(&DEFAULT_KEY.0).to_string();
    (Some(default_key), true)
}

/// Handle a new TCP connection with a per-connection tracing span.
///
/// This attaches a `trace_id` to all logs emitted during the connection's
/// lifecycle to simplify troubleshooting.
async fn handle_connect(
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
            tracing::error!("connection error: {err}");
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
        HeaderSizeSnafu { size: msg_len }.fail()?
    }

    let mut header_buf = vec![0u8; msg_len as usize];
    client_reader
        .read_exact(&mut header_buf)
        .await
        .context(IoSnafu {
            detail: "Read Header(addr,tag)",
        })?;

    // Use dynamic relay selection (TURELY_PROXY_SERVER is now added to relay config at startup)
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
        if result.is_err() {
            ctx.relay.mark_unhealthy(&relay_server);
        }
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

    // Non-relay mode: decrypt header
    let header = match Aes256GcmCryption::try_new_with_default_key() {
        Ok(mut cryption) => match cryption.decrypt_with_tag(&mut header_buf) {
            Ok(payload) => match serde_json::from_slice::<ProxyHeader>(payload) {
                Ok(header) => Some(header),
                Err(err) => {
                    tracing::warn!("parse header failed: {err}");
                    None
                }
            },
            Err(err) => {
                tracing::warn!("decrypt header failed: {err}");
                None
            }
        },
        Err(err) => {
            tracing::warn!("init decryptor failed: {err}");
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
    let stats = match result {
        Ok(stats) => *stats,
        Err(e) => {
            tracing::error!(
                "connection to {}:{} from {} failed: {}",
                dest_host,
                dest_port,
                peer_ip,
                e
            );
            TransferStats::default()
        }
    };
    let ended_at_ms = current_time_ms();
    let duration_ms = (ended_at_ms - started_at_ms).max(0);
    let error_msg = result.as_ref().err().map(|e| e.to_string());
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

/// Server configuration for testing.
#[derive(Clone)]
pub struct ServerConfig {
    pub metrics: Arc<MetricsStore>,
    pub nodes: Arc<NodeStore>,
    pub relay: Arc<RelayManager>,
    pub admin_token: Option<String>,
    pub require_control_encryption: bool,
    pub control_session_key: Option<String>,
    pub self_node_id: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let nodes = Arc::new(NodeStore::with_default_path());
        Self {
            metrics: Arc::new(MetricsStore::with_default_config()),
            relay: Arc::new(RelayManager::with_default_path(nodes.clone())),
            nodes,
            admin_token: None,
            require_control_encryption: false,
            control_session_key: None,
            self_node_id: None,
        }
    }
}

/// Run server with a pre-bound listener and cancellation token.
///
/// This is the core server loop. Use `start_server` for production with
/// graceful shutdown, or call this directly for testing/custom setups.
///
/// If `tracker` is provided, tasks are spawned through it for graceful shutdown.
/// Otherwise, tasks are spawned directly with `tokio::spawn`.
pub async fn run_server_with_listener(
    listener: TcpListener,
    config: ServerConfig,
    cancel_token: CancellationToken,
    tracker: Option<TaskTracker>,
) {
    config.metrics.init_realtime();

    // Spawn system stats collector (every 5s) with cancellation support
    let metrics_for_stats = config.metrics.clone();
    let stats_cancel = cancel_token.clone();
    tokio::spawn(async move {
        use proxy_core::metrics::SystemStats;
        use sysinfo::{Disks, Networks, Pid, ProcessesToUpdate, System};
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new_all();
        let mut disks = Disks::new_with_refreshed_list();
        let mut networks = Networks::new_with_refreshed_list();
        // Initial refresh for CPU baseline
        sys.refresh_cpu_all();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);

        // Track previous network bytes for rate calculation
        let mut prev_net_recv: u64 = 0;
        let mut prev_net_sent: u64 = 0;
        let interval_secs: u64 = 5;

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {
                    // Refresh process stats
                    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                    if let Some(proc) = sys.process(pid) {
                        metrics_for_stats.update_process_stats(proc.cpu_usage(), proc.memory());
                    }

                    // Refresh system stats
                    sys.refresh_cpu_all();
                    sys.refresh_memory();
                    disks.refresh(true);
                    networks.refresh(true);

                    // Calculate system CPU (average of all cores)
                    let cpu_percent = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>()
                        / sys.cpus().len().max(1) as f32;

                    // Disk stats (sum of all disks)
                    let (disk_used, disk_total) = disks.iter().fold((0u64, 0u64), |(used, total), d| {
                        (used + d.total_space() - d.available_space(), total + d.total_space())
                    });

                    // Network IO (sum of all interfaces)
                    let (net_recv, net_sent) = networks.iter().fold((0u64, 0u64), |(recv, sent), (_, data)| {
                        (recv + data.total_received(), sent + data.total_transmitted())
                    });

                    // Calculate rates (bytes/sec)
                    let recv_rate = if prev_net_recv > 0 {
                        net_recv.saturating_sub(prev_net_recv) / interval_secs
                    } else {
                        0
                    };
                    let sent_rate = if prev_net_sent > 0 {
                        net_sent.saturating_sub(prev_net_sent) / interval_secs
                    } else {
                        0
                    };
                    prev_net_recv = net_recv;
                    prev_net_sent = net_sent;

                    metrics_for_stats.update_system_stats(SystemStats {
                        cpu_percent,
                        memory_used: sys.used_memory(),
                        memory_total: sys.total_memory(),
                        net_recv_bytes: net_recv,
                        net_sent_bytes: net_sent,
                        net_recv_rate: recv_rate,
                        net_sent_rate: sent_rate,
                        disk_used,
                        disk_total,
                    });
                }
                _ = stats_cancel.cancelled() => {
                    break;
                }
            }
        }
    });

    let ctx = Arc::new(ServerContext {
        metrics: config.metrics,
        nodes: config.nodes,
        relay: config.relay,
        admin_token: config.admin_token,
        require_control_encryption: config.require_control_encryption,
        control_session_key: config.control_session_key,
        self_node_id: config.self_node_id,
        trace_id_seed: AtomicU64::new(1),
    });

    // Node sync is change-driven; no periodic background sync.

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, peer_addr)) => {
                        let ctx = ctx.clone();
                        let token = cancel_token.clone();
                        let task = async move {
                            let _ = handle_connect(socket, peer_addr, ctx).await;
                        };
                        let wrapped_task = async move {
                            tokio::select! {
                                _ = token.cancelled() => {}
                                _ = task => {}
                            }
                        };
                        if let Some(ref t) = tracker {
                            t.spawn(wrapped_task);
                        } else {
                            tokio::spawn(wrapped_task);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("accept error: {e}");
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                break;
            }
        }
    }
}

#[tracing::instrument]
pub async fn start_server(host: impl AsRef<str> + Debug, port: u16) {
    let nodes = Arc::new(NodeStore::with_default_path());
    if let Err(err) = nodes.load() {
        tracing::warn!("load nodes failed: {err}");
    }

    let metrics = Arc::new(MetricsStore::with_default_config());

    let control_session_key = if *CONTROL_REQUIRE_ENCRYPTION {
        let (key, is_default) = control_session_key_fallback();
        if is_default {
            tracing::warn!(
                "CONTROL_REQUIRE_ENCRYPTION is enabled but using DEFAULT_KEY - this is insecure!"
            );
        }
        key
    } else {
        (*CONTROL_SESSION_KEY).clone()
    };
    if *CONTROL_REQUIRE_ENCRYPTION && control_session_key.is_none() {
        tracing::warn!(
            "CONTROL_REQUIRE_ENCRYPTION is enabled but no control session key available"
        );
    }

    let mut self_addrs = Vec::new();
    if let Some(raw) = NODE_ADVERTISE_ADDR.as_ref() {
        self_addrs.extend(parse_addr_list(raw));
    }
    if let Some(addr) = auto_advertise_addr(host.as_ref(), port) {
        self_addrs.push(addr);
    }
    // Detect public IP, fallback to local IP if network fails
    if let Some(ip) = detect_public_ip() {
        tracing::info!("Detected public IP: {}", ip);
        self_addrs.push(format_ip_addr(ip, port));
    } else if let Some(ip) = detect_local_ip() {
        tracing::warn!("Failed to detect public IP, using local IP: {}", ip);
        self_addrs.push(format_ip_addr(ip, port));
    }
    let mut unique = Vec::new();
    for addr in self_addrs {
        if unique.iter().any(|v| v == &addr) {
            continue;
        }
        unique.push(addr);
    }

    let self_node_id = if let Some(primary_addr) = unique.first().cloned() {
        let node_id = (*NODE_ID).clone().unwrap_or_else(|| primary_addr.clone());
        nodes.set_self(node_id.clone(), primary_addr);
        nodes.set_self_addrs(unique);
        if let Err(err) = nodes.save() {
            tracing::warn!("save nodes failed: {err}");
        }
        if NODE_ADVERTISE_ADDR.is_none() {
            tracing::warn!("NODE_ADVERTISE_ADDR not set, using detected addresses for node sync");
        }
        Some(node_id)
    } else {
        None
    };

    let relay = Arc::new(RelayManager::with_default_path(nodes.clone()));

    // If TURELY_PROXY_SERVER is set, add it as initial relay target and enable relay
    if let Some(upstream) = TURELY_PROXY_SERVER.as_ref() {
        // Only add if relay is not already configured (respect persisted config)
        if relay.get_config().targets.is_empty() {
            tracing::info!(
                "TURELY_PROXY_SERVER={} detected, adding as initial relay target",
                upstream
            );
            relay.add_target(proxy_core::relay::UpstreamTarget::node(upstream));
            relay.set_enabled(true);
        } else {
            tracing::info!(
                "TURELY_PROXY_SERVER set but relay already configured, using persisted config"
            );
        }
    }

    let config = ServerConfig {
        metrics,
        nodes,
        relay,
        admin_token: (*CONTROL_ADMIN_TOKEN).clone(),
        require_control_encryption: *CONTROL_REQUIRE_ENCRYPTION,
        control_session_key,
        self_node_id,
    };

    let listener = TcpListener::bind((host.as_ref(), port))
        .await
        .expect("start listener never fails");
    tracing::info!("Server listening on {}:{}", host.as_ref(), port);

    let mut manager = GracefulShutdownManagerImpl::new();
    if !manager.spawn_graceful_signals() {
        return;
    }
    let cancel_token = manager.cancellation_token();
    let tracker = manager.tracker().clone();

    run_server_with_listener(listener, config, cancel_token, Some(tracker)).await;

    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
}
