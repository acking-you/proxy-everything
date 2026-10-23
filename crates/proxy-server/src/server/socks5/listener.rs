//! One listener generation: the settings, credentials and sessions that a
//! configuration change or shutdown revokes together.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use proxy_core::ProxyTransport;
use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::datagram::{
    DatagramAddress, DatagramRelayReader, DatagramRelayWriter, create_direct_datagram_relay,
    create_socks5_datagram_relay, encode_socks5_udp_packet, parse_socks5_udp_packet,
    udp_association_idle_timeout,
};
use proxy_core::metrics::current_time_ms;
use proxy_core::relay::{ExternalProxyKind, RelayRoute, ResolvedTarget};
use proxy_core::secure_transport::ProxyStream;
use proxy_core::session::NativeSession;
use proxy_core::socks5::{
    self, AUTH_VERSION, DatagramSink, DatagramSource, METHOD_NONE_ACCEPTABLE,
    METHOD_USERNAME_PASSWORD, NativeDatagramReader, NativeDatagramWriter, Socks5Config,
    Socks5Session, UdpClientEndpoint, VERSION, is_public_unicast, reply,
};
use proxy_core::util::error_report;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::super::connection::{
    ActiveConnection, TransferStats, proxy_with_metrics_normal,
    proxy_with_metrics_upstream_session, record_connection,
};
use super::super::{ServerContext, ServerError};

/// Outbound TCP connects and UDP relay setup, separate from the handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 128;

/// Verify a fixed-size MAC instead of comparing password bytes with an
/// early-exit string comparison. The MAC key is local to this generation.
struct Authenticator {
    key: hmac::Key,
    expected: hmac::Tag,
}

impl Authenticator {
    fn new(config: &Socks5Config) -> io::Result<Self> {
        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| io::Error::other("OS random generator failed"))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &random);
        let mut input = vec![config.username.len() as u8];
        input.extend_from_slice(config.username.as_bytes());
        input.extend_from_slice(config.password.as_bytes());
        let expected = hmac::sign(&key, &input);
        Ok(Self { key, expected })
    }

    async fn authenticate(&self, stream: &mut TcpStream) -> io::Result<()> {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = [0u8; 255];
        let count = usize::from(greeting[1]);
        if greeting[0] == VERSION && count != 0 {
            stream.read_exact(&mut methods[..count]).await?;
        }
        if greeting[0] != VERSION || !methods[..count].contains(&METHOD_USERNAME_PASSWORD) {
            stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await?;
            return Err(denied("SOCKS5 username/password method required"));
        }
        stream
            .write_all(&[VERSION, METHOD_USERNAME_PASSWORD])
            .await?;
        let version = stream.read_u8().await?;
        let username_len = usize::from(stream.read_u8().await?);
        if version != AUTH_VERSION || username_len == 0 {
            stream.write_all(&[AUTH_VERSION, 1]).await?;
            return Err(denied("invalid SOCKS5 authentication"));
        }
        let mut input = [0u8; 511];
        input[0] = username_len as u8;
        stream.read_exact(&mut input[1..1 + username_len]).await?;
        let password_len = usize::from(stream.read_u8().await?);
        stream
            .read_exact(&mut input[1 + username_len..1 + username_len + password_len])
            .await?;
        let accepted = password_len != 0
            && hmac::verify(
                &self.key,
                &input[..1 + username_len + password_len],
                self.expected.as_ref(),
            )
            .is_ok();
        stream
            .write_all(&[AUTH_VERSION, u8::from(!accepted)])
            .await?;
        if accepted {
            Ok(())
        } else {
            Err(denied("SOCKS5 authentication failed"))
        }
    }
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

struct Session {
    info: Socks5Session,
    cancel: CancellationToken,
}

/// Settings and credentials shared by every session of one listener run.
pub(super) struct Generation {
    pub(super) config: Socks5Config,
    auth: Authenticator,
    /// The server's public address, told to UDP clients that reach a private one.
    public_ip: Option<IpAddr>,
    sessions: Mutex<HashMap<u64, Session>>,
    pub(super) cancel: CancellationToken,
}

impl Generation {
    pub(super) fn new(config: Socks5Config, ctx: &ServerContext) -> io::Result<Self> {
        let public_ip = config.advertised_ip().or_else(|| {
            let node = ctx.nodes.get_self()?;
            node.addr.parse::<SocketAddr>().ok().map(|addr| addr.ip())
        });
        Ok(Self {
            auth: Authenticator::new(&config)?,
            config,
            public_ip: public_ip.map(|ip| ip.to_canonical()),
            sessions: Mutex::new(HashMap::new()),
            cancel: ctx.cancel.child_token(),
        })
    }

    pub(super) fn sessions(&self) -> Vec<Socks5Session> {
        let mut sessions: Vec<_> = self
            .sessions
            .lock()
            .values()
            .map(|session| session.info.clone())
            .collect();
        sessions.sort_by_key(|session| session.id);
        sessions
    }

    pub(super) fn active(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Close sessions by id, by client address, or all when both are absent.
    pub(super) fn close(&self, id: Option<u64>, peer: Option<IpAddr>) -> usize {
        let peer = peer.map(|ip| ip.to_canonical());
        let sessions = self.sessions.lock();
        let mut closed = 0;
        for session in sessions.values() {
            if id.is_none_or(|id| id == session.info.id)
                && peer.is_none_or(|peer| peer == session.info.peer.ip().to_canonical())
            {
                session.cancel.cancel();
                closed += 1;
            }
        }
        closed
    }

    fn register(self: &Arc<Self>, id: u64, peer: SocketAddr) -> Registration {
        let cancel = self.cancel.child_token();
        self.sessions.lock().insert(
            id,
            Session {
                info: Socks5Session {
                    id,
                    peer,
                    command: None,
                    destination: None,
                    started_at_ms: current_time_ms(),
                },
                cancel: cancel.clone(),
            },
        );
        Registration {
            generation: self.clone(),
            id,
            cancel,
        }
    }

    fn describe(&self, id: u64, command: &str, destination: Option<String>) {
        if let Some(session) = self.sessions.lock().get_mut(&id) {
            session.info.command = Some(command.into());
            session.info.destination = destination;
        }
    }
}

struct Registration {
    generation: Arc<Generation>,
    id: u64,
    cancel: CancellationToken,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.generation.sessions.lock().remove(&self.id);
    }
}

pub(super) async fn run(
    listener: Arc<TcpListener>,
    generation: Arc<Generation>,
    ctx: Arc<ServerContext>,
) {
    let tasks = TaskTracker::new();
    let max_sessions = generation.config.max_sessions as usize;
    let sessions = Arc::new(Semaphore::new(max_sessions));
    let pending = Arc::new(Semaphore::new(max_sessions.min(MAX_PENDING_HANDSHAKES)));
    let cancel = generation.cancel.clone();
    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            incoming = listener.accept() => match incoming {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "SOCKS5 accept failed");
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_millis(100)) => continue,
                    }
                }
            },
        };
        if !generation.config.allows_source(peer.ip()) {
            tracing::debug!(%peer, "SOCKS5 client address is not allowed");
            continue;
        }
        let (Ok(session), Ok(handshake)) = (
            sessions.clone().try_acquire_owned(),
            pending.clone().try_acquire_owned(),
        ) else {
            tracing::debug!(%peer, "SOCKS5 connection limit reached");
            continue;
        };
        let id = ctx.allocate_trace_id();
        let registration = generation.register(id, peer);
        let ctx = ctx.clone();
        let generation = generation.clone();
        tasks.spawn(async move {
            let _session = session;
            let _active = ActiveConnection::new(&ctx.metrics);
            let cancel = registration.cancel.clone();
            tokio::select! {
                biased;
                () = cancel.cancelled() => {}
                () = handle(stream, peer, id, &generation, &ctx, handshake) => {}
            }
            drop(registration);
        });
    }
    // Every session token is a child of the generation's token.
    tasks.close();
    tasks.wait().await;
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    id: u64,
    generation: &Generation,
    ctx: &Arc<ServerContext>,
    handshake: OwnedSemaphorePermit,
) {
    let started_at_ms = current_time_ms();
    let deadline = Duration::from_secs(generation.config.handshake_timeout_secs);
    let request =
        match tokio::time::timeout(deadline, negotiate(&mut stream, &generation.auth)).await {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                tracing::debug!(%peer, %error, "SOCKS5 negotiation failed");
                return;
            }
            Err(_) => {
                tracing::debug!(%peer, "SOCKS5 negotiation deadline exceeded");
                return;
            }
        };
    let egress = Egress::select(ctx);
    let (destination, result) = match request.command {
        socks5::CONNECT => {
            let (host, port) = match &request.address {
                DatagramAddress::Ip(addr) => (addr.ip().to_string(), addr.port()),
                DatagramAddress::Domain(host, port) => (host.clone(), *port),
            };
            generation.describe(id, "connect", Some(format_destination(&host, port)));
            let result = connect(stream, &host, port, &generation.config, &egress, handshake).await;
            ((host, port), result)
        }
        socks5::UDP_ASSOCIATE => {
            generation.describe(id, "udp_associate", None);
            let destination = match &egress.target {
                Some(target) => format!("udp:relay:{}", target.addr),
                None => "udp-associate".to_string(),
            };
            let result = associate(
                stream,
                peer,
                request.address,
                generation,
                &egress,
                handshake,
            )
            .await;
            ((destination, 0), result)
        }
        command => {
            let _ = socks5::write_failure(&mut stream, reply::COMMAND_NOT_SUPPORTED).await;
            tracing::debug!(%peer, command, "SOCKS5 command not supported");
            return;
        }
    };
    match result {
        Ok(None) => {}
        Ok(Some(stats)) => {
            record_connection(
                ctx,
                &peer.ip().to_canonical().to_string(),
                &destination.0,
                destination.1,
                started_at_ms,
                id,
                &Ok(stats),
            );
        }
        Err(error) => {
            record_connection(
                ctx,
                &peer.ip().to_canonical().to_string(),
                &destination.0,
                destination.1,
                started_at_ms,
                id,
                &Err(error),
            );
        }
    }
}

fn format_destination(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Authenticate and read one request, answering malformed requests.
async fn negotiate(stream: &mut TcpStream, auth: &Authenticator) -> io::Result<socks5::Request> {
    stream.set_nodelay(true)?;
    auth.authenticate(stream).await?;
    match socks5::read_request(stream).await {
        Ok(request) => Ok(request),
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::Unsupported {
                reply::ADDRESS_TYPE_NOT_SUPPORTED
            } else {
                reply::GENERAL_FAILURE
            };
            let _ = socks5::write_failure(stream, code).await;
            Err(error)
        }
    }
}

/// The route a session leaves through: direct, or the relay target selected
/// for it, which stays counted for least-connection balancing while it lives.
struct Egress<'a> {
    ctx: &'a ServerContext,
    target: Option<ResolvedTarget>,
}

impl<'a> Egress<'a> {
    fn select(ctx: &'a ServerContext) -> Self {
        let target = ctx.relay.select();
        if let Some(target) = &target {
            ctx.relay.on_connect(&target.id);
        }
        Self { ctx, target }
    }
}

impl Drop for Egress<'_> {
    fn drop(&mut self) {
        if let Some(target) = &self.target {
            self.ctx.relay.on_disconnect(&target.id);
        }
    }
}

fn split_node(addr: &str) -> io::Result<(String, u16)> {
    let endpoint = proxy_core::upstream::UpstreamAddress::parse(addr)?;
    Ok((endpoint.qualified_host(), endpoint.port))
}

fn transport_error(error: impl std::error::Error) -> io::Error {
    io::Error::other(error_report(&error))
}

enum TcpUpstream {
    Plain(TcpStream),
    Native(ProxyStream, Option<Cow<'static, str>>),
}

/// Open the outbound stream. Destinations named by address are checked on
/// every route; names are resolved and checked here only for direct egress,
/// because a relay resolves them where they leave.
async fn open_tcp(
    host: &str,
    port: u16,
    config: &Socks5Config,
    egress: &Egress<'_>,
) -> io::Result<TcpUpstream> {
    if let Ok(ip) = host.parse::<IpAddr>()
        && !config.allows_destination(ip)
    {
        return Err(denied("SOCKS5 destination is not allowed"));
    }
    let Some(target) = &egress.target else {
        let resolved = proxy_core::transport::resolve_host_addresses(host).await?;
        let allowed: Vec<IpAddr> = resolved
            .iter()
            .copied()
            .filter(|ip| config.allows_destination(*ip))
            .collect();
        if allowed.is_empty() {
            return Err(denied("SOCKS5 destination is not allowed"));
        }
        return proxy_core::transport::connect_tcp_addresses(&allowed, port)
            .await
            .map(TcpUpstream::Plain);
    };
    match &target.route {
        RelayRoute::ProxyServer { addr } => {
            let (node, node_port) = split_node(addr)?;
            let session = NativeSession::connect(host, port, &node, node_port, ProxyTransport::Tcp)
                .await
                .map_err(transport_error)?;
            let (stream, key) = session.into_parts();
            Ok(TcpUpstream::Native(stream, key))
        }
        RelayRoute::ExternalProxy(proxy) => proxy_core::transport::get_tcp_external_proxy_stream(
            proxy,
            host,
            port,
            "connect SOCKS5 destination through relay proxy",
        )
        .await
        .map(TcpUpstream::Plain)
        .map_err(transport_error),
    }
}

async fn connect(
    mut stream: TcpStream,
    host: &str,
    port: u16,
    config: &Socks5Config,
    egress: &Egress<'_>,
    handshake: OwnedSemaphorePermit,
) -> Result<Option<TransferStats>, ServerError> {
    let opened = tokio::time::timeout(CONNECT_TIMEOUT, open_tcp(host, port, config, egress))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS5 connect deadline exceeded",
            ))
        });
    let upstream = match opened {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = socks5::write_failure(&mut stream, reply::for_connect_error(&error)).await;
            return Err(ServerError::Io {
                detail: "SOCKS5 connect".into(),
                source: error,
            });
        }
    };
    let bound = match &upstream {
        TcpUpstream::Plain(upstream) => upstream.local_addr().ok(),
        TcpUpstream::Native(..) => None,
    }
    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    socks5::write_reply(&mut stream, reply::SUCCEEDED, bound)
        .await
        .map_err(|source| ServerError::Io {
            detail: "SOCKS5 reply".into(),
            source,
        })?;
    drop(handshake);
    let (cr, cw) = ProxyStream::from(stream).into_split();
    let (client_reader, client_writer) = (AsyncReader::new(cr), AsyncWriter::new(cw));
    let stats = match upstream {
        TcpUpstream::Plain(upstream) => {
            let (sr, sw) = ProxyStream::from(upstream).into_split();
            proxy_with_metrics_normal(
                client_reader,
                AsyncReader::new(sr),
                client_writer,
                AsyncWriter::new(sw),
            )
            .await
        }
        TcpUpstream::Native(upstream, key) => {
            let (sr, sw) = upstream.into_split();
            let (server_reader, server_writer) = (AsyncReader::new(sr), AsyncWriter::new(sw));
            match key {
                Some(key) => {
                    proxy_with_metrics_upstream_session(
                        &key,
                        client_reader,
                        server_reader,
                        client_writer,
                        server_writer,
                    )
                    .await
                }
                // v3 already protects the stream.
                None => {
                    proxy_with_metrics_normal(
                        client_reader,
                        server_reader,
                        client_writer,
                        server_writer,
                    )
                    .await
                }
            }
        }
    }?;
    Ok(Some(stats))
}

enum UdpSource {
    Relay(DatagramRelayReader),
    Native(Box<NativeDatagramReader>),
}

impl DatagramSource for UdpSource {
    async fn recv(&mut self) -> proxy_core::Result<Cow<'_, [u8]>> {
        match self {
            Self::Relay(reader) => DatagramSource::recv(reader).await,
            Self::Native(reader) => DatagramSource::recv(reader.as_mut()).await,
        }
    }
}

enum UdpTarget {
    Relay(DatagramRelayWriter),
    Native(Box<NativeDatagramWriter>),
}

/// Applies the destination policy before a datagram leaves. Direct egress
/// resolves names here, so the checked address is the one contacted, and
/// absorbs failures that only affect one datagram.
struct UdpSink {
    target: UdpTarget,
    direct: bool,
    allow_private: bool,
}

impl UdpSink {
    async fn forward(&mut self, packet: &[u8]) -> proxy_core::Result<()> {
        match &mut self.target {
            UdpTarget::Relay(writer) => DatagramSink::send(writer, packet).await,
            UdpTarget::Native(writer) => DatagramSink::send(writer.as_mut(), packet).await,
        }
    }

    fn allows(&self, ip: IpAddr) -> bool {
        self.allow_private || is_public_unicast(ip)
    }
}

impl DatagramSink for UdpSink {
    async fn send(&mut self, packet: &[u8]) -> proxy_core::Result<()> {
        let parsed = parse_socks5_udp_packet(packet)?;
        let candidates = match &parsed.destination {
            DatagramAddress::Ip(addr) if !self.allows(addr.ip()) => Vec::new(),
            DatagramAddress::Domain(..) if self.direct => {
                match parsed.destination.resolve().await {
                    Ok(resolved) => resolved
                        .into_iter()
                        .filter(|addr| self.allows(addr.ip()))
                        .collect(),
                    Err(error) => {
                        tracing::debug!(%error, "discarding SOCKS5 UDP packet to an unresolved name");
                        return Ok(());
                    }
                }
            }
            _ => return self.absorb(packet).await,
        };
        if candidates.is_empty() {
            tracing::debug!(destination = ?parsed.destination, "discarding SOCKS5 UDP packet to a disallowed destination");
            return Ok(());
        }
        let mut last = Ok(());
        for candidate in candidates {
            let rewritten =
                encode_socks5_udp_packet(&DatagramAddress::Ip(candidate), parsed.payload)?;
            last = self.forward(&rewritten).await;
            if last.is_ok() {
                break;
            }
        }
        self.settle(last)
    }
}

impl UdpSink {
    async fn absorb(&mut self, packet: &[u8]) -> proxy_core::Result<()> {
        let result = self.forward(packet).await;
        self.settle(result)
    }

    fn settle(&self, result: proxy_core::Result<()>) -> proxy_core::Result<()> {
        match result {
            Err(error) if self.direct => {
                tracing::debug!(%error, "discarding failed SOCKS5 UDP send");
                Ok(())
            }
            result => result,
        }
    }
}

async fn open_udp(
    config: &Socks5Config,
    egress: &Egress<'_>,
) -> io::Result<(
    UdpSource,
    UdpSink,
    Option<proxy_core::datagram::DatagramRelayGuard>,
)> {
    let sink = |target, direct| UdpSink {
        target,
        direct,
        allow_private: config.allow_private_destinations,
    };
    match egress.target.as_ref().map(|target| &target.route) {
        None => {
            let (reader, writer, guard) = create_direct_datagram_relay()
                .await
                .map_err(io::Error::other)?
                .into_parts();
            Ok((
                UdpSource::Relay(reader),
                sink(UdpTarget::Relay(writer), true),
                Some(guard),
            ))
        }
        Some(RelayRoute::ExternalProxy(proxy)) if proxy.kind == ExternalProxyKind::Socks5 => {
            let (reader, writer, guard) = create_socks5_datagram_relay(proxy)
                .await
                .map_err(io::Error::other)?
                .into_parts();
            Ok((
                UdpSource::Relay(reader),
                sink(UdpTarget::Relay(writer), false),
                Some(guard),
            ))
        }
        Some(RelayRoute::ExternalProxy(_)) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the relay's HTTP proxy cannot carry UDP",
        )),
        Some(RelayRoute::ProxyServer { addr }) => {
            let (node, node_port) = split_node(addr)?;
            let session =
                NativeSession::connect("", 0, &node, node_port, ProxyTransport::UdpAssociate)
                    .await
                    .map_err(transport_error)?;
            let (reader, writer) = session
                .into_datagram_tunnel(&node, node_port)
                .await
                .map_err(io::Error::other)?;
            Ok((
                UdpSource::Native(Box::new(reader)),
                sink(UdpTarget::Native(Box::new(writer)), false),
                None,
            ))
        }
    }
}

/// The address a UDP client should send to. A client that reached this
/// host's private address from a public one came through NAT and is told the
/// public address instead; everyone else uses the address they connected to.
fn udp_reply_address(bound: SocketAddr, peer: IpAddr, public: Option<IpAddr>) -> SocketAddr {
    match public {
        Some(public)
            if !is_public_unicast(bound.ip())
                && is_public_unicast(peer)
                && public.is_ipv4() == bound.is_ipv4() =>
        {
            SocketAddr::new(public, bound.port())
        }
        _ => bound,
    }
}

async fn associate(
    mut stream: TcpStream,
    peer: SocketAddr,
    requested: DatagramAddress,
    generation: &Generation,
    egress: &Egress<'_>,
    handshake: OwnedSemaphorePermit,
) -> Result<Option<TransferStats>, ServerError> {
    let config = &generation.config;
    if !config.udp {
        let _ = socks5::write_failure(&mut stream, reply::NOT_ALLOWED).await;
        return Ok(None);
    }
    let mut endpoint = match UdpClientEndpoint::new(&requested, peer.ip()) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = socks5::write_failure(&mut stream, reply::NOT_ALLOWED).await;
            tracing::debug!(%peer, %error, "SOCKS5 UDP endpoint rejected");
            return Ok(None);
        }
    };
    let setup = async {
        // A dual-stack listener reports IPv4 clients as IPv4-mapped IPv6.
        let local = stream.local_addr()?.ip().to_canonical();
        let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
        let upstream = tokio::time::timeout(CONNECT_TIMEOUT, open_udp(config, egress))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP setup timed out"))??;
        Ok::<_, io::Error>((socket, upstream))
    };
    let (socket, (mut source, mut sink, _guard)) = match setup.await {
        Ok(ready) => ready,
        Err(error) => {
            let _ = socks5::write_failure(&mut stream, reply::GENERAL_FAILURE).await;
            return Err(ServerError::Io {
                detail: "SOCKS5 UDP setup".into(),
                source: error,
            });
        }
    };
    let io_error = |detail: &str, source| ServerError::Io {
        detail: detail.into(),
        source,
    };
    let bound = udp_reply_address(
        socket
            .local_addr()
            .map_err(|e| io_error("SOCKS5 UDP address", e))?,
        peer.ip().to_canonical(),
        generation.public_ip,
    );
    socks5::write_reply(&mut stream, reply::SUCCEEDED, bound)
        .await
        .map_err(|e| io_error("SOCKS5 reply", e))?;
    drop(handshake);
    let report = socks5::relay_udp_association(
        &mut stream,
        &socket,
        &mut endpoint,
        &mut source,
        &mut sink,
        udp_association_idle_timeout(),
    )
    .await
    .map_err(|error| match error {
        socks5::UdpRelayError::Upstream { source } => ServerError::Datagram { source },
        socks5::UdpRelayError::Control { source }
        | socks5::UdpRelayError::ClientSocket { source } => io_error("SOCKS5 UDP relay", source),
    })?;
    tracing::debug!(
        %peer,
        close_reason = report.close_reason,
        packets_up = report.packets_up,
        packets_down = report.packets_down,
        "SOCKS5 UDP association closed"
    );
    Ok(Some(TransferStats {
        bytes_up: report.bytes_up,
        bytes_down: report.bytes_down,
        latency_ms: report
            .first_response
            .map(|latency| latency.as_millis() as u64),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_clients_behind_nat_get_the_public_address_and_others_keep_theirs() {
        let public = Some("9.9.9.9".parse().unwrap());
        let private: SocketAddr = "10.0.0.5:4000".parse().unwrap();
        assert_eq!(
            udp_reply_address(private, "1.1.1.1".parse().unwrap(), public),
            "9.9.9.9:4000".parse().unwrap()
        );
        assert_eq!(
            udp_reply_address(private, "10.0.0.8".parse().unwrap(), public),
            private
        );
        let loopback: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        assert_eq!(
            udp_reply_address(loopback, "127.0.0.1".parse().unwrap(), public),
            loopback
        );
        let secondary: SocketAddr = "8.8.8.8:4000".parse().unwrap();
        assert_eq!(
            udp_reply_address(secondary, "1.1.1.1".parse().unwrap(), public),
            secondary
        );
    }
}
