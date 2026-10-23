//! Shared RFC 1928/1929 framing, the managed listener's control types, and the
//! UDP association relay used by both the local client and the server endpoint.

use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::{fmt, io};

use ipnet::IpNet;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::ProxyError;
use crate::codec::{AsyncReader, AsyncWriter};
use crate::datagram::{
    DatagramAddress, DatagramRelayReader, DatagramRelayWriter, DatagramTunnelReader,
    DatagramTunnelWriter, MAX_SOCKS5_UDP_DATAGRAM_SIZE, SOCKS5_ATYP_DOMAIN, SOCKS5_ATYP_IPV4,
    SOCKS5_ATYP_IPV6, encode_socks5_address, parse_socks5_address, parse_socks5_udp_packet,
};
use crate::secure_transport::ProxyStream;

pub const VERSION: u8 = 5;
/// RFC 1929 subnegotiation version.
pub const AUTH_VERSION: u8 = 1;
pub const METHOD_NO_AUTH: u8 = 0;
pub const METHOD_USERNAME_PASSWORD: u8 = 2;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
pub const CONNECT: u8 = 1;
pub const UDP_ASSOCIATE: u8 = 3;

/// RFC 1928 reply codes.
pub mod reply {
    use std::io;

    pub const SUCCEEDED: u8 = 0;
    pub const GENERAL_FAILURE: u8 = 1;
    pub const NOT_ALLOWED: u8 = 2;
    pub const NETWORK_UNREACHABLE: u8 = 3;
    pub const HOST_UNREACHABLE: u8 = 4;
    pub const CONNECTION_REFUSED: u8 = 5;
    pub const TTL_EXPIRED: u8 = 6;
    pub const COMMAND_NOT_SUPPORTED: u8 = 7;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

    /// The closest reply for a failed outbound connection.
    pub fn for_connect_error(error: &io::Error) -> u8 {
        match error.kind() {
            io::ErrorKind::PermissionDenied => NOT_ALLOWED,
            io::ErrorKind::NetworkUnreachable => NETWORK_UNREACHABLE,
            io::ErrorKind::HostUnreachable => HOST_UNREACHABLE,
            io::ErrorKind::ConnectionRefused => CONNECTION_REFUSED,
            io::ErrorKind::TimedOut => TTL_EXPIRED,
            _ => GENERAL_FAILURE,
        }
    }
}

const DEFAULT_MAX_SESSIONS: u32 = 1024;
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const MAX_ALLOWED_SOURCES: usize = 256;

/// Persisted settings. The password is serialized only for explicit management
/// responses and the private state file; diagnostic formatting always redacts it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Config {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    /// `host` or `host:port` that clients dial, for NAT, port mapping or a
    /// domain name. Without it clients use the node's own host and `listen`'s port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Loopback, private, link-local and other non-public destinations are
    /// refused unless enabled, because SOCKS5 credentials cross the network in
    /// cleartext and the server's own services usually listen there.
    #[serde(default)]
    pub allow_private_destinations: bool,
    /// Client networks allowed to connect. Empty allows every source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_sources: Vec<IpNet>,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: u32,
    /// Deadline for authentication and the request, not for the outbound connect.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_max_sessions() -> u32 {
    DEFAULT_MAX_SESSIONS
}
fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

impl fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Config")
            .field("enabled", &self.enabled)
            .field("listen", &self.listen)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("advertise", &self.advertise)
            .field("udp", &self.udp)
            .field(
                "allow_private_destinations",
                &self.allow_private_destinations,
            )
            .field("allowed_sources", &self.allowed_sources)
            .field("max_sessions", &self.max_sessions)
            .field("handshake_timeout_secs", &self.handshake_timeout_secs)
            .finish()
    }
}

impl Socks5Config {
    /// A disabled endpoint with the given credentials and default policy.
    pub fn new(listen: SocketAddr, username: String, password: String) -> Self {
        Self {
            enabled: false,
            listen,
            username,
            password,
            advertise: None,
            udp: true,
            allow_private_destinations: false,
            allowed_sources: Vec::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            handshake_timeout_secs: DEFAULT_HANDSHAKE_TIMEOUT_SECS,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(1..=255).contains(&self.username.len()) || !(1..=255).contains(&self.password.len()) {
            return Err("SOCKS5 username and password must each be 1-255 bytes".into());
        }
        if !(1..=65_535).contains(&self.max_sessions) {
            return Err("max_sessions must be between 1 and 65535".into());
        }
        if !(1..=300).contains(&self.handshake_timeout_secs) {
            return Err("handshake_timeout_secs must be between 1 and 300".into());
        }
        if self.allowed_sources.len() > MAX_ALLOWED_SOURCES {
            return Err(format!(
                "at most {MAX_ALLOWED_SOURCES} allowed source networks are supported"
            ));
        }
        if let Some(advertise) = &self.advertise {
            split_advertise(advertise)?;
        }
        Ok(())
    }

    /// Apply a partial update. Nothing changes unless the result is valid.
    pub fn apply(&mut self, update: Socks5Update) -> Result<(), String> {
        let mut next = self.clone();
        if let Some(username) = update.username {
            next.username = username;
        }
        if let Some(password) = update.password {
            next.password = password;
        }
        if let Some(advertise) = update.advertise {
            let advertise = advertise.trim();
            next.advertise = (!advertise.is_empty()).then(|| advertise.to_string());
        }
        if let Some(udp) = update.udp {
            next.udp = udp;
        }
        if let Some(allow) = update.allow_private_destinations {
            next.allow_private_destinations = allow;
        }
        if let Some(max_sessions) = update.max_sessions {
            next.max_sessions = max_sessions;
        }
        if let Some(timeout) = update.handshake_timeout_secs {
            next.handshake_timeout_secs = timeout;
        }
        if update.clear_allowed_sources {
            next.allowed_sources.clear();
        }
        let remove: Vec<IpNet> = update
            .remove_allowed_sources
            .iter()
            .map(IpNet::trunc)
            .collect();
        next.allowed_sources.retain(|net| !remove.contains(net));
        for net in update.add_allowed_sources.iter().map(IpNet::trunc) {
            if !next.allowed_sources.contains(&net) {
                next.allowed_sources.push(net);
            }
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Whether the listener can keep serving: only the advertised client
    /// address may differ, and that never reaches a session.
    pub fn same_listener(&self, other: &Self) -> bool {
        Self {
            advertise: None,
            ..self.clone()
        } == Self {
            advertise: None,
            ..other.clone()
        }
    }

    pub fn allows_source(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allowed_sources.is_empty() || self.allowed_sources.iter().any(|net| net.contains(&ip))
    }

    pub fn allows_destination(&self, ip: IpAddr) -> bool {
        self.allow_private_destinations || is_public_unicast(ip)
    }

    /// The advertised host, when it is an IP address.
    pub fn advertised_ip(&self) -> Option<IpAddr> {
        let (host, _) = split_advertise(self.advertise.as_deref()?).ok()?;
        host.parse().ok()
    }

    /// What a client needs to connect. The host is absent unless advertised.
    pub fn endpoint(&self) -> Socks5Endpoint {
        let (host, port) = self
            .advertise
            .as_deref()
            .and_then(|advertise| split_advertise(advertise).ok())
            .map_or((None, None), |(host, port)| (Some(host), port));
        Socks5Endpoint {
            username: self.username.clone(),
            password: self.password.clone(),
            host,
            port: port.unwrap_or(self.listen.port()),
            udp: self.udp,
        }
    }
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port`. A bare IPv6 address has no port.
fn split_advertise(value: &str) -> Result<(String, Option<u16>), String> {
    let invalid = || format!("invalid advertise address {value:?}; expected HOST or HOST:PORT");
    if value.is_empty()
        || value.len() > 262
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(invalid());
    }
    let port = |text: &str| match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(invalid()),
    };
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        return match tail {
            "" => Ok((host.to_string(), None)),
            _ => Ok((
                host.to_string(),
                Some(port(tail.strip_prefix(':').ok_or_else(invalid)?)?),
            )),
        };
    }
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok((value.to_string(), None));
    }
    match value.rsplit_once(':') {
        Some((host, text)) if !host.is_empty() && !host.contains(':') => {
            Ok((host.to_string(), Some(port(text)?)))
        }
        Some(_) => Err(invalid()),
        None => Ok((value.to_string(), None)),
    }
}

/// A partial settings change. Absent fields keep their value; an empty
/// `advertise` clears it. Source networks are cleared, then removed, then added.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Update {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_destinations: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clear_allowed_sources: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_allowed_sources: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_allowed_sources: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Status {
    pub config: Socks5Config,
    /// Distinguishes persisted intent from a listener that could not be restored.
    pub running: bool,
    pub last_error: Option<String>,
    #[serde(default)]
    pub active_sessions: usize,
}

/// One authenticated or authenticating client connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Session {
    pub id: u64,
    pub peer: SocketAddr,
    /// `connect` or `udp_associate`, once the request has been read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    pub started_at_ms: i64,
}

/// What a proxy user needs to connect. Readable with the node's session key,
/// which already grants use of the native proxy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Endpoint {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub port: u16,
    pub udp: bool,
}

impl fmt::Debug for Socks5Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Endpoint")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("udp", &self.udp)
            .finish()
    }
}

/// RFC 3986 userinfo keeps only unreserved characters unencoded.
const USERINFO: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

impl Socks5Endpoint {
    /// `socks5://user:password@host:port`, using `fallback_host` (the address
    /// the caller reached the node at) unless a host is advertised.
    pub fn url(&self, fallback_host: &str) -> String {
        let host = self.host.as_deref().unwrap_or(fallback_host);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        format!(
            "socks5://{}:{}@{host}:{}",
            utf8_percent_encode(&self.username, USERINFO),
            utf8_percent_encode(&self.password, USERINFO),
            self.port
        )
    }
}

/// Whether `ip` is globally routable unicast. IPv4-mapped IPv6 addresses are
/// judged by their IPv4 address.
pub fn is_public_unicast(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                // Shared address space (carrier-grade NAT), 100.64.0.0/10.
                || (a == 100 && b & 0xc0 == 64)
                // Benchmarking, 198.18.0.0/15, also used for fake-IP DNS.
                || (a == 198 && b & 0xfe == 18)
                // IETF protocol assignments, 192.0.0.0/24.
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(ip) => {
            let [first, second, ..] = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                // Documentation, 2001:db8::/32.
                || (first == 0x2001 && second == 0x0db8)
                // Deprecated site-local, fec0::/10.
                || first & 0xffc0 == 0xfec0)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub command: u8,
    pub address: DatagramAddress,
}

/// Read exactly one request, leaving any pipelined application bytes untouched.
pub async fn read_request(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Request> {
    let mut header = [0; 3];
    reader.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request header",
        ));
    }
    Ok(Request {
        command: header[1],
        address: read_address(reader).await?,
    })
}

pub async fn read_address(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<DatagramAddress> {
    let mut encoded = [0u8; 259];
    encoded[0] = reader.read_u8().await?;
    let (offset, remaining) = match encoded[0] {
        SOCKS5_ATYP_IPV4 => (1, 6),
        SOCKS5_ATYP_IPV6 => (1, 18),
        SOCKS5_ATYP_DOMAIN => {
            encoded[1] = reader.read_u8().await?;
            if encoded[1] == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty SOCKS5 domain",
                ));
            }
            (2, usize::from(encoded[1]) + 2)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported SOCKS5 address type",
            ));
        }
    };
    reader
        .read_exact(&mut encoded[offset..offset + remaining])
        .await?;
    parse_socks5_address(&encoded[..offset + remaining])
        .map(|(address, _)| address)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 address"))
}

pub async fn write_reply(
    writer: &mut (impl AsyncWrite + Unpin),
    code: u8,
    bound: SocketAddr,
) -> io::Result<()> {
    let mut response = Vec::with_capacity(22);
    response.extend_from_slice(&[VERSION, code, 0]);
    encode_socks5_address(&DatagramAddress::Ip(bound), &mut response).map_err(io::Error::other)?;
    writer.write_all(&response).await
}

/// A failure reply. Its bound address carries no meaning.
pub async fn write_failure(writer: &mut (impl AsyncWrite + Unpin), code: u8) -> io::Result<()> {
    write_reply(writer, code, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

/// Pins a UDP association to its authenticated TCP peer and one UDP endpoint.
/// Only call `accept` after validating the datagram, so malformed packets cannot
/// claim an association whose requested port was zero.
///
/// Addresses are compared in canonical form: on a dual-stack listener an IPv4
/// client's TCP peer is IPv4-mapped IPv6 while its request names plain IPv4.
pub struct UdpClientEndpoint {
    peer: IpAddr,
    endpoint: Option<SocketAddr>,
}

impl UdpClientEndpoint {
    pub fn new(requested: &DatagramAddress, peer: IpAddr) -> io::Result<Self> {
        let peer = peer.to_canonical();
        let port = match requested {
            DatagramAddress::Domain(_, port) => *port,
            DatagramAddress::Ip(address)
                if address.ip().is_unspecified() || address.ip().to_canonical() == peer =>
            {
                address.port()
            }
            DatagramAddress::Ip(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 UDP endpoint must match TCP peer",
                ));
            }
        };
        Ok(Self {
            peer,
            endpoint: (port != 0).then(|| SocketAddr::new(peer, port)),
        })
    }

    pub fn accept(&mut self, source: SocketAddr) -> bool {
        let source = SocketAddr::new(source.ip().to_canonical(), source.port());
        if source.ip() != self.peer {
            return false;
        }
        match self.endpoint {
            Some(expected) => source == expected,
            None => {
                self.endpoint = Some(source);
                true
            }
        }
    }

    pub fn get(&self) -> Option<SocketAddr> {
        self.endpoint
    }
}

/// Where an association's datagrams go and come back from.
pub trait DatagramSource: Send {
    /// One RFC 1928 UDP packet addressed from its remote source.
    fn recv(&mut self) -> impl Future<Output = crate::Result<Cow<'_, [u8]>>> + Send;
}

pub trait DatagramSink: Send {
    /// Forward one RFC 1928 UDP packet. An error ends the association, so
    /// sinks absorb failures that only affect a single datagram.
    fn send(&mut self, packet: &[u8]) -> impl Future<Output = crate::Result<()>> + Send;
}

impl DatagramSource for DatagramRelayReader {
    async fn recv(&mut self) -> crate::Result<Cow<'_, [u8]>> {
        DatagramRelayReader::recv(self).await.map(Cow::Owned)
    }
}

impl DatagramSink for DatagramRelayWriter {
    async fn send(&mut self, packet: &[u8]) -> crate::Result<()> {
        DatagramRelayWriter::send(self, packet).await
    }
}

/// Datagram frames on an encrypted native session.
pub type NativeDatagramReader = DatagramTunnelReader<AsyncReader<tokio::io::ReadHalf<ProxyStream>>>;
pub type NativeDatagramWriter =
    DatagramTunnelWriter<AsyncWriter<tokio::io::WriteHalf<ProxyStream>>>;

impl DatagramSource for NativeDatagramReader {
    async fn recv(&mut self) -> crate::Result<Cow<'_, [u8]>> {
        self.recv_ref().await.map(Cow::Borrowed)
    }
}

impl DatagramSink for NativeDatagramWriter {
    async fn send(&mut self, packet: &[u8]) -> crate::Result<()> {
        DatagramTunnelWriter::send(self, packet).await
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UdpRelayReport {
    pub close_reason: &'static str,
    pub packets_up: u64,
    pub packets_down: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// From the first forwarded datagram to the first response.
    pub first_response: Option<Duration>,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum UdpRelayError {
    #[snafu(display("SOCKS5 UDP control connection failed"))]
    Control { source: io::Error },
    #[snafu(display("SOCKS5 UDP client socket failed"))]
    ClientSocket { source: io::Error },
    #[snafu(display("SOCKS5 UDP upstream failed"))]
    Upstream { source: ProxyError },
}

/// Relay one RFC 1928 UDP association until its TCP control connection ends,
/// the upstream disconnects, or it stays idle for `idle_timeout`.
///
/// Control closure is observed even while a datagram is being resolved or sent.
pub async fn relay_udp_association(
    control: &mut TcpStream,
    socket: &UdpSocket,
    endpoint: &mut UdpClientEndpoint,
    upstream_reader: &mut impl DatagramSource,
    upstream_writer: &mut impl DatagramSink,
    idle_timeout: Duration,
) -> Result<UdpRelayReport, UdpRelayError> {
    let mut report = UdpRelayReport::default();
    let relay = async {
        let mut buffer = vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE];
        let mut first_sent = None;
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                incoming = socket.recv_from(&mut buffer) => {
                    let (size, source) = match incoming {
                        Ok(received) => received,
                        // Windows reports an ICMP error for an earlier send here.
                        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => continue,
                        Err(source) => return Err(UdpRelayError::ClientSocket { source }),
                    };
                    let packet = &buffer[..size];
                    let payload = match parse_socks5_udp_packet(packet) {
                        Ok(parsed) => parsed.payload.len(),
                        Err(error) => {
                            tracing::debug!(%source, %error, "discarding malformed SOCKS5 UDP packet");
                            continue;
                        }
                    };
                    if !endpoint.accept(source) {
                        tracing::debug!(%source, "discarding SOCKS5 UDP packet from an unexpected client");
                        continue;
                    }
                    upstream_writer
                        .send(packet)
                        .await
                        .map_err(|source| UdpRelayError::Upstream { source })?;
                    first_sent.get_or_insert_with(Instant::now);
                    report.packets_up += 1;
                    report.bytes_up += payload as u64;
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                response = upstream_reader.recv() => {
                    let packet = match response {
                        Ok(packet) => packet,
                        Err(error) if error.is_expected_disconnect() => {
                            return Ok("upstream_disconnected");
                        }
                        Err(source) => return Err(UdpRelayError::Upstream { source }),
                    };
                    let payload = match parse_socks5_udp_packet(&packet) {
                        Ok(parsed) => parsed.payload.len(),
                        Err(error) => {
                            tracing::warn!(%error, "discarding malformed UDP packet from upstream");
                            continue;
                        }
                    };
                    let Some(client) = endpoint.get() else {
                        tracing::debug!("discarding UDP response before the client endpoint is known");
                        continue;
                    };
                    socket
                        .send_to(&packet, client)
                        .await
                        .map_err(|source| UdpRelayError::ClientSocket { source })?;
                    if report.first_response.is_none() {
                        report.first_response = first_sent.map(|sent: Instant| sent.elapsed());
                    }
                    report.packets_down += 1;
                    report.bytes_down += payload as u64;
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                () = &mut idle => return Ok("idle_timeout"),
            }
        }
    };
    let close_reason = tokio::select! {
        closed = watch_control(control) => closed?,
        relayed = relay => relayed?,
    };
    report.close_reason = close_reason;
    Ok(report)
}

/// RFC 1928 ties the association to its TCP connection. Stray bytes on it are
/// ignored rather than treated as closure.
async fn watch_control(control: &mut TcpStream) -> Result<&'static str, UdpRelayError> {
    let mut buffer = [0u8; 64];
    loop {
        match control.read(&mut buffer).await {
            Ok(0) => return Ok("tcp_control_closed"),
            Ok(_) => tracing::debug!("ignoring unexpected data on SOCKS5 UDP control connection"),
            Err(error) if crate::error::is_disconnect(&error) => {
                return Ok("tcp_control_disconnected");
            }
            Err(source) => return Err(UdpRelayError::Control { source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fragmented_requests_preserve_pipelined_bytes_and_address_families() {
        for address in [
            DatagramAddress::Ip("127.0.0.1:443".parse().unwrap()),
            DatagramAddress::Ip("[::1]:8443".parse().unwrap()),
            DatagramAddress::Domain("example.test".into(), 80),
        ] {
            let (mut client, mut server) = tokio::io::duplex(8);
            let mut frame = vec![5, CONNECT, 0];
            encode_socks5_address(&address, &mut frame).unwrap();
            frame.extend_from_slice(b"payload");
            let task = tokio::spawn(async move {
                for byte in frame {
                    client.write_all(&[byte]).await.unwrap();
                }
            });
            let request = read_request(&mut server).await.unwrap();
            assert_eq!(
                request,
                Request {
                    command: CONNECT,
                    address
                }
            );
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, b"payload");
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn malformed_headers_addresses_and_truncation_are_rejected() {
        for frame in [
            vec![4, 1, 0, 1, 127, 0, 0, 1, 0, 80],
            vec![5, 1, 1, 1, 127, 0, 0, 1, 0, 80],
            vec![5, 1, 0, 3, 0, 0, 80],
            vec![5, 1, 0, 3, 1, 255, 0, 80],
            vec![5, 1, 0, 9],
            vec![5, 1, 0, 1, 127],
        ] {
            assert!(read_request(&mut frame.as_slice()).await.is_err());
        }
    }

    #[test]
    fn udp_endpoint_is_pinned_to_tcp_peer_and_first_valid_source() {
        let peer = "127.0.0.1".parse().unwrap();
        let mut endpoint =
            UdpClientEndpoint::new(&DatagramAddress::Ip("0.0.0.0:0".parse().unwrap()), peer)
                .unwrap();
        assert!(!endpoint.accept("127.0.0.2:7000".parse().unwrap()));
        assert!(endpoint.accept("127.0.0.1:7000".parse().unwrap()));
        assert!(!endpoint.accept("127.0.0.1:7001".parse().unwrap()));
        assert!(endpoint.accept("127.0.0.1:7000".parse().unwrap()));
        assert!(
            UdpClientEndpoint::new(
                &DatagramAddress::Ip("127.0.0.2:7000".parse().unwrap()),
                peer
            )
            .is_err()
        );
        let mut pinned =
            UdpClientEndpoint::new(&DatagramAddress::Domain("client.test".into(), 7001), peer)
                .unwrap();
        assert!(!pinned.accept("127.0.0.1:7000".parse().unwrap()));
        assert!(pinned.accept("127.0.0.1:7001".parse().unwrap()));
    }

    #[test]
    fn dual_stack_peers_match_their_ipv4_requests_and_datagrams() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let mut endpoint = UdpClientEndpoint::new(
            &DatagramAddress::Ip("203.0.113.7:5000".parse().unwrap()),
            mapped,
        )
        .unwrap();
        assert!(endpoint.accept("[::ffff:203.0.113.7]:5000".parse().unwrap()));
        assert!(endpoint.accept("203.0.113.7:5000".parse().unwrap()));
        assert_eq!(endpoint.get(), Some("203.0.113.7:5000".parse().unwrap()));
    }

    #[test]
    fn non_public_destinations_and_sources_follow_policy() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
            "203.0.113.9",
        ] {
            assert!(!is_public_unicast(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public_unicast(public.parse().unwrap()), "{public}");
        }
        let mut config = Socks5Config::new(
            "0.0.0.0:1080".parse().unwrap(),
            "user".into(),
            "secret".into(),
        );
        assert!(!config.allows_destination("10.0.0.1".parse().unwrap()));
        assert!(config.allows_source("::ffff:10.0.0.1".parse().unwrap()));
        config
            .apply(Socks5Update {
                allow_private_destinations: Some(true),
                add_allowed_sources: vec!["10.0.0.9/8".parse().unwrap()],
                ..Default::default()
            })
            .unwrap();
        assert!(config.allows_destination("10.0.0.1".parse().unwrap()));
        assert_eq!(config.allowed_sources, vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(config.allows_source("::ffff:10.9.9.9".parse().unwrap()));
        assert!(!config.allows_source("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn updates_are_validated_atomically() {
        let mut config = Socks5Config::new(
            "0.0.0.0:1080".parse().unwrap(),
            "user".into(),
            "secret".into(),
        );
        let before = config.clone();
        assert!(
            config
                .apply(Socks5Update {
                    username: Some("next".into()),
                    max_sessions: Some(0),
                    ..Default::default()
                })
                .is_err()
        );
        assert_eq!(config, before);
        for invalid in ["host:0", "a b", "[::1", "user@host", "h:1:2"] {
            assert!(
                config
                    .apply(Socks5Update {
                        advertise: Some(invalid.into()),
                        ..Default::default()
                    })
                    .is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn endpoint_links_encode_credentials_and_prefer_advertised_addresses() {
        let mut config = Socks5Config::new(
            "0.0.0.0:1080".parse().unwrap(),
            "relay user".into(),
            "p@ss:word".into(),
        );
        assert_eq!(
            config.endpoint().url("2001:db8::1"),
            "socks5://relay%20user:p%40ss%3Aword@[2001:db8::1]:1080"
        );
        config.advertise = Some("proxy.example:443".into());
        assert_eq!(
            config.endpoint().url("10.0.0.1"),
            "socks5://relay%20user:p%40ss%3Aword@proxy.example:443"
        );
        config.advertise = Some("[2001:db8::2]".into());
        assert_eq!(
            config.endpoint().url("10.0.0.1"),
            "socks5://relay%20user:p%40ss%3Aword@[2001:db8::2]:1080"
        );
        assert!(config.same_listener(&Socks5Config {
            advertise: None,
            ..config.clone()
        }));
    }

    #[test]
    fn credentials_are_redacted_in_diagnostics_but_available_to_management() {
        let config = Socks5Config::new(
            "127.0.0.1:1080".parse().unwrap(),
            "user".into(),
            "private-test-value".into(),
        );
        assert!(!format!("{config:?}").contains(&config.password));
        assert!(!format!("{:?}", config.endpoint()).contains(&config.password));
        assert!(
            serde_json::to_string(&config)
                .unwrap()
                .contains(&config.password)
        );
    }

    #[test]
    fn earlier_state_files_load_with_default_policy() {
        let config: Socks5Config = serde_json::from_str(
            r#"{"enabled":true,"listen":"0.0.0.0:1080","username":"u","password":"p"}"#,
        )
        .unwrap();
        assert!(config.udp && !config.allow_private_destinations);
        assert_eq!(config.max_sessions, DEFAULT_MAX_SESSIONS);
    }

    #[test]
    fn new_control_operations_preserve_existing_wire_shapes() {
        use crate::control::{ControlOp, ControlRequest};
        let old: ControlRequest = serde_json::from_str(r#"{"token":null,"type":"ping"}"#).unwrap();
        assert_eq!(
            serde_json::to_value(old).unwrap(),
            serde_json::json!({"token":null,"type":"ping"})
        );
        let request: ControlRequest =
            serde_json::from_str(r#"{"token":null,"type":"set_socks5_enabled","enabled":true}"#)
                .unwrap();
        assert!(matches!(
            request.op,
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: None
            }
        ));
    }
}
