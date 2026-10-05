//! SOCKS5 UDP datagram parsing and transport primitives.
//!
//! UDP keeps message boundaries while the proxy protocol uses TCP tunnels. This
//! module centralizes the framing needed to preserve those boundaries and the
//! direct/SOCKS5 relay implementations shared by the client and server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::{FrameReader, FrameWriter};
use crate::relay::{ExternalProxyKind, ExternalProxyTarget};
use crate::{MyAsyncReadExt, MyAsyncWriteExt, ProxyError};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERNAME_PASSWORD: u8 = 0x02;
const SOCKS5_NO_ACCEPTABLE_METHOD: u8 = 0xff;
const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const AES_GCM_TAG_LEN: usize = 16;
#[cfg(test)]
const DATAGRAM_FRAME_PREFIX_SIZE: usize = 8;

/// Largest UDP packet accepted by the local SOCKS5 relay.
pub const MAX_SOCKS5_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;
/// Sent by the final proxy server after its UDP relay has been initialized.
pub const UDP_ASSOCIATION_READY: u8 = 0;
const MAX_DATAGRAM_TUNNEL_FRAME_SIZE: usize = MAX_SOCKS5_UDP_DATAGRAM_SIZE + AES_GCM_TAG_LEN;
const MAX_DIRECT_UDP_PEERS: usize = 4096;
const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SOCKS5_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_ASSOCIATION_IDLE_TIMEOUT_ENV: &str = "UDP_ASSOCIATION_IDLE_TIMEOUT_SECS";

/// Idle timeout shared by local and remote halves of a UDP association.
pub fn udp_association_idle_timeout() -> Duration {
    std::env::var(UDP_ASSOCIATION_IDLE_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .filter(|duration| !duration.is_zero())
        .unwrap_or(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT)
}

/// A destination encoded in a SOCKS5 request or UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DatagramAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl DatagramAddress {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    async fn resolve(&self) -> crate::Result<Vec<SocketAddr>> {
        match self {
            Self::Ip(addr) => Ok(vec![*addr]),
            Self::Domain(host, port) => {
                let addrs = crate::transport::resolve_host_addresses(host)
                    .await
                    .map_err(|source| ProxyError::Io {
                        context: "udp_resolve",
                        detail: format!("resolve {host}:{port}"),
                        source,
                    })?
                    .iter()
                    .map(|address| SocketAddr::new(*address, *port))
                    .collect::<Vec<_>>();
                tracing::debug!(host, port, ?addrs, "resolved SOCKS5 UDP destination");
                Ok(addrs)
            }
        }
    }
}

/// Borrowed view of an RFC 1928 SOCKS5 UDP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpPacket<'a> {
    pub destination: DatagramAddress,
    pub payload: &'a [u8],
}

/// Parse an RFC 1928 UDP request/response packet.
///
/// Fragmentation is deliberately rejected. RFC 1928 allows implementations to
/// drop fragmented packets, and silently reassembling them without bounded
/// state would make the relay vulnerable to memory exhaustion.
pub fn parse_socks5_udp_packet(data: &[u8]) -> crate::Result<Socks5UdpPacket<'_>> {
    if data.len() < 4 {
        return protocol_error("SOCKS5 UDP packet is shorter than its fixed header");
    }
    if data[0] != 0 || data[1] != 0 {
        return protocol_error("SOCKS5 UDP reserved bytes must be zero");
    }
    if data[2] != 0 {
        return protocol_error("SOCKS5 UDP fragmentation is not supported");
    }
    let (destination, consumed) = parse_socks5_address(&data[3..])?;
    Ok(Socks5UdpPacket {
        destination,
        payload: &data[3 + consumed..],
    })
}

/// Encode an RFC 1928 UDP request/response packet.
pub fn encode_socks5_udp_packet(
    address: &DatagramAddress,
    payload: &[u8],
) -> crate::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + 1 + 16 + 2 + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    encode_socks5_address(address, &mut packet)?;
    packet.extend_from_slice(payload);
    if packet.len() > MAX_SOCKS5_UDP_DATAGRAM_SIZE {
        return protocol_error("SOCKS5 UDP packet exceeds the maximum UDP datagram size");
    }
    Ok(packet)
}

/// Parse a SOCKS5 address beginning with ATYP and return the consumed length.
pub fn parse_socks5_address(data: &[u8]) -> crate::Result<(DatagramAddress, usize)> {
    let Some(&atyp) = data.first() else {
        return protocol_error("SOCKS5 address is missing ATYP");
    };
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            if data.len() < 7 {
                return protocol_error("truncated SOCKS5 IPv4 address");
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((DatagramAddress::Ip(SocketAddr::new(ip.into(), port)), 7))
        }
        SOCKS5_ATYP_IPV6 => {
            if data.len() < 19 {
                return protocol_error("truncated SOCKS5 IPv6 address");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                DatagramAddress::Ip(SocketAddr::new(Ipv6Addr::from(octets).into(), port)),
                19,
            ))
        }
        SOCKS5_ATYP_DOMAIN => {
            let Some(&domain_len) = data.get(1) else {
                return protocol_error("SOCKS5 domain address is missing its length");
            };
            let domain_len = domain_len as usize;
            let end = 2 + domain_len;
            if data.len() < end + 2 {
                return protocol_error("truncated SOCKS5 domain address");
            }
            let domain = std::str::from_utf8(&data[2..end])
                .map_err(|_| ProxyError::Protocol {
                    detail: "SOCKS5 domain address is not valid UTF-8".to_string(),
                })?
                .to_string();
            let port = u16::from_be_bytes([data[end], data[end + 1]]);
            Ok((DatagramAddress::Domain(domain, port), end + 2))
        }
        _ => protocol_error(format!("unsupported SOCKS5 address type {atyp:#x}")),
    }
}

/// Append a SOCKS5 ATYP/address/port tuple.
pub fn encode_socks5_address(address: &DatagramAddress, output: &mut Vec<u8>) -> crate::Result<()> {
    match address {
        DatagramAddress::Ip(SocketAddr::V4(addr)) => {
            output.push(SOCKS5_ATYP_IPV4);
            output.extend_from_slice(&addr.ip().octets());
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        DatagramAddress::Ip(SocketAddr::V6(addr)) => {
            output.push(SOCKS5_ATYP_IPV6);
            output.extend_from_slice(&addr.ip().octets());
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        DatagramAddress::Domain(domain, port) => {
            let len = u8::try_from(domain.len()).map_err(|_| ProxyError::Protocol {
                detail: "SOCKS5 domain address exceeds 255 bytes".to_string(),
            })?;
            output.extend_from_slice(&[SOCKS5_ATYP_DOMAIN, len]);
            output.extend_from_slice(domain.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// Reads datagram frames from a proxy TCP tunnel while preserving boundaries.
///
/// Each UDP packet is one existing proxy-protocol length frame. In encrypted
/// mode the frame body is `ciphertext || 16-byte GCM tag`; in plain mode it is
/// the RFC 1928 UDP packet verbatim. Framing packets individually is important:
/// treating the TCP tunnel as a byte stream would merge or split UDP messages.
pub struct DatagramTunnelReader<R> {
    frame: FrameReader<R>,
}

impl<R: MyAsyncReadExt + Send + Unpin> DatagramTunnelReader<R> {
    pub fn new(reader: R, key: Option<&str>) -> crate::Result<Self> {
        Ok(Self {
            frame: FrameReader::new(reader, key, MAX_DATAGRAM_TUNNEL_FRAME_SIZE)?,
        })
    }

    /// Receive an owned packet for callers that retain it beyond the next read.
    pub async fn recv(&mut self) -> crate::Result<Vec<u8>> {
        Ok(self.recv_ref().await?.to_vec())
    }

    /// Receive from the reusable frame buffer without copying the packet.
    /// Cancelling a pending receive retains its framing progress.
    pub async fn recv_ref(&mut self) -> crate::Result<&[u8]> {
        let packet = self
            .frame
            .read()
            .await?
            .ok_or_else(|| tunnel_eof("read datagram frame"))?;
        if packet.is_empty() || packet.len() > MAX_SOCKS5_UDP_DATAGRAM_SIZE {
            return protocol_error("invalid decrypted UDP tunnel frame size");
        }
        Ok(packet)
    }
}

/// Writes one length-delimited datagram per proxy TCP tunnel frame.
///
/// The encryptor and reusable frame buffer belong to the association. An
/// interrupted send is terminal so no new frame can follow a partial one.
pub struct DatagramTunnelWriter<W> {
    frame: FrameWriter<W>,
}

impl<W: MyAsyncWriteExt + Send + Unpin> DatagramTunnelWriter<W> {
    pub fn new(writer: W, key: Option<&str>) -> crate::Result<Self> {
        Ok(Self {
            frame: FrameWriter::new(writer, key, MAX_DATAGRAM_TUNNEL_FRAME_SIZE)?,
        })
    }

    pub async fn send(&mut self, packet: &[u8]) -> crate::Result<()> {
        if packet.is_empty() || packet.len() > MAX_SOCKS5_UDP_DATAGRAM_SIZE {
            return protocol_error(format!("invalid UDP tunnel datagram size {}", packet.len()));
        }
        self.frame.prepare()?.extend_from_slice(packet);
        self.frame.send().await
    }
}

/// Reader half for a direct UDP socket set or an upstream SOCKS5 association.
pub enum DatagramRelayReader {
    Direct(DirectDatagramReader),
    Socks5(Socks5DatagramReader),
}

impl DatagramRelayReader {
    pub async fn recv(&mut self) -> crate::Result<Vec<u8>> {
        match self {
            Self::Direct(reader) => reader.recv().await,
            Self::Socks5(reader) => reader.recv().await,
        }
    }
}

/// Writer half for a direct UDP socket set or an upstream SOCKS5 association.
pub enum DatagramRelayWriter {
    Direct(DirectDatagramWriter),
    Socks5(Socks5DatagramWriter),
}

impl DatagramRelayWriter {
    pub async fn send(&self, packet: &[u8]) -> crate::Result<()> {
        match self {
            Self::Direct(writer) => writer.send(packet).await,
            Self::Socks5(writer) => writer.send(packet).await,
        }
    }
}

/// A bidirectional UDP relay. The optional TCP control stream keeps an
/// upstream SOCKS5 UDP association alive for the lifetime of this value.
pub struct DatagramRelay {
    pub reader: DatagramRelayReader,
    pub writer: DatagramRelayWriter,
    _control_stream: Option<TcpStream>,
}

/// Keeps the control connection for an upstream UDP association alive.
pub struct DatagramRelayGuard {
    _control_stream: Option<TcpStream>,
}

impl DatagramRelay {
    pub fn into_parts(self) -> (DatagramRelayReader, DatagramRelayWriter, DatagramRelayGuard) {
        (
            self.reader,
            self.writer,
            DatagramRelayGuard {
                _control_stream: self._control_stream,
            },
        )
    }
}

/// Create a relay that sends UDP datagrams directly from this process.
pub async fn create_direct_datagram_relay() -> crate::Result<DatagramRelay> {
    let sockets = UdpSocketSet::bind().await?;
    tracing::info!(
        ipv4_socket = ?sockets.v4.local_addr().ok(),
        ipv6_socket = ?sockets.v6.as_ref().and_then(|socket| socket.local_addr().ok()),
        "direct UDP relay sockets initialized"
    );
    let peers = Arc::new(DashMap::new());
    Ok(DatagramRelay {
        reader: DatagramRelayReader::Direct(DirectDatagramReader {
            sockets: sockets.clone(),
            peers: peers.clone(),
            v4_buffer: vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE],
            v6_buffer: vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE],
        }),
        writer: DatagramRelayWriter::Direct(DirectDatagramWriter { sockets, peers }),
        _control_stream: None,
    })
}

/// Create an RFC 1928 UDP association through an external SOCKS5 proxy.
pub async fn create_socks5_datagram_relay(
    proxy: &ExternalProxyTarget,
) -> crate::Result<DatagramRelay> {
    tokio::time::timeout(
        SOCKS5_UDP_HANDSHAKE_TIMEOUT,
        create_socks5_datagram_relay_inner(proxy),
    )
    .await
    .map_err(|_| ProxyError::Protocol {
        detail: "upstream SOCKS5 UDP handshake timed out".to_string(),
    })?
}

async fn create_socks5_datagram_relay_inner(
    proxy: &ExternalProxyTarget,
) -> crate::Result<DatagramRelay> {
    if proxy.kind != ExternalProxyKind::Socks5 {
        return protocol_error("HTTP CONNECT proxies cannot relay UDP datagrams");
    }

    tracing::info!(
        upstream = %proxy.display_url(),
        remote_dns = proxy.remote_dns,
        password_auth_configured = proxy.username.is_some() && proxy.password.is_some(),
        "starting upstream SOCKS5 UDP ASSOCIATE handshake"
    );

    let mut control = crate::transport::get_tcp_stream(
        proxy.host.as_str(),
        proxy.port,
        "connect SOCKS5 UDP upstream",
    )
    .await
    .map_err(|error| ProxyError::IoSimple {
        context: "socks5_udp_upstream",
        detail: error.to_string(),
    })?;

    let use_password = proxy.username.is_some() && proxy.password.is_some();
    let greeting: &[u8] = if use_password {
        &[SOCKS5_VERSION, 2, SOCKS5_NO_AUTH, SOCKS5_USERNAME_PASSWORD]
    } else {
        &[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]
    };
    control
        .write_all(greeting)
        .await
        .map_err(|source| upstream_io("write SOCKS5 greeting", source))?;
    let mut method_reply = [0u8; 2];
    control
        .read_exact(&mut method_reply)
        .await
        .map_err(|source| upstream_io("read SOCKS5 method", source))?;
    if method_reply[0] != SOCKS5_VERSION || method_reply[1] == SOCKS5_NO_ACCEPTABLE_METHOD {
        return protocol_error("upstream SOCKS5 proxy rejected authentication methods");
    }
    match method_reply[1] {
        SOCKS5_NO_AUTH => {
            tracing::debug!("upstream SOCKS5 UDP proxy selected no-authentication");
        }
        SOCKS5_USERNAME_PASSWORD if use_password => {
            authenticate_socks5_password(&mut control, proxy).await?;
            tracing::debug!("upstream SOCKS5 UDP password authentication succeeded");
        }
        method => {
            return protocol_error(format!(
                "upstream SOCKS5 proxy selected unsupported method {method:#x}"
            ));
        }
    }

    let control_local = control
        .local_addr()
        .map_err(|source| upstream_io("read upstream SOCKS5 local address", source))?;
    let udp_bind = unspecified_addr(control_local.ip());
    let socket = Arc::new(
        UdpSocket::bind(udp_bind)
            .await
            .map_err(|source| upstream_io("bind SOCKS5 UDP socket", source))?,
    );
    let local_udp_addr = socket
        .local_addr()
        .map_err(|source| upstream_io("read SOCKS5 UDP socket address", source))?;
    let request_addr = DatagramAddress::Ip(local_udp_addr);
    let mut request = vec![SOCKS5_VERSION, SOCKS5_UDP_ASSOCIATE, 0];
    encode_socks5_address(&request_addr, &mut request)?;
    control
        .write_all(&request)
        .await
        .map_err(|source| upstream_io("write SOCKS5 UDP ASSOCIATE", source))?;

    let mut reply_prefix = [0u8; 3];
    control
        .read_exact(&mut reply_prefix)
        .await
        .map_err(|source| upstream_io("read SOCKS5 UDP ASSOCIATE reply", source))?;
    if reply_prefix[0] != SOCKS5_VERSION || reply_prefix[1] != 0 {
        return protocol_error(format!(
            "upstream SOCKS5 UDP ASSOCIATE failed with reply {:#x}",
            reply_prefix[1]
        ));
    }
    let relay_address = read_socks5_address(&mut control).await?;
    let relay_addr =
        resolve_relay_address(&relay_address, control.peer_addr().ok(), local_udp_addr).await?;

    tracing::info!(
        upstream = %proxy.display_url(),
        local_udp_addr = %local_udp_addr,
        relay_addr = %relay_addr,
        "upstream SOCKS5 UDP association is ready"
    );

    let reader = Socks5DatagramReader {
        socket: socket.clone(),
        relay_addr,
        buffer: vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE],
    };
    let writer = Socks5DatagramWriter {
        socket,
        relay_addr,
        remote_dns: proxy.remote_dns,
    };
    Ok(DatagramRelay {
        reader: DatagramRelayReader::Socks5(reader),
        writer: DatagramRelayWriter::Socks5(writer),
        _control_stream: Some(control),
    })
}

#[derive(Clone)]
struct UdpSocketSet {
    v4: Arc<UdpSocket>,
    v6: Option<Arc<UdpSocket>>,
}

impl UdpSocketSet {
    async fn bind() -> crate::Result<Self> {
        let v4 = Arc::new(
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .await
                .map_err(|source| ProxyError::Io {
                    context: "udp_relay",
                    detail: "bind IPv4 relay socket".to_string(),
                    source,
                })?,
        );
        let v6 = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(error) => {
                tracing::debug!(%error, "IPv6 UDP relay is unavailable");
                None
            }
        };
        Ok(Self { v4, v6 })
    }

    fn socket_for(&self, addr: SocketAddr) -> Option<&UdpSocket> {
        match addr {
            SocketAddr::V4(_) => Some(self.v4.as_ref()),
            SocketAddr::V6(_) => self.v6.as_deref(),
        }
    }
}

pub struct DirectDatagramReader {
    sockets: UdpSocketSet,
    peers: Arc<DashMap<SocketAddr, ()>>,
    v4_buffer: Vec<u8>,
    v6_buffer: Vec<u8>,
}

impl DirectDatagramReader {
    async fn recv(&mut self) -> crate::Result<Vec<u8>> {
        // Separate sockets avoid platform-specific dual-stack behavior. Some
        // operating systems default IPv6 sockets to v6-only while others map
        // IPv4 peers into IPv6 addresses, which would make peer validation
        // inconsistent across supported platforms.
        loop {
            let (size, source, is_v6) = match &self.sockets.v6 {
                Some(v6) => {
                    tokio::select! {
                        result = self.sockets.v4.recv_from(&mut self.v4_buffer) => {
                            let (size, source) = result.map_err(|source| ProxyError::Io {
                                context: "udp_relay",
                                detail: "receive IPv4 datagram".to_string(),
                                source,
                            })?;
                            (size, source, false)
                        }
                        result = v6.recv_from(&mut self.v6_buffer) => {
                            let (size, source) = result.map_err(|source| ProxyError::Io {
                                context: "udp_relay",
                                detail: "receive IPv6 datagram".to_string(),
                                source,
                            })?;
                            (size, source, true)
                        }
                    }
                }
                None => {
                    let (size, source) = self
                        .sockets
                        .v4
                        .recv_from(&mut self.v4_buffer)
                        .await
                        .map_err(|source| ProxyError::Io {
                            context: "udp_relay",
                            detail: "receive IPv4 datagram".to_string(),
                            source,
                        })?;
                    (size, source, false)
                }
            };
            if !self.peers.contains_key(&source) {
                tracing::debug!(%source, "discarding UDP response from an unknown peer");
                continue;
            }
            let payload = if is_v6 {
                &self.v6_buffer[..size]
            } else {
                &self.v4_buffer[..size]
            };
            tracing::debug!(
                direction = "remote_to_tunnel",
                remote = %source,
                payload_bytes = size,
                "received direct UDP response"
            );
            return encode_socks5_udp_packet(&DatagramAddress::Ip(source), payload);
        }
    }
}

pub struct DirectDatagramWriter {
    sockets: UdpSocketSet,
    peers: Arc<DashMap<SocketAddr, ()>>,
}

impl DirectDatagramWriter {
    async fn send(&self, packet: &[u8]) -> crate::Result<()> {
        let packet = parse_socks5_udp_packet(packet)?;
        let candidates = packet.destination.resolve().await?;
        let mut last_error = None;
        for destination in candidates {
            let Some(socket) = self.sockets.socket_for(destination) else {
                continue;
            };
            // Only destinations contacted by this association may send data
            // back. Besides rejecting unsolicited packets, the bounded set
            // prevents a local client from growing per-association state
            // indefinitely by cycling through arbitrary destination tuples.
            if !self.peers.contains_key(&destination) && self.peers.len() >= MAX_DIRECT_UDP_PEERS {
                return protocol_error("UDP association exceeded its destination limit");
            }
            match socket.send_to(packet.payload, destination).await {
                Ok(_) => {
                    self.peers.insert(destination, ());
                    tracing::debug!(
                        direction = "tunnel_to_remote",
                        remote = %destination,
                        payload_bytes = packet.payload.len(),
                        tracked_peers = self.peers.len(),
                        "sent direct UDP request"
                    );
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(source) => Err(ProxyError::Io {
                context: "udp_relay",
                detail: "send UDP datagram".to_string(),
                source,
            }),
            None => protocol_error("no compatible address is available for the UDP destination"),
        }
    }
}

pub struct Socks5DatagramReader {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    buffer: Vec<u8>,
}

impl Socks5DatagramReader {
    async fn recv(&mut self) -> crate::Result<Vec<u8>> {
        loop {
            let (size, source) = self
                .socket
                .recv_from(&mut self.buffer)
                .await
                .map_err(|source| upstream_io("receive upstream SOCKS5 UDP packet", source))?;
            if source != self.relay_addr {
                tracing::debug!(%source, expected = %self.relay_addr, "discarding packet from an unexpected SOCKS5 UDP relay");
                continue;
            }
            let packet = parse_socks5_udp_packet(&self.buffer[..size])?;
            tracing::debug!(
                direction = "upstream_socks5_to_tunnel",
                relay = %source,
                remote = ?packet.destination,
                payload_bytes = packet.payload.len(),
                "received UDP response from upstream SOCKS5 relay"
            );
            return Ok(self.buffer[..size].to_vec());
        }
    }
}

pub struct Socks5DatagramWriter {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    remote_dns: bool,
}

impl Socks5DatagramWriter {
    async fn send(&self, packet: &[u8]) -> crate::Result<()> {
        let parsed = parse_socks5_udp_packet(packet)?;
        let rewritten;
        let (output, address_rewritten) =
            if !self.remote_dns && matches!(parsed.destination, DatagramAddress::Domain(_, _)) {
                let destination = parsed
                    .destination
                    .resolve()
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| ProxyError::IoSimple {
                        context: "socks5_udp_upstream",
                        detail: "empty local DNS result".to_string(),
                    })?;
                rewritten =
                    encode_socks5_udp_packet(&DatagramAddress::Ip(destination), parsed.payload)?;
                (rewritten.as_slice(), true)
            } else {
                (packet, false)
            };
        self.socket
            .send_to(output, self.relay_addr)
            .await
            .map_err(|source| upstream_io("send upstream SOCKS5 UDP packet", source))?;
        tracing::debug!(
            direction = "tunnel_to_upstream_socks5",
            relay = %self.relay_addr,
            remote = ?parsed.destination,
            payload_bytes = parsed.payload.len(),
            remote_dns = self.remote_dns,
            address_rewritten,
            "sent UDP request through upstream SOCKS5 relay"
        );
        Ok(())
    }
}

async fn authenticate_socks5_password(
    control: &mut TcpStream,
    proxy: &ExternalProxyTarget,
) -> crate::Result<()> {
    let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
    let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
    let username_len = u8::try_from(username.len()).map_err(|_| ProxyError::Protocol {
        detail: "SOCKS5 username exceeds 255 bytes".to_string(),
    })?;
    let password_len = u8::try_from(password.len()).map_err(|_| ProxyError::Protocol {
        detail: "SOCKS5 password exceeds 255 bytes".to_string(),
    })?;
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[1, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    control
        .write_all(&request)
        .await
        .map_err(|source| upstream_io("write SOCKS5 password authentication", source))?;
    let mut response = [0u8; 2];
    control
        .read_exact(&mut response)
        .await
        .map_err(|source| upstream_io("read SOCKS5 password authentication", source))?;
    if response != [1, 0] {
        return protocol_error("upstream SOCKS5 username/password authentication failed");
    }
    Ok(())
}

async fn read_socks5_address(control: &mut TcpStream) -> crate::Result<DatagramAddress> {
    let atyp = control
        .read_u8()
        .await
        .map_err(|source| upstream_io("read SOCKS5 address type", source))?;
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            control
                .read_exact(&mut octets)
                .await
                .map_err(|source| upstream_io("read SOCKS5 IPv4 address", source))?;
            let port = control
                .read_u16()
                .await
                .map_err(|source| upstream_io("read SOCKS5 IPv4 port", source))?;
            Ok(DatagramAddress::Ip(SocketAddr::new(
                Ipv4Addr::from(octets).into(),
                port,
            )))
        }
        SOCKS5_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            control
                .read_exact(&mut octets)
                .await
                .map_err(|source| upstream_io("read SOCKS5 IPv6 address", source))?;
            let port = control
                .read_u16()
                .await
                .map_err(|source| upstream_io("read SOCKS5 IPv6 port", source))?;
            Ok(DatagramAddress::Ip(SocketAddr::new(
                Ipv6Addr::from(octets).into(),
                port,
            )))
        }
        SOCKS5_ATYP_DOMAIN => {
            let len = control
                .read_u8()
                .await
                .map_err(|source| upstream_io("read SOCKS5 domain length", source))?
                as usize;
            let mut domain = vec![0u8; len];
            control
                .read_exact(&mut domain)
                .await
                .map_err(|source| upstream_io("read SOCKS5 domain", source))?;
            let port = control
                .read_u16()
                .await
                .map_err(|source| upstream_io("read SOCKS5 domain port", source))?;
            let domain = String::from_utf8(domain).map_err(|_| ProxyError::Protocol {
                detail: "upstream SOCKS5 returned a non-UTF-8 domain".to_string(),
            })?;
            Ok(DatagramAddress::Domain(domain, port))
        }
        _ => protocol_error(format!(
            "upstream SOCKS5 returned unsupported address type {atyp:#x}"
        )),
    }
}

async fn resolve_relay_address(
    address: &DatagramAddress,
    control_peer: Option<SocketAddr>,
    local_udp_addr: SocketAddr,
) -> crate::Result<SocketAddr> {
    let mut candidates = address.resolve().await?;
    for candidate in &mut candidates {
        if candidate.ip().is_unspecified()
            && let Some(peer) = control_peer
        {
            candidate.set_ip(peer.ip());
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_ipv4() == local_udp_addr.is_ipv4())
        .ok_or_else(|| ProxyError::Protocol {
            detail: "upstream SOCKS5 returned an incompatible UDP relay address".to_string(),
        })
}

fn unspecified_addr(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    }
}

fn upstream_io(detail: &'static str, source: std::io::Error) -> ProxyError {
    ProxyError::Io {
        context: "socks5_udp_upstream",
        detail: detail.to_string(),
        source,
    }
}

fn protocol_error<T>(detail: impl Into<String>) -> crate::Result<T> {
    Err(ProxyError::Protocol {
        detail: detail.into(),
    })
}

fn tunnel_read_error(detail: &'static str, source: std::io::Error) -> ProxyError {
    ProxyError::Io {
        context: "udp_tunnel",
        detail: detail.to_string(),
        source,
    }
}

fn tunnel_eof(detail: &'static str) -> ProxyError {
    tunnel_read_error(
        detail,
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "proxy UDP tunnel closed during a datagram frame",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{AsyncReader, AsyncWriter};
    use crate::protocol::get_check_sum;

    #[test]
    fn socks5_udp_packet_round_trips_all_address_types() {
        let addresses = [
            DatagramAddress::Ip("127.0.0.1:53".parse().unwrap()),
            DatagramAddress::Ip("[::1]:5353".parse().unwrap()),
            DatagramAddress::Domain("example.com".to_string(), 443),
        ];
        for address in addresses {
            let encoded = encode_socks5_udp_packet(&address, b"payload").unwrap();
            let decoded = parse_socks5_udp_packet(&encoded).unwrap();
            assert_eq!(decoded.destination, address);
            assert_eq!(decoded.payload, b"payload");
        }
    }

    #[test]
    fn socks5_udp_packet_rejects_fragments_and_truncation() {
        assert!(parse_socks5_udp_packet(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53]).is_err());
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 3, 10, b'a']).is_err());
    }

    #[tokio::test]
    async fn encrypted_datagram_tunnel_preserves_boundaries() {
        let (left, right) = tokio::io::duplex(4096);
        let (_left_read, left_write) = tokio::io::split(left);
        let (right_read, _right_write) = tokio::io::split(right);
        let key = "01234567890123456789012345678901";
        let mut writer =
            DatagramTunnelWriter::new(AsyncWriter::new(left_write), Some(key)).unwrap();
        let mut reader =
            DatagramTunnelReader::new(AsyncReader::new(right_read), Some(key)).unwrap();
        let first = encode_socks5_udp_packet(
            &DatagramAddress::Domain("example.com".to_string(), 53),
            b"first",
        )
        .unwrap();
        let second = encode_socks5_udp_packet(
            &DatagramAddress::Ip("127.0.0.1:5353".parse().unwrap()),
            b"second",
        )
        .unwrap();

        writer.send(&first).await.unwrap();
        writer.send(&second).await.unwrap();
        assert_eq!(reader.recv().await.unwrap(), first);
        assert_eq!(reader.recv().await.unwrap(), second);
    }

    #[tokio::test]
    async fn plain_datagram_tunnel_preserves_boundaries() {
        let (left, right) = tokio::io::duplex(4096);
        let (_left_read, left_write) = tokio::io::split(left);
        let (right_read, _right_write) = tokio::io::split(right);
        let mut writer = DatagramTunnelWriter::new(AsyncWriter::new(left_write), None).unwrap();
        let mut reader = DatagramTunnelReader::new(AsyncReader::new(right_read), None).unwrap();
        let packet = encode_socks5_udp_packet(
            &DatagramAddress::Ip("127.0.0.1:53".parse().unwrap()),
            b"plain",
        )
        .unwrap();

        writer.send(&packet).await.unwrap();
        assert_eq!(reader.recv().await.unwrap(), packet);
    }

    #[tokio::test]
    async fn datagram_tunnel_resumes_after_prefix_read_is_cancelled() {
        let (mut wire_writer, wire_reader) = tokio::io::duplex(4096);
        let mut reader = DatagramTunnelReader::new(AsyncReader::new(wire_reader), None).unwrap();
        let packet = encode_socks5_udp_packet(
            &DatagramAddress::Domain("example.com".to_string(), 53),
            b"cancel-prefix",
        )
        .unwrap();
        let frame = plain_tunnel_frame(&packet);

        wire_writer.write_all(&frame[..3]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.recv())
                .await
                .is_err()
        );
        wire_writer.write_all(&frame[3..]).await.unwrap();

        assert_eq!(reader.recv().await.unwrap(), packet);
    }

    #[tokio::test]
    async fn datagram_tunnel_resumes_after_body_read_is_cancelled() {
        let (mut wire_writer, wire_reader) = tokio::io::duplex(4096);
        let mut reader = DatagramTunnelReader::new(AsyncReader::new(wire_reader), None).unwrap();
        let packet = encode_socks5_udp_packet(
            &DatagramAddress::Ip("127.0.0.1:53".parse().unwrap()),
            b"cancel-body",
        )
        .unwrap();
        let frame = plain_tunnel_frame(&packet);
        let split = DATAGRAM_FRAME_PREFIX_SIZE + 2;

        wire_writer.write_all(&frame[..split]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.recv())
                .await
                .is_err()
        );
        wire_writer.write_all(&frame[split..]).await.unwrap();

        assert_eq!(reader.recv().await.unwrap(), packet);
    }

    fn plain_tunnel_frame(packet: &[u8]) -> Vec<u8> {
        let size = packet.len() as u32;
        let mut frame = Vec::with_capacity(DATAGRAM_FRAME_PREFIX_SIZE + packet.len());
        frame.extend_from_slice(&get_check_sum(size).to_be_bytes());
        frame.extend_from_slice(&size.to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    #[tokio::test]
    async fn http_upstream_is_rejected_for_udp() {
        let proxy = ExternalProxyTarget::parse("http://127.0.0.1:8080").unwrap();
        let Err(error) = create_socks5_datagram_relay(&proxy).await else {
            panic!("HTTP upstream unexpectedly accepted UDP");
        };
        assert!(error.to_string().contains("cannot relay UDP"));
    }
}
