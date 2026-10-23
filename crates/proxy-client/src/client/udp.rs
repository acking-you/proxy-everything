//! SOCKS5 UDP ASSOCIATE lifecycle and local relay.

use std::net::SocketAddr;

use proxy_core::ProxyError;
use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::config::runtime;
use proxy_core::datagram::{
    DatagramAddress, DatagramRelayGuard, DatagramRelayReader, DatagramRelayWriter,
    DatagramTunnelReader, DatagramTunnelWriter, create_socks5_datagram_relay,
    udp_association_idle_timeout,
};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::secure_transport::ProxyStream;
use proxy_core::socks5::{
    DatagramSink, DatagramSource, NativeDatagramReader, NativeDatagramWriter, UdpRelayError,
    relay_udp_association,
};
use snafu::ResultExt;
use tokio::net::{TcpStream, UdpSocket};

use super::{DatagramSnafu, Forwarder, Result, TransportSnafu};

/// Establish and confirm the same native UDP association used by SOCKS5 and
/// by a live node-switch probe. No datagram is sent by the probe.
pub(super) async fn connect_native_udp(
    host: &str,
    port: u16,
) -> Result<(ProxyStream, Option<std::borrow::Cow<'static, str>>)> {
    let session = proxy_core::session::NativeSession::connect(
        "",
        0,
        host,
        port,
        proxy_core::ProxyTransport::UdpAssociate,
    )
    .await
    .context(TransportSnafu)?;
    confirm_native_udp(session, host, port).await
}

pub(super) async fn confirm_native_udp(
    session: proxy_core::session::NativeSession,
    host: &str,
    port: u16,
) -> Result<(ProxyStream, Option<std::borrow::Cow<'static, str>>)> {
    session.confirm_udp(host, port).await.context(DatagramSnafu)
}

enum UpstreamReader {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    Direct(super::process_bypass::UdpReader),
    Proxy(Box<NativeDatagramReader>),
    Socks5(DatagramRelayReader),
}

impl DatagramSource for UpstreamReader {
    async fn recv(&mut self) -> std::result::Result<std::borrow::Cow<'_, [u8]>, ProxyError> {
        match self {
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            Self::Direct(reader) => reader.recv().await.map(std::borrow::Cow::Owned),
            Self::Proxy(reader) => reader.recv_ref().await.map(std::borrow::Cow::Borrowed),
            Self::Socks5(reader) => reader.recv().await.map(std::borrow::Cow::Owned),
        }
    }
}

enum UpstreamWriter {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    Direct(super::process_bypass::UdpWriter),
    Proxy(Box<NativeDatagramWriter>),
    Socks5(DatagramRelayWriter),
}

impl DatagramSink for UpstreamWriter {
    async fn send(&mut self, packet: &[u8]) -> std::result::Result<(), ProxyError> {
        match self {
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            Self::Direct(writer) => writer.send(packet).await,
            Self::Proxy(writer) => writer.send(packet).await,
            Self::Socks5(writer) => writer.send(packet).await,
        }
    }
}

/// A single SOCKS5 UDP association. The TCP control stream owns its lifetime.
pub struct UdpAssociation {
    control_stream: TcpStream,
    relay_socket: UdpSocket,
    client_endpoint: proxy_core::socks5::UdpClientEndpoint,
    upstream_reader: UpstreamReader,
    upstream_writer: UpstreamWriter,
    _upstream_guard: Option<DatagramRelayGuard>,
}

impl UdpAssociation {
    pub(super) async fn bind(
        control_stream: TcpStream,
        requested_client: DatagramAddress,
        upstream_proxy: Option<&ExternalProxyTarget>,
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        direct_interface: Option<&super::process_bypass::DirectRoute>,
    ) -> Result<(Self, SocketAddr)> {
        let peer_addr = control_stream
            .peer_addr()
            .map_err(|source| super::ClientError::Io {
                uri: None,
                detail: "read SOCKS5 TCP peer address",
                source,
            })?;
        let local_addr = control_stream
            .local_addr()
            .map_err(|source| super::ClientError::Io {
                uri: None,
                detail: "read SOCKS5 TCP local address",
                source,
            })?;
        let client_endpoint =
            proxy_core::socks5::UdpClientEndpoint::new(&requested_client, peer_addr.ip()).map_err(
                |source| super::ClientError::Io {
                    uri: None,
                    detail: "validate SOCKS5 UDP client endpoint",
                    source,
                },
            )?;

        // A dual-stack listener reports IPv4 clients as IPv4-mapped IPv6.
        let relay_socket = UdpSocket::bind(SocketAddr::new(local_addr.ip().to_canonical(), 0))
            .await
            .map_err(|source| super::ClientError::Io {
                uri: None,
                detail: "bind local SOCKS5 UDP relay",
                source,
            })?;
        let relay_addr = relay_socket
            .local_addr()
            .map_err(|source| super::ClientError::Io {
                uri: None,
                detail: "read local SOCKS5 UDP relay address",
                source,
            })?;

        // A UDP association remains pinned to the endpoint generation active
        // when its TCP control connection was accepted.
        let server_endpoint = runtime::server_endpoint();
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let direct = match direct_interface {
            Some(iface) => Some(
                super::process_bypass::udp_relay(iface)
                    .await
                    .context(DatagramSnafu)?,
            ),
            None => None,
        };
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        let direct: Option<(UpstreamReader, UpstreamWriter)> = None;
        let (upstream_reader, upstream_writer, upstream_guard) =
            if let Some((reader, writer)) = direct {
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                {
                    (
                        UpstreamReader::Direct(reader),
                        UpstreamWriter::Direct(writer),
                        None,
                    )
                }
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                {
                    (reader, writer, None)
                }
            } else if let Some(proxy) = upstream_proxy {
                let relay = create_socks5_datagram_relay(proxy)
                    .await
                    .context(DatagramSnafu)?;
                let (reader, writer, guard) = relay.into_parts();
                (
                    UpstreamReader::Socks5(reader),
                    UpstreamWriter::Socks5(writer),
                    Some(guard),
                )
            } else {
                let (stream, msg_key) =
                    connect_native_udp(&server_endpoint.host, server_endpoint.port).await?;
                let msg_key = msg_key.as_deref();
                let (read_half, write_half) = stream.into_split();
                (
                    UpstreamReader::Proxy(Box::new(
                        DatagramTunnelReader::new(AsyncReader::new(read_half), msg_key)
                            .context(DatagramSnafu)?,
                    )),
                    UpstreamWriter::Proxy(Box::new(
                        DatagramTunnelWriter::new(AsyncWriter::new(write_half), msg_key)
                            .context(DatagramSnafu)?,
                    )),
                    None,
                )
            };

        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let direct = matches!(&upstream_reader, UpstreamReader::Direct(_));
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        let direct = false;
        tracing::info!(
            tcp_peer = %peer_addr,
            requested_client = ?requested_client,
            local_udp_relay = %relay_addr,
            upstream = %if direct { "physical-interface".to_string() } else { upstream_proxy
                .map(ExternalProxyTarget::display_url)
                .unwrap_or_else(|| format!("proxy-server://{}:{}", server_endpoint.host, server_endpoint.port)) },
            native_encrypted = !direct && upstream_proxy.is_none(),
            "SOCKS5 UDP association initialized"
        );

        Ok((
            Self {
                control_stream,
                relay_socket,
                client_endpoint,
                upstream_reader,
                upstream_writer,
                _upstream_guard: upstream_guard,
            },
            relay_addr,
        ))
    }

    pub async fn reply_success(&mut self, relay_addr: SocketAddr) -> Result<()> {
        proxy_core::socks5::write_reply(
            &mut self.control_stream,
            proxy_core::socks5::reply::SUCCEEDED,
            relay_addr,
        )
        .await
        .map_err(|source| super::ClientError::Io {
            uri: None,
            detail: "send SOCKS5 UDP ASSOCIATE reply",
            source,
        })
    }

    async fn run(mut self) -> Result<()> {
        let report = relay_udp_association(
            &mut self.control_stream,
            &self.relay_socket,
            &mut self.client_endpoint,
            &mut self.upstream_reader,
            &mut self.upstream_writer,
            udp_association_idle_timeout(),
        )
        .await
        .map_err(|error| match error {
            UdpRelayError::Upstream { source } => super::ClientError::Datagram { source },
            UdpRelayError::Control { source } => super::ClientError::Io {
                uri: None,
                detail: "read SOCKS5 UDP control connection",
                source,
            },
            UdpRelayError::ClientSocket { source } => super::ClientError::Io {
                uri: None,
                detail: "relay local SOCKS5 UDP packet",
                source,
            },
        })?;
        tracing::info!(
            close_reason = report.close_reason,
            client = ?self.client_endpoint.get(),
            packets_up = report.packets_up,
            packets_down = report.packets_down,
            bytes_up = report.bytes_up,
            bytes_down = report.bytes_down,
            "SOCKS5 UDP association closed"
        );
        Ok(())
    }
}

impl Forwarder for UdpAssociation {
    async fn forward(self) -> Result<()> {
        self.run().await
    }
}
