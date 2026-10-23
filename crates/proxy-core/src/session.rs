//! Application sessions always protect native proxy payloads. Runtime protocol
//! selection belongs here, not in HTTP, SOCKS, TUN, or the FFI probe.

use std::borrow::Cow;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::ProxyError;
use crate::codec::{AsyncReader, AsyncWriter};
use crate::datagram::{DatagramTunnelReader, DatagramTunnelWriter, UDP_ASSOCIATION_READY};
use crate::protocol::{ProxyHeader, ProxyTransport};
use crate::secure_transport::{ProxyStream, WireProtocol};
use crate::socks5::{NativeDatagramReader, NativeDatagramWriter};
use crate::transport::{Result, TransportError, get_tcp_stream, setup_proxy_stream};

const UDP_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// An encrypted session to a native node. Legacy peers use their existing
/// payload frames; v3 protects the stream itself and needs no inner codec.
pub struct NativeSession {
    stream: ProxyStream,
    legacy_key: Option<Cow<'static, str>>,
}

impl NativeSession {
    pub async fn connect(
        host: &str,
        port: u16,
        node: &str,
        node_port: u16,
        transport: ProxyTransport,
    ) -> Result<Self> {
        let protocol = WireProtocol::configured().map_err(|source| TransportError::Io {
            uri: None,
            detail: "select native session protocol",
            source,
        })?;
        Self::connect_with_protocol(host, port, node, node_port, transport, protocol).await
    }

    pub async fn connect_with_protocol(
        host: &str,
        port: u16,
        node: &str,
        node_port: u16,
        transport: ProxyTransport,
        protocol: WireProtocol,
    ) -> Result<Self> {
        let stream = get_tcp_stream(node, node_port, "connect native proxy session").await?;
        Self::from_tcp_stream_with_protocol(host, port, transport, stream, protocol).await
    }

    /// Negotiate on a connection whose route and peer the caller has already
    /// selected. No DNS lookup or alternative connection can occur here.
    pub async fn from_tcp_stream(
        host: &str,
        port: u16,
        transport: ProxyTransport,
        stream: TcpStream,
    ) -> Result<Self> {
        let protocol = WireProtocol::configured().map_err(|source| TransportError::Io {
            uri: None,
            detail: "select native session protocol",
            source,
        })?;
        Self::from_tcp_stream_with_protocol(host, port, transport, stream, protocol).await
    }

    async fn from_tcp_stream_with_protocol(
        host: &str,
        port: u16,
        transport: ProxyTransport,
        stream: TcpStream,
        protocol: WireProtocol,
    ) -> Result<Self> {
        let legacy_key = match protocol {
            WireProtocol::Legacy => Some(Cow::Owned(crate::config::gen_random_key())),
            WireProtocol::V3 => None,
        };
        let header = ProxyHeader {
            host: host.into(),
            port,
            key: legacy_key,
            transport,
        };
        let stream =
            setup_proxy_stream(&header, stream, &format!("{host}:{port}"), protocol).await?;
        Ok(Self {
            stream,
            legacy_key: header.key,
        })
    }

    /// `None` means v3 already encrypts the stream, never plaintext native TCP.
    /// Datagram and stream codecs share the selected legacy key without
    /// allocating a second key or starting a second nonce sequence.
    pub fn into_parts(self) -> (ProxyStream, Option<Cow<'static, str>>) {
        (self.stream, self.legacy_key)
    }
}

impl NativeSession {
    /// Wait until the final server confirms the UDP association this session
    /// requested. No datagram is sent. `node` only labels errors.
    pub async fn confirm_udp(
        self,
        node: &str,
        node_port: u16,
    ) -> crate::Result<(ProxyStream, Option<Cow<'static, str>>)> {
        let (mut stream, key) = self.into_parts();
        let ready = match tokio::time::timeout(UDP_READY_TIMEOUT, stream.read_u8()).await {
            Err(_) => {
                return Err(ProxyError::Protocol {
                    detail: format!(
                        "remote proxy server {node}:{node_port} timed out before confirming UDP \
                         support; verify that the server is current and allows UDP egress"
                    ),
                });
            }
            Ok(Err(source)) if crate::error::is_disconnect(&source) => {
                return Err(ProxyError::Protocol {
                    detail: format!(
                        "remote proxy server {node}:{node_port} closed the UDP association before \
                         readiness; its binary likely predates UDP support or UDP relay \
                         initialization failed. Upgrade and restart http-proxy-server with the \
                         same release as this node"
                    ),
                });
            }
            Ok(Err(source)) => {
                return Err(ProxyError::Io {
                    context: "native_udp",
                    detail: "wait for remote UDP association readiness".into(),
                    source,
                });
            }
            Ok(Ok(ready)) => ready,
        };
        if ready != UDP_ASSOCIATION_READY {
            return Err(ProxyError::Protocol {
                detail: if ready == 1 {
                    "remote proxy server could not initialize its UDP relay; check server logs, \
                     firewall rules, and any configured upstream SOCKS5 UDP support"
                        .to_string()
                } else {
                    format!(
                        "remote proxy server returned unknown UDP association status {ready:#x}; \
                         node versions may be incompatible"
                    )
                },
            });
        }
        tracing::debug!(
            server = %format!("{node}:{node_port}"),
            "remote proxy server confirmed UDP association readiness"
        );
        Ok((stream, key))
    }

    /// Confirm the UDP association, then frame datagrams on this session.
    pub async fn into_datagram_tunnel(
        self,
        node: &str,
        node_port: u16,
    ) -> crate::Result<(NativeDatagramReader, NativeDatagramWriter)> {
        let (stream, key) = self.confirm_udp(node, node_port).await?;
        let (read, write) = stream.into_split();
        Ok((
            DatagramTunnelReader::new(AsyncReader::new(read), key.as_deref())?,
            DatagramTunnelWriter::new(AsyncWriter::new(write), key.as_deref())?,
        ))
    }
}
