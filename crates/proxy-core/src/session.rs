//! Application sessions always protect native proxy payloads. Runtime protocol
//! selection belongs here, not in HTTP, SOCKS, TUN, or the FFI probe.

use std::borrow::Cow;

use tokio::net::TcpStream;

use crate::protocol::{ProxyHeader, ProxyTransport};
use crate::secure_transport::{ProxyStream, WireProtocol};
use crate::transport::{Result, TransportError, get_tcp_stream, setup_proxy_stream};

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
