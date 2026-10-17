//! Application sessions always protect native proxy payloads. Runtime protocol
//! selection belongs here, not in HTTP, SOCKS, TUN, or the FFI probe.

use std::borrow::Cow;

use crate::protocol::{ProxyHeader, ProxyTransport};
use crate::secure_transport::{ProxyStream, WireProtocol};
use crate::transport::{Result, TransportError, get_proxy_stream};

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
        let legacy_key =
            (protocol == WireProtocol::Legacy).then(|| Cow::Owned(crate::config::gen_random_key()));
        let header = ProxyHeader {
            host: host.into(),
            port,
            key: legacy_key,
            transport,
        };
        let stream = get_proxy_stream(
            &header,
            node,
            node_port,
            "connect native proxy session",
            &format!("{host}:{port}"),
            protocol,
        )
        .await?;
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
