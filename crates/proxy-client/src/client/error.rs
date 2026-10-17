//! Errors retain typed sources across frontend, transport, and relay boundaries.
use snafu::Snafu;

use super::http::HttpProxyError;
use super::socks::SocksError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ClientError {
    #[snafu(display("I/O failure for {uri:?}: {detail}"))]
    Io {
        uri: Option<String>,
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Forwarding to {uri} failed"))]
    Proxy {
        uri: String,
        source: proxy_core::ProxyError,
    },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Auto-proxy decision channel closed for {uri}"))]
    ReceiveAutoProxy { uri: String },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Cannot proxy the local endpoint 127.0.0.1:{port}"))]
    LocalHost { port: u16 },
    #[snafu(display("HTTP frontend failed"))]
    HttpProxy { source: HttpProxyError },
    #[snafu(display("SOCKS frontend failed"))]
    SocksProxy { source: SocksError },
    #[snafu(display("Upstream transport failed"))]
    Transport {
        source: proxy_core::transport::TransportError,
    },
    #[snafu(display("UDP proxy error"))]
    Datagram { source: proxy_core::ProxyError },
    #[snafu(display("Failed to register shutdown signals"))]
    RegisterSignal,
}
