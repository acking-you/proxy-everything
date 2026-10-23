//! Runtime wire selection and socket metadata around configuration-free crypto.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub use proxy_crypto::v3::{MAGIC, SecureStream, accept_v3, connect_v3};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::upstream::CarrierStream;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// An explicitly selected connection protocol. Legacy is the compatibility
/// default; authentication failures never trigger fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireProtocol {
    Legacy,
    V3,
}

static WIRE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Set the protocol for subsequent connections in the single-client FFI runtime.
/// Existing streams keep the protocol and keys chosen when they were created.
pub fn set_wire_protocol(protocol: WireProtocol) {
    WIRE_OVERRIDE.store(
        match protocol {
            WireProtocol::Legacy => 1,
            WireProtocol::V3 => 3,
        },
        std::sync::atomic::Ordering::Release,
    );
}

impl WireProtocol {
    /// Parse a stable FFI wire version without changing process configuration.
    pub fn from_version(version: i32) -> io::Result<Self> {
        match version {
            0 => Ok(Self::Legacy),
            3 => Ok(Self::V3),
            _ => Err(invalid("unsupported wire protocol")),
        }
    }

    pub fn configured() -> io::Result<Self> {
        match WIRE_OVERRIDE.load(std::sync::atomic::Ordering::Acquire) {
            1 => return Ok(Self::Legacy),
            3 => return Ok(Self::V3),
            _ => {}
        }
        match std::env::var("PROXY_WIRE_PROTOCOL").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("legacy") => Ok(Self::Legacy),
            Ok("v3") => Ok(Self::V3),
            _ => Err(invalid("PROXY_WIRE_PROTOCOL must be legacy or v3")),
        }
    }
}

/// TCP/QUIC or an authenticated v3 transport over either carrier. Splitting retains partial record
/// progress in the stream, independently of the lifetime of a read future.
pub enum ProxyStream {
    Plain {
        stream: CarrierStream,
        prefix: Vec<u8>,
        position: usize,
    },
    Secure(Box<SecureStream<CarrierStream>>),
}
impl From<TcpStream> for ProxyStream {
    fn from(stream: TcpStream) -> Self {
        Self::from(CarrierStream::from(stream))
    }
}
impl From<CarrierStream> for ProxyStream {
    fn from(stream: CarrierStream) -> Self {
        Self::Plain {
            stream,
            prefix: Vec::new(),
            position: 0,
        }
    }
}
impl ProxyStream {
    /// The local endpoint selected by the operating system for the TCP socket.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Self::Plain { stream, .. } => stream.local_addr(),
            Self::Secure(stream) => stream.get_ref().local_addr(),
        }
    }

    /// The connected TCP peer, independently of the destination inside the proxy.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Self::Plain { stream, .. } => stream.peer_addr(),
            Self::Secure(stream) => stream.get_ref().peer_addr(),
        }
    }

    /// Read-only endpoint, route and TCP statistics within a diagnostic scope.
    pub fn record_diagnostics(&self, observation: &'static str) {
        let socket = match self {
            Self::Plain { stream, .. } => stream,
            Self::Secure(stream) => stream.get_ref(),
        };
        socket.record_diagnostics(observation);
    }

    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }

    pub fn into_split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        tokio::io::split(self)
    }

    pub fn legacy_with_prefix(stream: impl Into<CarrierStream>, prefix: Vec<u8>) -> Self {
        Self::Plain {
            stream: stream.into(),
            prefix,
            position: 0,
        }
    }
}
impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain {
                stream,
                prefix,
                position,
            } => {
                if *position < prefix.len() && buf.remaining() > 0 {
                    let n = buf.remaining().min(prefix.len() - *position);
                    buf.put_slice(&prefix[*position..*position + n]);
                    *position += n;
                    Poll::Ready(Ok(()))
                } else {
                    Pin::new(stream).poll_read(cx, buf)
                }
            }
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_write(cx, buf),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_flush(cx),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_shutdown(cx),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_versions_are_explicit() {
        assert_eq!(WireProtocol::from_version(0).unwrap(), WireProtocol::Legacy);
        assert_eq!(WireProtocol::from_version(3).unwrap(), WireProtocol::V3);
        for version in [-1, 1, 2, 4] {
            assert!(WireProtocol::from_version(version).is_err());
        }
    }
}
