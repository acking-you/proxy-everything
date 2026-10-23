//! The carrier to a native proxy, independent of the destination's TCP/UDP protocol.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Carrier {
    #[default]
    Tcp,
    Quic,
}

/// Immutable, per-dial choice. Bare addresses keep their historical TCP meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAddress {
    pub host: String,
    pub port: u16,
    pub carrier: Carrier,
}

impl UpstreamAddress {
    pub fn from_host(host: &str, port: u16) -> io::Result<Self> {
        let host = host.trim();
        if host.contains("://") {
            let url = reqwest::Url::parse(host).map_err(io::Error::other)?;
            let carrier = match url.scheme() {
                "tcp" => Carrier::Tcp,
                "quic" => Carrier::Quic,
                _ => return Err(invalid("native upstream scheme must be tcp or quic")),
            };
            if !url.username().is_empty()
                || url.password().is_some()
                || !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid(
                    "native upstream accepts only scheme, host and port",
                ));
            }
            Ok(Self {
                host: url
                    .host_str()
                    .ok_or_else(|| invalid("missing upstream host"))?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port: url.port().unwrap_or(port),
                carrier,
            })
        } else if host.is_empty()
            || host.contains(['/', '?', '#', '@'])
            || host.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            Err(invalid("invalid upstream host"))
        } else {
            Ok(Self {
                host: host.trim_start_matches('[').trim_end_matches(']').into(),
                port,
                carrier: Carrier::Tcp,
            })
        }
    }

    pub fn parse(addr: &str) -> io::Result<Self> {
        if addr.contains("://") {
            let endpoint = Self::from_host(addr, 0)?;
            return if endpoint.port == 0 {
                Err(invalid("upstream requires a nonzero port"))
            } else {
                Ok(endpoint)
            };
        }
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| invalid("upstream requires host:port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| invalid("invalid upstream port"))?;
        if port == 0 {
            return Err(invalid("upstream requires a nonzero port"));
        }
        Self::from_host(host, port)
    }

    /// Preserve the carrier through older host/port APIs without changing their ABI.
    pub fn qualified_host(&self) -> String {
        match self.carrier {
            Carrier::Tcp => self.host.clone(),
            Carrier::Quic if self.host.contains(':') => format!("quic://[{}]", self.host),
            Carrier::Quic => format!("quic://{}", self.host),
        }
    }

    pub async fn connect(&self) -> io::Result<CarrierStream> {
        match self.carrier {
            Carrier::Tcp => crate::transport::connect_tcp_host(&self.host, self.port)
                .await
                .map(Into::into),
            Carrier::Quic => crate::quic::connect(&self.host, self.port)
                .await
                .map(|stream| CarrierStream::Quic(Box::new(stream))),
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// An ordered byte stream. FIN closes only the write half on both carriers.
pub enum CarrierStream {
    Tcp(TcpStream),
    Quic(Box<crate::quic::QuicStream>),
}

impl From<TcpStream> for CarrierStream {
    fn from(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }
}

impl CarrierStream {
    pub fn carrier(&self) -> Carrier {
        match self {
            Self::Tcp(_) => Carrier::Tcp,
            Self::Quic(_) => Carrier::Quic,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(s) => s.local_addr(),
            Self::Quic(s) => Ok(s.local_addr()),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Tcp(s) => s.peer_addr(),
            Self::Quic(s) => Ok(s.peer_addr()),
        }
    }

    pub fn record_diagnostics(&self, observation: &'static str) {
        match self {
            Self::Tcp(s) => crate::diagnostics::record_socket(observation, s),
            Self::Quic(s) => s.record_diagnostics(observation),
        }
    }
}

impl AsyncRead for CarrierStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Quic(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for CarrierStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Quic(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Quic(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Quic(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn carrier_is_explicit_and_legacy_addresses_remain_tcp() {
        let tcp = UpstreamAddress::parse("[::1]:1081").unwrap();
        assert_eq!(tcp.carrier, Carrier::Tcp);
        assert_eq!(tcp.host, "::1");
        let quic = UpstreamAddress::parse("quic://[::1]:10811").unwrap();
        assert_eq!(quic.carrier, Carrier::Quic);
        assert_eq!(UpstreamAddress::parse("QUIC://[::1]:10811").unwrap(), quic);
        assert_eq!(
            UpstreamAddress::from_host(&quic.qualified_host(), quic.port).unwrap(),
            quic
        );
        assert!(UpstreamAddress::parse("quic://host").is_err());
        assert!(UpstreamAddress::parse("quic://user:password@host:10811").is_err());
        assert!(UpstreamAddress::parse("https://host:10811").is_err());
    }
}
