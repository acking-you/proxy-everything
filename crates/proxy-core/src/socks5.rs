//! Shared RFC 1928 request framing and managed-listener control types.

use std::net::SocketAddr;
use std::{fmt, io};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::datagram::{DatagramAddress, encode_socks5_address, parse_socks5_address};

pub const CONNECT: u8 = 1;
pub const UDP_ASSOCIATE: u8 = 3;

/// Persisted settings. The password is serialized only for explicit management
/// responses and the private state file; diagnostic formatting always redacts it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Config {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Config")
            .field("enabled", &self.enabled)
            .field("listen", &self.listen)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Status {
    pub config: Socks5Config,
    /// Distinguishes persisted intent from a listener that could not be restored.
    pub running: bool,
    pub last_error: Option<String>,
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
    if header[0] != 5 || header[2] != 0 {
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
        1 => (1, 6),
        4 => (1, 18),
        3 => {
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
    response.extend_from_slice(&[5, code, 0]);
    encode_socks5_address(&DatagramAddress::Ip(bound), &mut response).map_err(io::Error::other)?;
    writer.write_all(&response).await
}

/// Pins a UDP association to its authenticated TCP peer and one UDP endpoint.
/// Only call `accept` after validating the datagram, so malformed packets cannot
/// claim an association whose requested port was zero.
pub struct UdpClientEndpoint {
    peer: std::net::IpAddr,
    endpoint: Option<SocketAddr>,
}

impl UdpClientEndpoint {
    pub fn new(requested: &DatagramAddress, peer: std::net::IpAddr) -> io::Result<Self> {
        match requested {
            DatagramAddress::Domain(_, port) => Ok(Self {
                peer,
                endpoint: (*port != 0).then(|| SocketAddr::new(peer, *port)),
            }),
            DatagramAddress::Ip(address)
                if address.ip().is_unspecified() || address.ip() == peer =>
            {
                Ok(Self {
                    peer,
                    endpoint: (address.port() != 0).then(|| SocketAddr::new(peer, address.port())),
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 UDP endpoint must match TCP peer",
            )),
        }
    }

    pub fn accept(&mut self, source: SocketAddr) -> bool {
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
    fn credentials_are_redacted_in_diagnostics_but_available_to_management() {
        let config = Socks5Config {
            enabled: false,
            listen: "127.0.0.1:1080".parse().unwrap(),
            username: "user".into(),
            password: "private-test-value".into(),
        };
        assert!(!format!("{config:?}").contains(&config.password));
        assert!(
            serde_json::to_string(&config)
                .unwrap()
                .contains(&config.password)
        );
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
