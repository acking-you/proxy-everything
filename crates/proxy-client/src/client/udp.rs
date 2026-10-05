//! SOCKS5 UDP ASSOCIATE lifecycle and local relay.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use proxy_core::ProxyError;
use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::config::runtime;
use proxy_core::datagram::{
    DatagramAddress, DatagramRelayGuard, DatagramRelayReader, DatagramRelayWriter,
    DatagramTunnelReader, DatagramTunnelWriter, MAX_SOCKS5_UDP_DATAGRAM_SIZE,
    UDP_ASSOCIATION_READY, create_socks5_datagram_relay, encode_socks5_address,
    parse_socks5_udp_packet, udp_association_idle_timeout,
};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::secure_transport::ProxyStream;
use snafu::ResultExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use super::{DatagramSnafu, ExternalProxySnafu, Forwarder, Result};

const UDP_ASSOCIATION_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

enum UpstreamReader {
    Proxy(Box<DatagramTunnelReader<AsyncReader<ReadHalf<ProxyStream>>>>),
    Socks5(DatagramRelayReader),
}

impl UpstreamReader {
    async fn recv(&mut self) -> std::result::Result<std::borrow::Cow<'_, [u8]>, ProxyError> {
        match self {
            Self::Proxy(reader) => reader.recv_ref().await.map(std::borrow::Cow::Borrowed),
            Self::Socks5(reader) => reader.recv().await.map(std::borrow::Cow::Owned),
        }
    }
}

enum UpstreamWriter {
    Proxy(Box<DatagramTunnelWriter<AsyncWriter<WriteHalf<ProxyStream>>>>),
    Socks5(DatagramRelayWriter),
}

impl UpstreamWriter {
    async fn send(&mut self, packet: &[u8]) -> std::result::Result<(), ProxyError> {
        match self {
            Self::Proxy(writer) => writer.send(packet).await,
            Self::Socks5(writer) => writer.send(packet).await,
        }
    }
}

/// A single SOCKS5 UDP association. The TCP control stream owns its lifetime.
pub struct UdpAssociation {
    control_stream: TcpStream,
    relay_socket: UdpSocket,
    client_ip: IpAddr,
    client_endpoint: Option<SocketAddr>,
    requested_port: u16,
    upstream_reader: UpstreamReader,
    upstream_writer: UpstreamWriter,
    _upstream_guard: Option<DatagramRelayGuard>,
}

impl UdpAssociation {
    pub async fn bind(
        control_stream: TcpStream,
        requested_client: DatagramAddress,
        msg_key: Option<Cow<'static, str>>,
        upstream_proxy: Option<&ExternalProxyTarget>,
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
        validate_requested_client(&requested_client, peer_addr.ip())?;
        let requested_port = requested_client.port();
        let client_endpoint =
            (requested_port != 0).then(|| SocketAddr::new(peer_addr.ip(), requested_port));

        let relay_socket = UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0))
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
        let (upstream_reader, upstream_writer, upstream_guard) = if let Some(proxy) = upstream_proxy
        {
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
            let mut stream = proxy_core::transport::get_udp_proxy_stream(
                server_endpoint.host.as_str(),
                server_endpoint.port,
                msg_key.clone(),
                "connect UDP association to proxy server",
            )
            .await
            .context(ExternalProxySnafu)?;
            let ready = match tokio::time::timeout(UDP_ASSOCIATION_SETUP_TIMEOUT, stream.read_u8())
                .await
            {
                Err(_) => {
                    return Err(super::ClientError::Datagram {
                        source: ProxyError::Protocol {
                            detail: format!(
                                "remote proxy server {}:{} timed out before confirming UDP \
                                 support; verify that the server is current and allows UDP egress",
                                server_endpoint.host, server_endpoint.port
                            ),
                        },
                    });
                }
                Ok(Err(source)) if is_expected_disconnect(&source) => {
                    return Err(super::ClientError::Datagram {
                        source: ProxyError::Protocol {
                            detail: format!(
                                "remote proxy server {}:{} closed the UDP association before \
                                 readiness; its binary likely predates UDP support or UDP relay \
                                 initialization failed. Upgrade and restart http-proxy-server \
                                 with the same release as this client",
                                server_endpoint.host, server_endpoint.port
                            ),
                        },
                    });
                }
                Ok(Err(source)) => {
                    return Err(super::ClientError::Io {
                        uri: None,
                        detail: "wait for remote UDP association readiness",
                        source,
                    });
                }
                Ok(Ok(ready)) => ready,
            };
            if ready != UDP_ASSOCIATION_READY {
                return Err(super::ClientError::Datagram {
                    source: ProxyError::Protocol {
                        detail: if ready == 1 {
                            "remote proxy server could not initialize its UDP relay; check server \
                             logs, firewall rules, and any configured upstream SOCKS5 UDP support"
                                .to_string()
                        } else {
                            format!(
                                "remote proxy server returned unknown UDP association status \
                                 {ready:#x}; client and server versions may be incompatible"
                            )
                        },
                    },
                });
            }
            tracing::debug!(
                server = %format!("{}:{}", server_endpoint.host, server_endpoint.port),
                datagram_encryption = msg_key.is_some(),
                "remote proxy server confirmed UDP association readiness"
            );
            let msg_key = if stream.is_secure() {
                None
            } else {
                msg_key.as_deref()
            };
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

        tracing::info!(
            tcp_peer = %peer_addr,
            requested_client = ?requested_client,
            local_udp_relay = %relay_addr,
            upstream = %upstream_proxy
                .map(ExternalProxyTarget::display_url)
                .unwrap_or_else(|| format!("proxy-server://{}:{}", server_endpoint.host, server_endpoint.port)),
            datagram_encryption = msg_key.is_some(),
            "SOCKS5 UDP association initialized"
        );

        Ok((
            Self {
                control_stream,
                relay_socket,
                client_ip: peer_addr.ip(),
                client_endpoint,
                requested_port,
                upstream_reader,
                upstream_writer,
                _upstream_guard: upstream_guard,
            },
            relay_addr,
        ))
    }

    pub async fn reply_success(&mut self, relay_addr: SocketAddr) -> Result<()> {
        let mut response = vec![0x05, 0x00, 0x00];
        encode_socks5_address(&DatagramAddress::Ip(relay_addr), &mut response)
            .context(DatagramSnafu)?;
        self.control_stream
            .write_all(&response)
            .await
            .map_err(|source| super::ClientError::Io {
                uri: None,
                detail: "send SOCKS5 UDP ASSOCIATE reply",
                source,
            })
    }

    async fn run(mut self) -> Result<()> {
        let mut local_buffer = vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE];
        let mut control_buffer = [0u8; 1];
        let mut packets_up = 0u64;
        let mut packets_down = 0u64;
        let mut bytes_up = 0u64;
        let mut bytes_down = 0u64;
        let idle_timeout = udp_association_idle_timeout();
        let idle_sleep = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle_sleep);

        // RFC 1928 ties the UDP relay lifetime to this TCP control stream. The
        // select loop therefore watches control EOF, local UDP, remote tunnel
        // traffic, and the idle timer as four independent termination sources.
        let close_reason = loop {
            tokio::select! {
                control = self.control_stream.read(&mut control_buffer) => {
                    match control {
                        Ok(0) => break "tcp_control_closed",
                        Ok(_) => {
                            tracing::debug!("ignoring unexpected data on SOCKS5 UDP control connection");
                        }
                        Err(error) if is_expected_disconnect(&error) => break "tcp_control_disconnected",
                        Err(source) => {
                            return Err(super::ClientError::Io {
                                uri: None,
                                detail: "read SOCKS5 UDP control connection",
                                source,
                            });
                        }
                    }
                }
                incoming = self.relay_socket.recv_from(&mut local_buffer) => {
                    let (size, source) = incoming.map_err(|source| super::ClientError::Io {
                        uri: None,
                        detail: "receive local SOCKS5 UDP packet",
                        source,
                    })?;
                    let packet = &local_buffer[..size];
                    let parsed = match parse_socks5_udp_packet(packet) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            tracing::debug!(%source, %error, "discarding malformed SOCKS5 UDP packet");
                            continue;
                        }
                    };
                    if !self.accept_client_endpoint(source) {
                        tracing::debug!(%source, "discarding SOCKS5 UDP packet from an unexpected client");
                        continue;
                    }
                    tracing::debug!(
                        direction = "client_to_upstream",
                        client = %source,
                        remote = ?parsed.destination,
                        payload_bytes = parsed.payload.len(),
                        "forwarding SOCKS5 UDP request"
                    );
                    self.upstream_writer
                        .send(packet)
                        .await
                        .context(DatagramSnafu)?;
                    packets_up = packets_up.saturating_add(1);
                    bytes_up = bytes_up.saturating_add(parsed.payload.len() as u64);
                    reset_idle(&mut idle_sleep, idle_timeout);
                }
                response = self.upstream_reader.recv() => {
                    let packet = match response {
                        Ok(packet) => packet,
                        Err(error) if error.is_expected_disconnect() => break "upstream_disconnected",
                        Err(error) => return Err(error).context(DatagramSnafu),
                    };
                    let parsed = match parse_socks5_udp_packet(&packet) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            tracing::warn!(%error, "discarding malformed UDP packet from upstream");
                            continue;
                        }
                    };
                    let Some(client_endpoint) = self.client_endpoint else {
                        tracing::debug!("discarding UDP response before the client endpoint is known");
                        continue;
                    };
                    self.relay_socket
                        .send_to(&packet, client_endpoint)
                        .await
                        .map_err(|source| super::ClientError::Io {
                            uri: None,
                            detail: "send SOCKS5 UDP response to client",
                            source,
                        })?;
                    tracing::debug!(
                        direction = "upstream_to_client",
                        client = %client_endpoint,
                        remote = ?parsed.destination,
                        payload_bytes = parsed.payload.len(),
                        "forwarded SOCKS5 UDP response"
                    );
                    packets_down = packets_down.saturating_add(1);
                    bytes_down = bytes_down.saturating_add(parsed.payload.len() as u64);
                    reset_idle(&mut idle_sleep, idle_timeout);
                }
                _ = &mut idle_sleep => {
                    tracing::debug!(?idle_timeout, "SOCKS5 UDP association expired after being idle");
                    break "idle_timeout";
                }
            }
        };
        tracing::info!(
            close_reason,
            client = ?self.client_endpoint,
            packets_up,
            packets_down,
            bytes_up,
            bytes_down,
            "SOCKS5 UDP association closed"
        );
        Ok(())
    }

    fn accept_client_endpoint(&mut self, source: SocketAddr) -> bool {
        if source.ip() != self.client_ip {
            return false;
        }
        if self.requested_port != 0 && source.port() != self.requested_port {
            return false;
        }
        match self.client_endpoint {
            Some(endpoint) => endpoint == source,
            None => {
                self.client_endpoint = Some(source);
                tracing::info!(
                    client = %source,
                    "pinned SOCKS5 UDP association to its first valid client endpoint"
                );
                true
            }
        }
    }
}

impl Forwarder for UdpAssociation {
    async fn forward(self) -> Result<()> {
        self.run().await
    }
}

fn validate_requested_client(address: &DatagramAddress, peer_ip: IpAddr) -> Result<()> {
    if let DatagramAddress::Ip(address) = address
        && !address.ip().is_unspecified()
        && address.ip() != peer_ip
    {
        return Err(super::ClientError::Datagram {
            source: ProxyError::Protocol {
                detail: "SOCKS5 UDP client address does not match the TCP peer".to_string(),
            },
        });
    }
    Ok(())
}

fn reset_idle(sleep: &mut std::pin::Pin<&mut tokio::time::Sleep>, timeout: std::time::Duration) {
    sleep.as_mut().reset(Instant::now() + timeout);
}

fn is_expected_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
    )
}
