//! The local HTTP/SOCKS entry point uses the same owner matcher and physical
//! connector as TUN capture. Internal TUN connections are excluded by PID.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_core::datagram::{self, DatagramAddress, DatagramRelayReader, DatagramRelayWriter};
use tokio::sync::{OnceCell, oneshot};
use tun2proxy::direct::{self, BindInterface};

pub(super) struct LocalPolicy {
    pub matcher: tun2proxy::LocalProcessMatcher,
    pub virtual_dns: super::tun::TunVirtualDnsState,
    pub dns_fallback: IpAddr,
}

#[derive(Clone)]
pub(super) struct DirectRoute {
    iface: Arc<OnceCell<BindInterface>>,
    virtual_dns: super::tun::TunVirtualDnsState,
    dns_fallback: IpAddr,
}

impl DirectRoute {
    pub(super) fn new(virtual_dns: super::tun::TunVirtualDnsState, dns_fallback: IpAddr) -> Self {
        Self {
            iface: Arc::new(OnceCell::new()),
            virtual_dns,
            dns_fallback,
        }
    }

    async fn interface(&self) -> io::Result<&BindInterface> {
        // Local services must work even while no physical adapter is available.
        self.iface
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(|| direct::detect(None, None).map_err(io::Error::other))
                    .await
                    .map_err(io::Error::other)?
            })
            .await
    }

    async fn resolve(&self, host: &str, port: u16, ipv6: bool) -> io::Result<Option<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.resolve_address(SocketAddr::new(ip, port), ipv6).await;
        }
        self.resolve_domain(host, port, ipv6).await
    }

    async fn resolve_address(
        &self,
        mut address: SocketAddr,
        ipv6: bool,
    ) -> io::Result<Option<SocketAddr>> {
        address.set_ip(address.ip().to_canonical());
        match self.virtual_dns.resolve_ip(address.ip()).await? {
            Some(domain) => self.resolve_domain(&domain, address.port(), ipv6).await,
            None => Ok((address.is_ipv6() == ipv6).then_some(address)),
        }
    }

    async fn resolve_domain(
        &self,
        host: &str,
        port: u16,
        ipv6: bool,
    ) -> io::Result<Option<SocketAddr>> {
        if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("localhost.") {
            let ip = if ipv6 {
                Ipv6Addr::LOCALHOST.into()
            } else {
                Ipv4Addr::LOCALHOST.into()
            };
            return Ok(Some(SocketAddr::new(ip, port)));
        }
        let iface = self.interface().await?;
        if (ipv6 && iface.ipv6_index == 0) || (!ipv6 && iface.ipv4_index == 0) {
            return Ok(None);
        }
        // Resolve the next family only after the previous attempt fails. This
        // also covers A records that resolve successfully but cannot connect.
        direct::resolve_domain_bound(host, port, self.dns_fallback, ipv6, iface)
            .await
            .map(Some)
    }
}

pub(super) async fn connect(
    host: &str,
    port: u16,
    route: &DirectRoute,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no usable direct destination",
    );
    let mut connect_error = None;
    for ipv6 in [false, true] {
        let address = match route.resolve(host, port, ipv6).await {
            Ok(Some(address)) => address,
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(host, port, ipv6, %error, "direct destination resolution failed");
                last_error = error;
                continue;
            }
        };
        let iface = if address.ip().is_loopback() {
            None
        } else {
            Some(route.interface().await?)
        };
        let started = Instant::now();
        let result = match iface {
            Some(iface) => direct::connect_tcp_bound(address, iface).await,
            None => tokio::net::TcpStream::connect(address).await,
        };
        proxy_core::diagnostics::tcp_connect_finished(address, started.elapsed(), &result);
        match result {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                tracing::info!(host, port, destination = %address, local = ?stream.local_addr().ok(),
                    interface = iface.map(|iface| iface.name.as_str()).unwrap_or("loopback"),
                    interface_index = iface.map(|iface| if address.is_ipv6() { iface.ipv6_index } else { iface.ipv4_index }),
                    "excluded local proxy client connected directly");
                return Ok(stream);
            }
            Err(error) => connect_error = Some(error),
        }
    }
    // A missing AAAA record must not hide the preceding TCP failure.
    Err(connect_error.unwrap_or(last_error))
}

pub(super) struct UdpReader {
    physical: Option<DatagramRelayReader>,
    pending_physical: oneshot::Receiver<DatagramRelayReader>,
    loopback: DatagramRelayReader,
}
pub(super) struct UdpWriter {
    physical: Option<DatagramRelayWriter>,
    pending_physical: Option<oneshot::Sender<DatagramRelayReader>>,
    loopback: DatagramRelayWriter,
    route: DirectRoute,
    resolved: std::collections::HashMap<String, (Instant, IpAddr)>,
}

pub(super) async fn udp_relay(route: &DirectRoute) -> proxy_core::Result<(UdpReader, UdpWriter)> {
    // No physical socket is needed until the application sends a non-local
    // datagram. Each relay independently validates its response peers.
    let (loopback_reader, loopback_writer, _) =
        datagram::create_direct_datagram_relay().await?.into_parts();
    let (sender, receiver) = oneshot::channel();
    Ok((
        UdpReader {
            physical: None,
            pending_physical: receiver,
            loopback: loopback_reader,
        },
        UdpWriter {
            physical: None,
            pending_physical: Some(sender),
            loopback: loopback_writer,
            route: route.clone(),
            resolved: Default::default(),
        },
    ))
}

fn udp_error(detail: impl Into<String>, source: io::Error) -> proxy_core::ProxyError {
    proxy_core::ProxyError::Io {
        context: "udp_bypass",
        detail: detail.into(),
        source,
    }
}

impl UdpReader {
    pub(super) async fn recv(&mut self) -> proxy_core::Result<Vec<u8>> {
        let physical = async {
            let reader = match &mut self.physical {
                Some(reader) => reader,
                slot @ None => slot.insert((&mut self.pending_physical).await.map_err(|_| {
                    udp_error("physical relay closed", io::ErrorKind::BrokenPipe.into())
                })?),
            };
            // Awaiting the reader is cancellation-safe when loopback wins.
            reader.recv().await
        };
        tokio::select! { result = physical => result, result = self.loopback.recv() => result }
    }
}

impl UdpWriter {
    async fn send_to(&mut self, destination: SocketAddr, payload: &[u8]) -> proxy_core::Result<()> {
        let packet =
            datagram::encode_socks5_udp_packet(&DatagramAddress::Ip(destination), payload)?;
        if destination.ip().is_loopback() {
            return self.loopback.send(&packet).await;
        }
        let writer = match &mut self.physical {
            Some(writer) => writer,
            slot @ None => {
                let iface = self
                    .route
                    .interface()
                    .await
                    .map_err(|source| udp_error("select physical interface", source))?;
                let v4 = direct::bind_udp_unconnected(false, iface)
                    .map_err(|source| udp_error(format!("bind IPv4 to {iface}"), source))?;
                let v6 = if iface.ipv6_index != 0 {
                    direct::bind_udp_unconnected(true, iface).ok()
                } else {
                    None
                };
                let (reader, writer, _) =
                    datagram::create_direct_datagram_relay_with_sockets(v4, v6).into_parts();
                if let Some(sender) = self.pending_physical.take() {
                    sender.send(reader).map_err(|_| {
                        udp_error(
                            "physical relay reader closed",
                            io::ErrorKind::BrokenPipe.into(),
                        )
                    })?;
                }
                slot.insert(writer)
            }
        };
        writer.send(&packet).await
    }

    pub(super) async fn send(&mut self, bytes: &[u8]) -> proxy_core::Result<()> {
        let packet = datagram::parse_socks5_udp_packet(bytes)?;
        let mut send_error = None;
        if let DatagramAddress::Domain(host, port) = &packet.destination
            && let Some((_, ip)) = self
                .resolved
                .get(host)
                .filter(|(time, _)| time.elapsed() < Duration::from_secs(30))
        {
            match self
                .send_to(SocketAddr::new(*ip, *port), packet.payload)
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::debug!(host, port, %error, "cached direct UDP destination failed");
                    send_error = Some(error);
                    self.resolved.remove(host);
                }
            }
        }
        let mut last_error = udp_error(
            "no usable direct destination",
            io::ErrorKind::AddrNotAvailable.into(),
        );
        for ipv6 in [false, true] {
            let resolved = match &packet.destination {
                DatagramAddress::Ip(address) => self.route.resolve_address(*address, ipv6).await,
                DatagramAddress::Domain(host, port) => self.route.resolve(host, *port, ipv6).await,
            };
            let destination = match resolved {
                Ok(Some(address)) => address,
                Ok(None) => continue,
                Err(error) => {
                    last_error = udp_error(
                        format!("resolve {:?} (IPv6={ipv6})", packet.destination),
                        error,
                    );
                    tracing::debug!(error = %last_error, "direct UDP resolution failed");
                    continue;
                }
            };
            match self.send_to(destination, packet.payload).await {
                Ok(()) => {
                    if let DatagramAddress::Domain(host, _) = &packet.destination {
                        if self.resolved.len() >= 256 {
                            self.resolved
                                .retain(|_, (time, _)| time.elapsed() < Duration::from_secs(30));
                            if self.resolved.len() >= 256
                                && let Some(oldest) = self
                                    .resolved
                                    .iter()
                                    .min_by_key(|(_, (time, _))| *time)
                                    .map(|(host, _)| host.clone())
                            {
                                self.resolved.remove(&oldest);
                            }
                        }
                        self.resolved
                            .insert(host.clone(), (Instant::now(), destination.ip()));
                    }
                    return Ok(());
                }
                Err(error) => {
                    tracing::debug!(%destination, %error, "direct UDP send failed");
                    send_error = Some(error);
                }
            }
        }
        Err(send_error.unwrap_or(last_error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_connections_need_no_physical_interface_and_retry_ipv6() {
        let route = DirectRoute::new(Default::default(), "223.5.5.5".parse().unwrap());
        let listener = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        // Only ::1 listens on this port; the IPv4 attempt must fall back.
        let stream = connect("localhost", listener.local_addr().unwrap().port(), &route)
            .await
            .unwrap();
        assert!(stream.peer_addr().unwrap().is_ipv6());
        assert!(route.iface.get().is_none());
        drop(stream);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let stream = connect(
            "::ffff:127.0.0.1",
            listener.local_addr().unwrap().port(),
            &route,
        )
        .await
        .unwrap();
        assert!(stream.peer_addr().unwrap().ip().is_loopback());
        assert!(route.iface.get().is_none());
        let socket = tokio::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let (mut reader, mut writer) = udp_relay(&route).await.unwrap();
        let packet = datagram::encode_socks5_udp_packet(
            &DatagramAddress::Ip(socket.local_addr().unwrap()),
            b"local-udp",
        )
        .unwrap();
        writer.send(&packet).await.unwrap();
        let mut buffer = [0; 32];
        let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..size], peer).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), reader.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            datagram::parse_socks5_udp_packet(&response)
                .unwrap()
                .payload,
            b"local-udp"
        );
        assert!(route.iface.get().is_none());
        assert!(writer.physical.is_none());
    }
}
