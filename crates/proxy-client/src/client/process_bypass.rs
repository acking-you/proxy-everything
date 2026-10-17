//! The local HTTP/SOCKS entry point uses the same owner matcher and physical
//! connector as TUN capture. Internal TUN connections are excluded by PID.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tun2proxy::direct::{self, BindInterface};

pub(super) struct LocalPolicy {
    pub matcher: tun2proxy::LocalProcessMatcher,
    pub virtual_dns: super::tun::TunVirtualDnsState,
    pub dns_fallback: IpAddr,
}

#[derive(Clone)]
pub(super) struct DirectRoute {
    iface: Arc<BindInterface>,
    virtual_dns: super::tun::TunVirtualDnsState,
    dns_fallback: IpAddr,
}

pub(super) async fn physical_interface(
    virtual_dns: super::tun::TunVirtualDnsState,
    dns_fallback: IpAddr,
) -> io::Result<DirectRoute> {
    let iface = tokio::task::spawn_blocking(|| {
        direct::detect(None, None)
            .map(Arc::new)
            .map_err(io::Error::other)
    })
    .await
    .map_err(io::Error::other)??;
    Ok(DirectRoute {
        iface,
        virtual_dns,
        dns_fallback,
    })
}

impl DirectRoute {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.resolve_address(SocketAddr::new(ip, port)).await;
        }
        self.resolve_domain(host, port).await
    }

    async fn resolve_address(&self, address: SocketAddr) -> io::Result<SocketAddr> {
        match self.virtual_dns.resolve_ip(address.ip()).await? {
            Some(domain) => self.resolve_domain(&domain, address.port()).await,
            None => Ok(address),
        }
    }

    async fn resolve_domain(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        // Loopback services must stay on loopback even for an excluded process.
        if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("localhost.") {
            return Ok(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
        }
        // Reuse the physical DNS path for names and old Fake-IP mappings.
        match direct::resolve_domain_bound(host, port, self.dns_fallback, false, &self.iface).await
        {
            Ok(address) => Ok(address),
            Err(error) if self.iface.ipv6_index == 0 => Err(error),
            Err(_) => {
                direct::resolve_domain_bound(host, port, self.dns_fallback, true, &self.iface).await
            }
        }
    }
}

pub(super) async fn connect(
    host: &str,
    port: u16,
    route: &DirectRoute,
) -> io::Result<tokio::net::TcpStream> {
    let address = route.resolve(host, port).await?;
    let iface = &route.iface;
    let started = std::time::Instant::now();
    let result = if address.ip().is_loopback() {
        tokio::net::TcpStream::connect(address).await
    } else {
        direct::connect_tcp_bound(address, iface).await
    };
    proxy_core::diagnostics::tcp_connect_finished(address, started.elapsed(), &result);
    let stream = result?;
    stream.set_nodelay(true)?;
    tracing::info!(host, port, destination = %address, local = ?stream.local_addr().ok(), interface = %iface,
        "excluded local proxy client connected directly");
    Ok(stream)
}

use proxy_core::datagram::{self, DatagramAddress, DatagramRelayReader, DatagramRelayWriter};

pub(super) struct UdpReader {
    physical: DatagramRelayReader,
    loopback: DatagramRelayReader,
}
pub(super) struct UdpWriter {
    physical: DatagramRelayWriter,
    loopback: DatagramRelayWriter,
    route: DirectRoute,
    resolved: std::collections::HashMap<String, (std::time::Instant, IpAddr)>,
}

pub(super) async fn udp_relay(route: &DirectRoute) -> proxy_core::Result<(UdpReader, UdpWriter)> {
    let iface = &route.iface;
    let v4 = direct::bind_udp_unconnected(false, iface).map_err(|source| {
        proxy_core::ProxyError::Io {
            context: "udp_bypass",
            detail: format!("bind IPv4 to {iface}"),
            source,
        }
    })?;
    let v6 = if iface.ipv6_index != 0 {
        direct::bind_udp_unconnected(true, iface).ok()
    } else {
        None
    };
    let (physical_reader, physical_writer, _) =
        datagram::create_direct_datagram_relay_with_sockets(v4, v6).into_parts();
    // Loopback is intentionally separate; forcing it onto a physical NIC can
    // break local services on Windows/macOS. Both relays validate reply peers.
    let (loopback_reader, loopback_writer, _) =
        datagram::create_direct_datagram_relay().await?.into_parts();
    Ok((
        UdpReader {
            physical: physical_reader,
            loopback: loopback_reader,
        },
        UdpWriter {
            physical: physical_writer,
            loopback: loopback_writer,
            route: route.clone(),
            resolved: Default::default(),
        },
    ))
}

impl UdpReader {
    pub(super) async fn recv(&mut self) -> proxy_core::Result<Vec<u8>> {
        tokio::select! { result = self.physical.recv() => result, result = self.loopback.recv() => result }
    }
}

impl UdpWriter {
    pub(super) async fn send(&mut self, bytes: &[u8]) -> proxy_core::Result<()> {
        let packet = datagram::parse_socks5_udp_packet(bytes)?;
        let destination = match &packet.destination {
            DatagramAddress::Ip(address) => {
                self.route
                    .resolve_address(*address)
                    .await
                    .map_err(|source| proxy_core::ProxyError::Io {
                        context: "udp_bypass",
                        detail: format!("restore {address}"),
                        source,
                    })?
            }
            DatagramAddress::Domain(host, port)
                if host.eq_ignore_ascii_case("localhost")
                    || host.eq_ignore_ascii_case("localhost.") =>
            {
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, *port))
            }
            DatagramAddress::Domain(host, port) => {
                match self
                    .resolved
                    .get(host)
                    .filter(|(time, _)| time.elapsed() < std::time::Duration::from_secs(30))
                {
                    Some((_, ip)) => SocketAddr::new(*ip, *port),
                    None => {
                        let address = self.route.resolve(host, *port).await.map_err(|source| {
                            proxy_core::ProxyError::Io {
                                context: "udp_bypass_dns",
                                detail: format!("resolve {host}:{port} via {}", self.route.iface),
                                source,
                            }
                        })?;
                        if self.resolved.len() >= 256 {
                            self.resolved.clear();
                        }
                        self.resolved
                            .insert(host.clone(), (std::time::Instant::now(), address.ip()));
                        address
                    }
                }
            }
        };
        let packet =
            datagram::encode_socks5_udp_packet(&DatagramAddress::Ip(destination), packet.payload)?;
        let writer = if destination.ip().is_loopback() {
            &self.loopback
        } else {
            &self.physical
        };
        writer.send(&packet).await
    }
}
