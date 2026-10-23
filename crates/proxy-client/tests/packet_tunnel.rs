#![cfg(feature = "network-extension")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use proxy_client::client::packet_tunnel::{PacketTunnelConfig, PacketTunnelRuntime, PacketWrite};
use proxy_core::config::DEFAULT_SECRET_KEY;
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

static RUNTIME_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn send(tunnel: &PacketTunnelRuntime, packet: &[u8]) {
    assert_eq!(tunnel.write_packet(packet).unwrap(), PacketWrite::Queued);
}

#[track_caller]
fn receive(tunnel: &PacketTunnelRuntime, accept: impl Fn(&SlicedPacket<'_>) -> bool) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(packet) = tunnel.read_packet(Duration::from_millis(100)).unwrap()
            && accept(&SlicedPacket::from_ip(&packet).unwrap())
        {
            return packet;
        }
    }
    panic!(
        "no matching packet before deadline: {:?}",
        tunnel.last_error()
    );
}

/// The real packet adapter, IP stack, SOCKS listener and server are exercised
/// entirely on loopback. No OS tunnel, routes, DNS or public service is touched.
#[test]
fn provider_forwards_encrypted_tcp_dns_and_local_udp_and_stops() {
    packet_round_trips(false, false);
    packet_round_trips(false, true);
}

#[test]
#[ignore = "requires ICMP sockets; run inside an isolated network namespace"]
fn provider_forwards_real_echo_v4_v6_legacy_and_v3() {
    packet_round_trips(true, false);
}

fn packet_round_trips(with_echo: bool, auto_proxy: bool) {
    let _guard = RUNTIME_CONFIG_LOCK.lock().unwrap();
    struct TestLog;
    impl log::Log for TestLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            eprintln!("{} {}", record.level(), record.args());
        }

        fn flush(&self) {}
    }
    let _ = log::set_logger(&TestLog);
    log::set_max_level(log::LevelFilter::Debug);
    let dir = TempDir(std::env::temp_dir().join(format!("proxy-packet-test-{}-{}",
        std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let runtime = Runtime::new().unwrap();
    let (server_listener, tcp_echo, udp_echo) = runtime.block_on(async {
        (
            TcpListener::bind("127.0.0.1:0").await.unwrap(),
            TcpListener::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        )
    });
    let server_addr = server_listener.local_addr().unwrap();
    let tcp_port = tcp_echo.local_addr().unwrap().port();
    let udp_port = udp_echo.local_addr().unwrap().port();
    let udp6_echo = runtime.block_on(UdpSocket::bind("[::1]:0")).unwrap();
    let udp6_port = udp6_echo.local_addr().unwrap().port();
    runtime.spawn(async move {
        let mut buf = [0; 4096];
        while let Ok((n, peer)) = udp6_echo.recv_from(&mut buf).await {
            udp6_echo.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    runtime.spawn(async move {
        while let Ok((mut stream, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                // Exercise a server-first protocol through the actual TUN,
                // SOCKS listener and legacy/v3 forwarding paths.
                stream.write_all(b"server-ready\r\n").await.unwrap();
                let mut buf = [0; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    runtime.spawn(async move {
        let mut buf = [0; 4096];
        while let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await {
            udp_echo.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    let nodes = Arc::new(NodeStore::new(dir.0.join("nodes.json")));
    let cancel = CancellationToken::new();
    let metrics = Arc::new(MetricsStore::with_default_config());
    let config = ServerConfig {
        quic_endpoint: None,
        metrics: metrics.clone(),
        relay: Arc::new(RelayManager::new(nodes.clone(), &dir.0)),
        nodes: nodes.clone(),
        admin_token: None,
        require_control_encryption: false,
        require_secure_transport: false,
        control_session_key: None,
        socks5: std::sync::Arc::new(proxy_server::server::Socks5Manager::in_memory().unwrap()),
        self_node_id: None,
    };
    let relay_directory = dir.0.join("relay");
    std::fs::create_dir_all(&relay_directory).unwrap();
    let relay_manager = Arc::new(RelayManager::new(nodes, &relay_directory));
    relay_manager.set_config(proxy_core::relay::RelayConfig {
        enabled: true,
        targets: vec![proxy_core::relay::UpstreamTarget::node(
            server_addr.to_string(),
        )],
        ..Default::default()
    });
    let relay_listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let relay_address = relay_listener.local_addr().unwrap();
    let relay = runtime.spawn(run_server_with_listener(
        relay_listener,
        ServerConfig {
            quic_endpoint: None,
            relay: relay_manager,
            ..config.clone()
        },
        cancel.clone(),
        None,
    ));
    let server = runtime.spawn(run_server_with_listener(
        server_listener,
        config,
        cancel.clone(),
        None,
    ));

    for (protocol, endpoint) in [
        proxy_core::secure_transport::WireProtocol::Legacy,
        proxy_core::secure_transport::WireProtocol::V3,
    ]
    .into_iter()
    .flat_map(|protocol| [server_addr, relay_address].map(move |endpoint| (protocol, endpoint)))
    {
        proxy_core::secure_transport::set_wire_protocol(protocol);
        let tunnel = PacketTunnelRuntime::start(
            PacketTunnelConfig {
                server_host: endpoint.ip().to_string(),
                server_port: endpoint.port(),
                local_port: 0,
                session_key: Some(DEFAULT_SECRET_KEY.into()),
                auto_proxy,
                udp_enabled: true,
                udp_direct_fallback: false,
                tun_fake_ip: true,
                tun_dns_server: proxy_client::client::tun::DEFAULT_TUN_DNS_SERVER,
                reverse_geo: false,
            },
            dir.0.join(format!("{protocol:?}-{}", endpoint.port())),
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .max_blocking_threads(32)
                .enable_all()
                .build()
                .unwrap(),
        )
        .unwrap();

        // DNS is answered by the provider's persistent virtual resolver, even
        // though the synthetic resolver address is not reachable on the host.
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";
        let mut packet = Vec::new();
        PacketBuilder::ipv4([10, 77, 0, 2], [10, 77, 0, 1], 64)
            .udp(43000, 53)
            .write(&mut packet, query)
            .unwrap();
        send(&tunnel, &packet);
        let answer = receive(
            &tunnel,
            |parsed| matches!(&parsed.transport, Some(TransportSlice::Udp(udp)) if udp.destination_port() == 43000),
        );
        let parsed = SlicedPacket::from_ip(&answer).unwrap();
        let Some(TransportSlice::Udp(udp)) = parsed.transport else {
            panic!("expected DNS reply")
        };
        assert_eq!(&udp.payload()[..2], &[0x12, 0x34]);
        assert_eq!(udp.payload()[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([udp.payload()[6], udp.payload()[7]]), 1);

        let payload = b"packet-bridge-udp-echo";
        packet.clear();
        PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
            .udp(43001, udp_port)
            .write(&mut packet, payload)
            .unwrap();
        send(&tunnel, &packet);
        receive(
            &tunnel,
            |parsed| matches!(&parsed.transport, Some(TransportSlice::Udp(udp)) if udp.destination_port() == 43001 && udp.payload() == payload),
        );

        packet.clear();
        PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
            .tcp(43002, tcp_port, 100, 65535)
            .syn()
            .write(&mut packet, &[])
            .unwrap();
        send(&tunnel, &packet);
        let syn_ack = receive(
            &tunnel,
            |parsed| matches!(&parsed.transport, Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 43002 && tcp.syn() && tcp.ack()),
        );
        let parsed = SlicedPacket::from_ip(&syn_ack).unwrap();
        let Some(TransportSlice::Tcp(tcp)) = parsed.transport else {
            panic!("expected SYN ACK")
        };
        assert_eq!(tcp.acknowledgment_number(), 101);
        let ack = tcp.sequence_number().wrapping_add(1);
        packet.clear();
        PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
            .tcp(43002, tcp_port, 101, 65535)
            .ack(ack)
            .write(&mut packet, &[])
            .unwrap();
        send(&tunnel, &packet);
        let greeting = receive(
            &tunnel,
            |parsed| matches!(&parsed.transport, Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 43002 && tcp.payload() == b"server-ready\r\n"),
        );
        let parsed = SlicedPacket::from_ip(&greeting).unwrap();
        let Some(TransportSlice::Tcp(tcp)) = parsed.transport else {
            panic!("expected server greeting")
        };
        let ack = tcp
            .sequence_number()
            .wrapping_add(tcp.payload().len() as u32);
        let payload = b"packet-bridge-tcp-echo";
        packet.clear();
        PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
            .tcp(43002, tcp_port, 101, 65535)
            .ack(ack)
            .psh()
            .write(&mut packet, payload)
            .unwrap();
        send(&tunnel, &packet);
        receive(
            &tunnel,
            |parsed| matches!(&parsed.transport, Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 43002 && tcp.payload() == payload),
        );

        packet.clear();
        PacketBuilder::ipv6(
            "fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            std::net::Ipv6Addr::LOCALHOST.octets(),
            64,
        )
        .udp(43003, udp6_port)
        .write(&mut packet, b"ipv6-udp-echo")
        .unwrap();
        send(&tunnel, &packet);
        receive(&tunnel, |parsed| {
            matches!(&parsed.transport, Some(TransportSlice::Udp(udp))
            if udp.destination_port() == 43003 && udp.payload() == b"ipv6-udp-echo")
        });

        if with_echo {
            let query = b"\x43\x21\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
            packet.clear();
            PacketBuilder::ipv4([10, 77, 0, 2], [10, 77, 0, 1], 64)
                .udp(43004, 53)
                .write(&mut packet, query)
                .unwrap();
            send(&tunnel, &packet);
            let answer = receive(
                &tunnel,
                |parsed| matches!(&parsed.transport, Some(TransportSlice::Udp(udp)) if udp.destination_port() == 43004),
            );
            let parsed = SlicedPacket::from_ip(&answer).unwrap();
            let Some(TransportSlice::Udp(udp)) = parsed.transport else {
                panic!("expected DNS reply")
            };
            let dns = udp.payload();
            assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1);
            let fake_ip: [u8; 4] = dns[dns.len() - 4..].try_into().unwrap();
            assert_eq!(fake_ip[0], 198);
            packet.clear();
            PacketBuilder::ipv4([10, 77, 0, 2], fake_ip, 64)
                .icmpv4_echo_request(0xabcd, 1)
                .write(&mut packet, b"fake-ip-echo")
                .unwrap();
            send(&tunnel, &packet);
            let response = receive(
                &tunnel,
                |parsed| matches!(&parsed.transport, Some(TransportSlice::Icmpv4(icmp)) if matches!(icmp.icmp_type(), etherparse::Icmpv4Type::EchoReply(header) if header.id == 0xabcd)),
            );
            let mut expected = Vec::new();
            PacketBuilder::ipv4(fake_ip, [10, 77, 0, 2], 64)
                .icmpv4_echo_reply(0xabcd, 1)
                .write(&mut expected, b"fake-ip-echo")
                .unwrap();
            assert_eq!(&response[12..], &expected[12..]);

            // Two requests per family exercise reuse and original identifier /
            // sequence restoration. A real kernel Echo reply crosses every hop.
            for sequence in [7, 8] {
                let payload = b"real-icmp-echo-odd-payload";
                for ipv6 in [false, true] {
                    packet.clear();
                    if ipv6 {
                        PacketBuilder::ipv6(
                            "fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
                            std::net::Ipv6Addr::LOCALHOST.octets(),
                            64,
                        )
                        .icmpv6_echo_request(0x1234, sequence)
                        .write(&mut packet, payload)
                        .unwrap();
                    } else {
                        PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
                            .icmpv4_echo_request(0x1234, sequence)
                            .write(&mut packet, payload)
                            .unwrap();
                    }
                    send(&tunnel, &packet);
                    let response = receive(&tunnel, |parsed| match &parsed.transport {
                        Some(TransportSlice::Icmpv4(icmp)) => {
                            matches!(icmp.icmp_type(), etherparse::Icmpv4Type::EchoReply(header) if header.id == 0x1234 && header.seq == sequence)
                        }
                        Some(TransportSlice::Icmpv6(icmp)) => {
                            matches!(icmp.icmp_type(), etherparse::Icmpv6Type::EchoReply(header) if header.id == 0x1234 && header.seq == sequence)
                        }
                        _ => false,
                    });
                    // Build the expected whole packet independently, including
                    // both checksums and the rewritten TUN addresses.
                    let mut expected = Vec::new();
                    if ipv6 {
                        PacketBuilder::ipv6(
                            std::net::Ipv6Addr::LOCALHOST.octets(),
                            "fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
                            64,
                        )
                        .icmpv6_echo_reply(0x1234, sequence)
                        .write(&mut expected, payload)
                        .unwrap();
                        assert_eq!(&response[8..], &expected[8..]);
                    } else {
                        PacketBuilder::ipv4([127, 0, 0, 1], [10, 77, 0, 2], 64)
                            .icmpv4_echo_reply(0x1234, sequence)
                            .write(&mut expected, payload)
                            .unwrap();
                        assert_eq!(&response[12..], &expected[12..]);
                    }
                }
            }
        }

        // Keep more TCP sessions alive than the desktop runtime has blocking
        // threads. Cancelling their relays must not synchronously wait inside
        // stream destructors and starve the packet workers needed to finish.
        for source_port in 44000..44128 {
            packet.clear();
            PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
                .tcp(source_port, tcp_port, 100, 65535)
                .syn()
                .write(&mut packet, &[])
                .unwrap();
            send(&tunnel, &packet);
            let syn_ack = receive(
                &tunnel,
                |parsed| matches!(&parsed.transport, Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == source_port && tcp.syn() && tcp.ack()),
            );
            let parsed = SlicedPacket::from_ip(&syn_ack).unwrap();
            let Some(TransportSlice::Tcp(tcp)) = parsed.transport else {
                panic!("expected SYN ACK")
            };
            packet.clear();
            PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
                .tcp(source_port, tcp_port, 101, 65535)
                .ack(tcp.sequence_number().wrapping_add(1))
                .write(&mut packet, &[])
                .unwrap();
            send(&tunnel, &packet);
            receive(
                &tunnel,
                |parsed| matches!(&parsed.transport, Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == source_port && tcp.payload() == b"server-ready\r\n"),
            );
        }

        if auto_proxy {
            let counters = tunnel.routing_counters();
            assert!(counters["directTcp"].as_u64().unwrap() > 0);
            assert_eq!(counters["dnsFailures"], 0);
        }
        let port = tunnel.local_port;
        let shutdown = std::time::Instant::now();
        std::thread::scope(|scope| {
            let reader = scope.spawn(
                || {
                    while tunnel.read_packet(Duration::from_secs(30)).is_ok() {}
                },
            );
            std::thread::sleep(Duration::from_millis(10));
            tunnel.cancel();
            reader.join().unwrap();
        });
        assert!(
            shutdown.elapsed() < Duration::from_secs(1),
            "cancellation must wake a blocked reader"
        );
        assert_eq!(tunnel.write_packet(&packet).unwrap(), PacketWrite::Closed);
        drop(tunnel);
        assert!(
            shutdown.elapsed() < Duration::from_secs(5),
            "active TCP sessions must drain before the shutdown deadline"
        );
        // Cancellation releases the listener as well as packet forwarding.
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
    }
    // A legacy/rejecting server must fail startup before any packet forwarding
    // is advertised, and the failed attempt must release its local listener.
    let rejecting = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let rejecting_address = rejecting.local_addr().unwrap();
    let rejection = runtime.spawn(async move {
        let (stream, _) = rejecting.accept().await.unwrap();
        drop(stream);
    });
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let failed = PacketTunnelRuntime::start(
        PacketTunnelConfig {
            server_host: rejecting_address.ip().to_string(),
            server_port: rejecting_address.port(),
            local_port,
            session_key: Some(DEFAULT_SECRET_KEY.into()),
            auto_proxy: false,
            udp_enabled: true,
            udp_direct_fallback: false,
            tun_fake_ip: true,
            tun_dns_server: proxy_client::client::tun::DEFAULT_TUN_DNS_SERVER,
            reverse_geo: false,
        },
        dir.0.join("rejected"),
        Runtime::new().unwrap(),
    );
    assert!(failed.is_err(), "unsupported UDP must fail VPN startup");
    assert!(std::net::TcpListener::bind(("127.0.0.1", local_port)).is_ok());
    runtime.block_on(rejection).unwrap();
    cancel.cancel();
    runtime.block_on(server).unwrap();
    runtime.block_on(relay).unwrap();
    runtime.shutdown_timeout(Duration::from_secs(2));
}

/// Local UDP and DNS remain available with UDP proxying off; foreign traffic
/// receives immediate ICMP feedback without contacting the upstream.
#[test]
fn udp_off_keeps_local_and_dns_but_rejects_foreign_v4_v6() {
    let _guard = RUNTIME_CONFIG_LOCK.lock().unwrap();
    let dir = TempDir(std::env::temp_dir().join(format!("proxy-direct-udp-{}-{}",
        std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let runtime = Runtime::new().unwrap();
    let unavailable = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = unavailable.local_addr().unwrap().port();
    // Keep the listener open without accepting. Any implicit readiness probe
    // or datagram proxying would time out instead of returning the echo.
    let echo = runtime.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let destination = echo.local_addr().unwrap();
    let task = runtime.spawn(async move {
        let mut buf = [0; 1500];
        let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..n], peer).await.unwrap();
    });
    let config: PacketTunnelConfig = serde_json::from_value(serde_json::json!({
        "serverHost": "127.0.0.1", "serverPort": port, "localPort": 0,
        "autoProxy": true, "reverseGeo": true
    }))
    .unwrap();
    assert!(!config.udp_enabled);
    assert!(!config.udp_direct_fallback);
    let tunnel =
        PacketTunnelRuntime::start(config, dir.0.clone(), Runtime::new().unwrap()).unwrap();
    let payload = b"udp-bypasses-auto-and-proxy";
    let mut packet = Vec::new();
    PacketBuilder::ipv4([10, 77, 0, 2], [127, 0, 0, 1], 64)
        .udp(43005, destination.port())
        .write(&mut packet, payload)
        .unwrap();
    send(&tunnel, &packet);
    receive(
        &tunnel,
        |parsed| matches!(&parsed.transport, Some(TransportSlice::Udp(udp)) if udp.destination_port() == 43005 && udp.payload() == payload),
    );
    for ipv6 in [false, true] {
        packet.clear();
        let builder = if ipv6 {
            PacketBuilder::ipv6(
                "fd77::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
                "2606:4700::1111"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
                61,
            )
        } else {
            PacketBuilder::ipv4([10, 77, 0, 2], [1, 1, 1, 1], 61)
        };
        builder
            .udp(43006, 443)
            .write(&mut packet, &[42; 1400])
            .unwrap();
        let started = Instant::now();
        send(&tunnel, &packet);
        let rejected = receive(&tunnel, |parsed| {
            matches!(
                parsed.transport,
                Some(TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_))
            )
        });
        assert!(started.elapsed() < Duration::from_secs(1));
        let parsed = SlicedPacket::from_ip(&rejected).unwrap();
        let quote = match parsed.transport.unwrap() {
            TransportSlice::Icmpv4(icmp) => {
                assert_eq!(
                    icmp.icmp_type(),
                    etherparse::Icmpv4Type::DestinationUnreachable(
                        etherparse::icmpv4::DestUnreachableHeader::Port
                    )
                );
                assert_eq!(
                    icmp.icmp_type().calc_checksum(icmp.payload()),
                    icmp.checksum()
                );
                assert!(rejected.len() <= 576);
                icmp.payload()
            }
            TransportSlice::Icmpv6(icmp) => {
                assert_eq!(
                    icmp.icmp_type(),
                    etherparse::Icmpv6Type::DestinationUnreachable(
                        etherparse::icmpv6::DestUnreachableCode::Port
                    )
                );
                let etherparse::NetSlice::Ipv6(ip) = parsed.net.unwrap() else {
                    panic!("IPv6 response")
                };
                assert_eq!(
                    icmp.icmp_type()
                        .calc_checksum(
                            ip.header().source(),
                            ip.header().destination(),
                            icmp.payload()
                        )
                        .unwrap(),
                    icmp.checksum()
                );
                assert!(rejected.len() <= 1280);
                icmp.payload()
            }
            _ => unreachable!(),
        };
        assert_eq!(
            quote,
            &packet[..quote.len()],
            "ICMP must quote the actual request"
        );
    }
    packet.clear();
    let query =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";
    PacketBuilder::ipv4([10, 77, 0, 2], [10, 77, 0, 1], 64)
        .udp(43007, 53)
        .write(&mut packet, query)
        .unwrap();
    send(&tunnel, &packet);
    receive(
        &tunnel,
        |parsed| matches!(&parsed.transport, Some(TransportSlice::Udp(udp)) if udp.destination_port() == 43007 && udp.payload()[2] & 0x80 != 0),
    );
    assert_eq!(tunnel.routing_counters()["rejectedUdp"], 2);
    assert_eq!(tunnel.routing_counters()["dnsFailures"], 0);
    assert!(
        runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_millis(20), unavailable.accept()).await
            })
            .is_err()
    );
    tunnel.cancel();
    drop(tunnel);
    runtime.block_on(task).unwrap();
}
