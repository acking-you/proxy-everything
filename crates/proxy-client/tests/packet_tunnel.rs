#![cfg(feature = "network-extension")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
fn provider_forwards_dns_tcp_and_udp_in_plain_and_encrypted_modes_and_stops() {
    packet_round_trips(false);
}

#[test]
#[ignore = "requires ICMP sockets; run inside an isolated network namespace"]
fn provider_forwards_real_echo_v4_v6_legacy_and_v3() {
    packet_round_trips(true);
}

fn packet_round_trips(with_echo: bool) {
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
    let config = ServerConfig {
        metrics: Arc::new(MetricsStore::with_default_config()),
        relay: Arc::new(RelayManager::new(nodes.clone(), &dir.0)),
        nodes: nodes.clone(),
        admin_token: None,
        require_control_encryption: false,
        require_secure_transport: false,
        control_session_key: None,
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

    for (encrypted, protocol, endpoint) in [
        (false, proxy_core::secure_transport::WireProtocol::Legacy),
        (true, proxy_core::secure_transport::WireProtocol::Legacy),
        (true, proxy_core::secure_transport::WireProtocol::V3),
    ]
    .into_iter()
    .flat_map(|(encrypted, protocol)| {
        [server_addr, relay_address].map(move |endpoint| (encrypted, protocol, endpoint))
    }) {
        proxy_core::secure_transport::set_wire_protocol(protocol);
        let tunnel = PacketTunnelRuntime::start(
            PacketTunnelConfig {
                server_host: endpoint.ip().to_string(),
                server_port: endpoint.port(),
                local_port: 0,
                session_key: Some(DEFAULT_SECRET_KEY.into()),
                auto_proxy: false,
                udp_enabled: true,
                udp_direct_fallback: false,
                tun_fake_ip: true,
                tun_dns_server: proxy_client::client::tun::DEFAULT_TUN_DNS_SERVER,
                reverse_geo: false,
                need_codec_ips: None,
                force_codec: encrypted,
            },
            dir.0.join(if encrypted { "encrypted" } else { "plain" }),
            Runtime::new().unwrap(),
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
        // Cancellation releases the listener as well as packet forwarding.
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok());
    }
    cancel.cancel();
    runtime.block_on(server).unwrap();
    runtime.block_on(relay).unwrap();
    runtime.shutdown_timeout(Duration::from_secs(2));
}
