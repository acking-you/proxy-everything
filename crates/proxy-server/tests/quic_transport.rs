//! Real UDP QUIC, shared TCP listeners and unchanged destination protocols.
use std::sync::Arc;
use std::time::Duration;

use proxy_core::config::runtime;
use proxy_core::control::{ControlClient, ControlOp, ControlRequest, ControlResult, QuicEndpoint};
use proxy_core::datagram::{DatagramAddress, encode_socks5_udp_packet, parse_socks5_udp_packet};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::quic::{EndpointOwner, configure_trust, server_config};
use proxy_core::secure_transport::{WireProtocol, set_wire_protocol};
use proxy_core::session::NativeSession;
use proxy_core::transport::get_tcp_proxy_stream_with_protocol;
use proxy_core::{ProxyTransport, quic};
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

const CERT: &[u8] = include_bytes!("../../proxy-core/tests/fixtures/quic-cert.pem");
const KEY: &[u8] = include_bytes!("../../proxy-core/tests/fixtures/quic-key.pem");
const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn quic_multiplexes_tcp_udp_control_and_switches_carrier_between_sessions() {
    tokio::time::timeout(Duration::from_secs(30), scenario())
        .await
        .unwrap();
}

async fn scenario() {
    let state = tempfile::tempdir().unwrap();
    let ca = state.path().join("ca.pem");
    std::fs::write(&ca, CERT).unwrap();
    configure_trust(Some(&ca)).unwrap();
    runtime::set_secret_key(Some(SECRET.into()));
    let endpoint = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let quic_port = endpoint.0.local_addr().unwrap().port();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = listener.local_addr().unwrap().port();
    let nodes = Arc::new(NodeStore::new(state.path().join("nodes.json")));
    let config = ServerConfig {
        quic_endpoint: Some(endpoint.clone()),
        metrics: Arc::new(MetricsStore::with_default_config()),
        relay: Arc::new(RelayManager::new(nodes.clone(), state.path())),
        nodes,
        ..ServerConfig::default()
    };
    let cancel = CancellationToken::new();
    let _guard = cancel.clone().drop_guard();
    let server = tokio::spawn(run_server_with_listener(
        listener,
        config,
        cancel.clone(),
        None,
    ));
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_cancel = cancel.clone();
    let echo_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = echo_cancel.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                result = echo.accept() => {
                    let (mut socket, _) = result.unwrap();
                    tasks.spawn(async move {
                        let (mut read, mut write) = socket.split();
                        tokio::io::copy(&mut read, &mut write).await.unwrap();
                        write.shutdown().await.unwrap();
                    });
                }
            }
        }
    });

    // Explicit per-call carrier choices share one live process and listeners.
    let mut held = get_tcp_proxy_stream_with_protocol(
        "127.0.0.1",
        echo_port,
        "quic://127.0.0.1",
        quic_port,
        None,
        "test",
        WireProtocol::V3,
    )
    .await
    .unwrap();
    let raw_a = quic::connect("127.0.0.1", quic_port).await.unwrap();
    let raw_b = quic::connect("127.0.0.1", quic_port).await.unwrap();
    assert_eq!(raw_a.connection_id(), raw_b.connection_id());
    drop(raw_a); // Closing one stream leaves its siblings open.
    drop(raw_b);
    // A health probe authenticates a connection of its own rather than trusting
    // the pooled one, so an unreachable carrier is reported as such.
    let probe = |port| {
        proxy_core::upstream::UpstreamAddress::parse(&format!("quic://127.0.0.1:{port}")).unwrap()
    };
    probe(quic_port).probe().await.unwrap();
    assert!(probe(tcp_port).probe().await.is_err());
    let mut transfers = tokio::task::JoinSet::new();
    for index in 0..16 {
        transfers.spawn(async move {
            let protocol = if index % 2 == 0 {
                WireProtocol::V3
            } else {
                WireProtocol::Legacy
            };
            let mut stream = get_tcp_proxy_stream_with_protocol(
                "127.0.0.1",
                echo_port,
                "quic://127.0.0.1",
                quic_port,
                None,
                "test",
                protocol,
            )
            .await
            .unwrap();
            let payload = vec![index as u8; 65536];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
        });
    }
    while let Some(result) = transfers.join_next().await {
        result.unwrap();
    }
    // Changing the runtime endpoint affects only the next session.
    for (host, port) in [("127.0.0.1", tcp_port), ("quic://127.0.0.1", quic_port)] {
        runtime::set_server_endpoint(host.into(), port);
        let chosen = runtime::server_endpoint();
        let mut stream = get_tcp_proxy_stream_with_protocol(
            "127.0.0.1",
            echo_port,
            &chosen.host,
            chosen.port,
            None,
            "test",
            WireProtocol::V3,
        )
        .await
        .unwrap();
        stream.write_all(b"new").await.unwrap();
        let mut reply = [0; 3];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"new");
        held.write_all(b"old").await.unwrap();
        held.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"old");
        stream.shutdown().await.unwrap();
    }
    held.shutdown().await.unwrap();
    let mut end = Vec::new();
    held.read_to_end(&mut end).await.unwrap();
    drop(held);

    set_wire_protocol(WireProtocol::V3);
    let mut control = ControlClient::connect("quic://127.0.0.1", quic_port, None)
        .await
        .unwrap();
    assert!(
        control
            .request(ControlRequest {
                token: None,
                op: ControlOp::Ping
            })
            .await
            .unwrap()
            .ok
    );
    drop(control);
    // Clients learn the QUIC port over either carrier, before choosing one.
    for (host, port) in [("127.0.0.1", tcp_port), ("quic://127.0.0.1", quic_port)] {
        let mut client = ControlClient::connect(host, port, None).await.unwrap();
        assert_eq!(
            client.get_quic_endpoint().await.unwrap(),
            Some(QuicEndpoint { port: quic_port })
        );
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = DatagramAddress::Ip(udp.local_addr().unwrap());
    let udp_task = tokio::spawn(async move {
        let mut data = [0; 2048];
        for _ in 0..2 {
            let (len, peer) = udp.recv_from(&mut data).await.unwrap();
            udp.send_to(&data[..len], peer).await.unwrap();
        }
    });
    for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
        let session = NativeSession::connect_with_protocol(
            "",
            0,
            "quic://127.0.0.1",
            quic_port,
            ProxyTransport::UdpAssociate,
            protocol,
        )
        .await
        .unwrap();
        let (mut read, mut write) = session
            .into_datagram_tunnel("quic://127.0.0.1", quic_port)
            .await
            .unwrap();
        let packet = encode_socks5_udp_packet(&destination, b"one datagram").unwrap();
        write.send(&packet).await.unwrap();
        let received = read.recv().await.unwrap();
        assert_eq!(
            parse_socks5_udp_packet(&received).unwrap().payload,
            b"one datagram"
        );
    }
    udp_task.await.unwrap();
    // Relay carrier is selected per route, independently of its incoming carrier.
    let relay_state = tempfile::tempdir().unwrap();
    let relay_nodes = Arc::new(NodeStore::new(relay_state.path().join("nodes.json")));
    let relay = Arc::new(RelayManager::new(relay_nodes.clone(), relay_state.path()));
    let relay_endpoint = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let relay_quic = relay_endpoint.0.local_addr().unwrap().port();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_tcp = relay_listener.local_addr().unwrap().port();
    let relay_server = tokio::spawn(run_server_with_listener(
        relay_listener,
        ServerConfig {
            quic_endpoint: Some(relay_endpoint),
            nodes: relay_nodes,
            relay: relay.clone(),
            admin_token: Some("test-quic-administrator".into()),
            ..ServerConfig::default()
        },
        cancel.clone(),
        None,
    ));
    for (entry, entry_port, target) in [
        (
            "127.0.0.1",
            relay_tcp,
            format!("quic://127.0.0.1:{quic_port}"),
        ),
        (
            "quic://127.0.0.1",
            relay_quic,
            format!("127.0.0.1:{tcp_port}"),
        ),
    ] {
        relay.set_config(proxy_core::relay::RelayConfig {
            enabled: true,
            targets: vec![proxy_core::relay::UpstreamTarget::node(target)],
            ..Default::default()
        });
        for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
            let mut stream = get_tcp_proxy_stream_with_protocol(
                "127.0.0.1",
                echo_port,
                entry,
                entry_port,
                None,
                "relay test",
                protocol,
            )
            .await
            .unwrap();
            stream.write_all(b"across carriers").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"across carriers");
        }
    }
    relay.set_config(proxy_core::relay::RelayConfig {
        enabled: true,
        targets: vec![proxy_core::relay::UpstreamTarget::node(format!(
            "quic://127.0.0.1:{quic_port}"
        ))],
        ..Default::default()
    });
    // The public managed SOCKS listener also reaches its native target over QUIC.
    let mut admin = ControlClient::connect("quic://127.0.0.1", relay_quic, None)
        .await
        .unwrap();
    // Reading it needs no admin token, which this server requires for management.
    assert_eq!(
        admin.get_quic_endpoint().await.unwrap(),
        Some(QuicEndpoint { port: relay_quic })
    );
    let mut status = None;
    for op in [
        ControlOp::UpdateSocks5Config {
            update: proxy_core::socks5::Socks5Update {
                allow_private_destinations: Some(true),
                ..Default::default()
            },
        },
        ControlOp::SetSocks5Enabled {
            enabled: true,
            listen: Some("127.0.0.1:0".parse().unwrap()),
        },
    ] {
        let response = admin
            .request(ControlRequest {
                token: Some("test-quic-administrator".into()),
                op,
            })
            .await
            .unwrap();
        assert!(response.ok, "{:?}", response.error);
        if let Some(ControlResult::Socks5Status { status: value }) = response.result {
            status = Some(value);
        }
    }
    let status = status.unwrap();
    let proxy = proxy_core::relay::ExternalProxyTarget::parse(&format!(
        "socks5://{}:{}@{}",
        status.config.username, status.config.password, status.config.listen,
    ))
    .unwrap();
    let mut stream = proxy_core::transport::get_tcp_external_proxy_stream(
        &proxy,
        "127.0.0.1",
        echo_port,
        "managed SOCKS over QUIC",
    )
    .await
    .unwrap();
    stream.write_all(b"managed").await.unwrap();
    let mut reply = [0; 7];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"managed");
    stream.shutdown().await.unwrap();
    drop(stream);
    drop(admin);
    quic::shutdown_clients().await;
    // A later session reconnects after an explicit close, without replaying any old stream.
    let stream = quic::connect("127.0.0.1", quic_port).await.unwrap();
    drop(stream);
    cancel.cancel();
    server.await.unwrap();
    relay_server.await.unwrap();
    echo_task.await.unwrap();
    quic::shutdown_clients().await;
}
