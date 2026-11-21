//! End-to-end Legacy/V3 TCP, SOCKS5 UDP, health-probe and node-switch failover over QUIC standby
//! ingress.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use proxy_core::ProxyTransport;
use proxy_core::config::runtime;
use proxy_core::datagram::{DatagramAddress, encode_socks5_udp_packet, parse_socks5_udp_packet};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::quic::{self, EndpointOwner, StandbyRule, configure_trust, server_config};
use proxy_core::secure_transport::WireProtocol;
use proxy_core::session::NativeSession;
use proxy_core::transport::get_tcp_proxy_stream_with_protocol;
use proxy_core::upstream::UpstreamAddress;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const CERT: &[u8] = include_bytes!("../../proxy-core/tests/fixtures/quic-cert.pem");
const KEY: &[u8] = include_bytes!("../../proxy-core/tests/fixtures/quic-key.pem");
const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn legacy_and_v3_tcp_udp_probes_and_upstream_switches_recover_through_standby_ingress() {
    tokio::time::timeout(Duration::from_secs(45), scenario())
        .await
        .unwrap();
}

async fn scenario() {
    let state = tempfile::tempdir().unwrap();
    let ca = state.path().join("ca.pem");
    std::fs::write(&ca, CERT).unwrap();
    configure_trust(Some(&ca)).unwrap();
    runtime::set_secret_key(Some(SECRET.into()));

    let cancel = CancellationToken::new();
    let _guard = cancel.clone().drop_guard();

    // Backend QUIC + TCP proxy server A (with dual UDP ingresses) and server B (single ingress).
    let (quic_a_backend, server_a) = spawn_proxy_server(state.path(), "a", cancel.clone()).await;
    let (quic_b_addr, server_b) = spawn_proxy_server(state.path(), "b", cancel.clone()).await;
    let quic_b_port = quic_b_addr.port();

    let drop_primary_a = Arc::new(AtomicBool::new(true));
    let drop_standby_a = Arc::new(AtomicBool::new(false));
    let (primary_a, fwd_primary) =
        spawn_udp_ingress(quic_a_backend, Arc::clone(&drop_primary_a), cancel.clone()).await;
    let (standby_a, fwd_standby) =
        spawn_udp_ingress(quic_a_backend, Arc::clone(&drop_standby_a), cancel.clone()).await;

    quic::configure_standby([StandbyRule::new("localhost", primary_a, standby_a).unwrap()])
        .unwrap();

    // Destination TCP echo and UDP echo origins.
    let echo_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_tcp_port = echo_tcp.local_addr().unwrap().port();
    let tcp_cancel = cancel.clone();
    let echo_tcp_task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = tcp_cancel.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = echo_tcp.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    tasks.spawn(async move {
                        let (mut r, mut w) = socket.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        let _ = w.shutdown().await;
                    });
                }
            }
        }
    });

    let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_dest = DatagramAddress::Ip(echo_udp.local_addr().unwrap());
    let udp_cancel = cancel.clone();
    let echo_udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                _ = udp_cancel.cancelled() => break,
                recv = echo_udp.recv_from(&mut buf) => {
                    let (len, peer) = recv.unwrap();
                    echo_udp.send_to(&buf[..len], peer).await.unwrap();
                }
            }
        }
    });

    // 1. Relay health probe (`UpstreamAddress::probe`) succeeds via standby when primary is down.
    let node_a_addr = UpstreamAddress::parse(&format!("quic://localhost:{primary_a}")).unwrap();
    node_a_addr.probe().await.unwrap();

    // 2. Both Legacy and V3 wire protocols succeed for TCP and SOCKS5 UDP over standby without
    //    framing changes.
    runtime::set_server_endpoint("quic://localhost".into(), primary_a);
    for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
        let endpoint = runtime::server_endpoint();
        let mut tcp_stream = get_tcp_proxy_stream_with_protocol(
            "127.0.0.1",
            echo_tcp_port,
            &endpoint.host,
            endpoint.port,
            None,
            "standby tcp session",
            protocol,
        )
        .await
        .unwrap();
        let msg = b"standby-wire-compatible";
        tcp_stream.write_all(msg).await.unwrap();
        tcp_stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tcp_stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, msg);

        let udp_session = NativeSession::connect_with_protocol(
            "",
            0,
            &endpoint.host,
            endpoint.port,
            ProxyTransport::UdpAssociate,
            protocol,
        )
        .await
        .unwrap();
        let (mut udp_reader, mut udp_writer) = udp_session
            .into_datagram_tunnel(&endpoint.host, endpoint.port)
            .await
            .unwrap();
        let packet = encode_socks5_udp_packet(&udp_dest, b"udp-over-standby").unwrap();
        udp_writer.send(&packet).await.unwrap();
        let echoed_pkt = udp_reader.recv_ref().await.unwrap();
        let parsed = parse_socks5_udp_packet(echoed_pkt).unwrap();
        assert_eq!(parsed.payload, b"udp-over-standby");
    }

    // 3. Switching runtime upstream to Node B (`proxy_switch_upstream` / TUN switch path) uses Node
    //    B cleanly
    // without inheriting Node A's standby state, and switching back to Node A reuses Node A's
    // standby.
    runtime::set_server_endpoint("quic://localhost".into(), quic_b_port);
    let chosen_b = runtime::server_endpoint();
    let mut stream_b = get_tcp_proxy_stream_with_protocol(
        "127.0.0.1",
        echo_tcp_port,
        &chosen_b.host,
        chosen_b.port,
        None,
        "node b session",
        WireProtocol::V3,
    )
    .await
    .unwrap();
    stream_b.write_all(b"node-b").await.unwrap();
    let mut out_b = [0u8; 6];
    stream_b.read_exact(&mut out_b).await.unwrap();
    assert_eq!(&out_b, b"node-b");
    drop(stream_b);

    runtime::set_server_endpoint("quic://localhost".into(), primary_a);
    let chosen_a = runtime::server_endpoint();
    let mut stream_a = get_tcp_proxy_stream_with_protocol(
        "127.0.0.1",
        echo_tcp_port,
        &chosen_a.host,
        chosen_a.port,
        None,
        "node a session again",
        WireProtocol::V3,
    )
    .await
    .unwrap();
    stream_a.write_all(b"node-a").await.unwrap();
    let mut out_a = [0u8; 6];
    stream_a.read_exact(&mut out_a).await.unwrap();
    assert_eq!(&out_a, b"node-a");
    drop(stream_a);

    // 4. Both ingresses down -> probe fails cleanly.
    drop_standby_a.store(true, Ordering::SeqCst);
    assert!(node_a_addr.probe().await.is_err());

    quic::configure_standby(Vec::new()).unwrap();
    quic::shutdown_clients().await;
    cancel.cancel();
    server_a.await.unwrap();
    server_b.await.unwrap();
    fwd_primary.await.unwrap();
    fwd_standby.await.unwrap();
    echo_tcp_task.await.unwrap();
    echo_udp_task.await.unwrap();
}

async fn spawn_proxy_server(
    root: &std::path::Path,
    name: &str,
    cancel: CancellationToken,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let endpoint = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let quic_addr = endpoint.0.local_addr().unwrap();
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nodes = Arc::new(NodeStore::new(dir.join("nodes.json")));
    let config = ServerConfig {
        quic_endpoint: Some(endpoint),
        metrics: Arc::new(MetricsStore::with_default_config()),
        relay: Arc::new(RelayManager::new(Arc::clone(&nodes), &dir)),
        nodes,
        ..ServerConfig::default()
    };
    let handle = tokio::spawn(run_server_with_listener(tcp_listener, config, cancel, None));
    (quic_addr, handle)
}

async fn spawn_udp_ingress(
    backend: SocketAddr,
    drop_all: Arc<AtomicBool>,
    cancel: CancellationToken,
) -> (u16, tokio::task::JoinHandle<()>) {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = front.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let mut routes = HashMap::<SocketAddr, Arc<UdpSocket>>::new();
        let mut replies = JoinSet::new();
        let mut buf = [0u8; 65536];
        loop {
            let (len, client) = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                pkt = front.recv_from(&mut buf) => match pkt {
                    Ok(pkt) => pkt,
                    Err(_) => break,
                },
            };
            if drop_all.load(Ordering::SeqCst) {
                continue;
            }
            let upstream = match routes.get(&client) {
                Some(existing) => Arc::clone(existing),
                None => {
                    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    sock.connect(backend).await.unwrap();
                    let incoming = Arc::clone(&sock);
                    let outgoing = Arc::clone(&front);
                    let drop_reply = Arc::clone(&drop_all);
                    replies.spawn(async move {
                        let mut rbuf = [0u8; 65536];
                        while let Ok(n) = incoming.recv(&mut rbuf).await {
                            if !drop_reply.load(Ordering::SeqCst) {
                                let _ = outgoing.send_to(&rbuf[..n], client).await;
                            }
                        }
                    });
                    routes.insert(client, Arc::clone(&sock));
                    sock
                }
            };
            let _ = upstream.send(&buf[..len]).await;
        }
        replies.abort_all();
        while replies.join_next().await.is_some() {}
    });
    (port, handle)
}
