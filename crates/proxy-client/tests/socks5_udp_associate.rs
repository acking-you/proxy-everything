use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use proxy_client::client::{
    ClientConfig, ClientRuntimeConfig, run_client_with_listener_runtime_config,
};
use proxy_core::config::{DEFAULT_SECRET_KEY, runtime};
use proxy_core::datagram::{DatagramAddress, encode_socks5_udp_packet, parse_socks5_udp_packet};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::relay::ExternalProxyTarget;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn socks5_udp_associate_supports_plain_encrypted_and_chained_relays() {
    let echo_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_socket.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((size, peer)) = echo_socket.recv_from(&mut buffer).await {
            if echo_socket.send_to(&buffer[..size], peer).await.is_err() {
                break;
            }
        }
    });

    let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    runtime::init_config(
        server_addr.ip().to_string(),
        server_addr.port(),
        false,
        Vec::new(),
        Some(DEFAULT_SECRET_KEY.to_string()),
    );

    let state_dir = unique_temp_dir("socks5-udp");
    std::fs::create_dir_all(&state_dir).unwrap();
    let nodes = Arc::new(NodeStore::new(state_dir.join("nodes.json")));
    let server_config = ServerConfig {
        metrics: Arc::new(MetricsStore::with_default_config()),
        relay: Arc::new(RelayManager::new(nodes.clone(), &state_dir)),
        nodes,
        admin_token: None,
        require_control_encryption: false,
        control_session_key: None,
        self_node_id: None,
    };
    let server_cancel = CancellationToken::new();
    let server_task = tokio::spawn(run_server_with_listener(
        server_listener,
        server_config,
        server_cancel.clone(),
        None,
    ));

    // Exercise the original unencrypted data path first. UDP support shares
    // the connection setup with TCP, so both codec modes need end-to-end
    // coverage rather than relying only on framing unit tests.
    let plain_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain_listener.local_addr().unwrap();
    let plain_cancel = CancellationToken::new();
    let plain_task = tokio::spawn(run_client_with_listener_runtime_config::<false>(
        plain_listener,
        plain_cancel.clone(),
        None,
        Some(ClientRuntimeConfig {
            client: ClientConfig {
                enable_auto_proxy: false,
                cache_dir: None,
            },
            upstream_proxy: None,
        }),
    ));
    assert_udp_round_trip(
        plain_addr,
        DatagramAddress::Ip(echo_addr),
        DatagramAddress::Ip(echo_addr),
        b"udp-through-plain-proxy",
    )
    .await;

    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_cancel = CancellationToken::new();
    let client_task = tokio::spawn(run_client_with_listener_runtime_config::<true>(
        client_listener,
        client_cancel.clone(),
        None,
        Some(ClientRuntimeConfig {
            client: ClientConfig {
                enable_auto_proxy: false,
                cache_dir: None,
            },
            upstream_proxy: None,
        }),
    ));

    assert_udp_round_trip(
        client_addr,
        DatagramAddress::Ip(echo_addr),
        DatagramAddress::Ip(echo_addr),
        b"udp-through-encrypted-proxy",
    )
    .await;

    let chained_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chained_addr = chained_listener.local_addr().unwrap();
    let chained_cancel = CancellationToken::new();
    let chained_task = tokio::spawn(run_client_with_listener_runtime_config::<false>(
        chained_listener,
        chained_cancel.clone(),
        None,
        Some(ClientRuntimeConfig {
            client: ClientConfig {
                enable_auto_proxy: false,
                cache_dir: None,
            },
            upstream_proxy: Some(
                ExternalProxyTarget::parse(&format!("socks5h://{client_addr}")).unwrap(),
            ),
        }),
    ));
    assert_udp_round_trip(
        chained_addr,
        // Keep ATYP=DOMAIN coverage while avoiding OS-dependent localhost
        // ordering (`::1` may precede `127.0.0.1` on Windows).
        DatagramAddress::Domain("127.0.0.1".to_string(), echo_addr.port()),
        DatagramAddress::Ip(echo_addr),
        b"udp-through-socks5-chain",
    )
    .await;

    chained_cancel.cancel();
    client_cancel.cancel();
    plain_cancel.cancel();
    server_cancel.cancel();
    chained_task.await.unwrap();
    client_task.await.unwrap();
    plain_task.await.unwrap();
    server_task.await.unwrap();
    echo_task.abort();
    let _ = std::fs::remove_dir_all(state_dir);
}

async fn assert_udp_round_trip(
    client_addr: std::net::SocketAddr,
    destination: DatagramAddress,
    expected_source: DatagramAddress,
    payload: &[u8],
) {
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = TcpStream::connect(client_addr).await.unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let udp_client_addr = udp_client.local_addr().unwrap();
    let mut request = vec![0x05, 0x03, 0x00];
    proxy_core::datagram::encode_socks5_address(
        &DatagramAddress::Ip(udp_client_addr),
        &mut request,
    )
    .unwrap();
    control.write_all(&request).await.unwrap();
    let relay_addr = read_socks5_reply(&mut control).await;

    // A UDP association is pinned to the endpoint declared on its TCP control
    // connection. A packet from a different source port must not be relayed.
    let unexpected_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = encode_socks5_udp_packet(&destination, payload).unwrap();
    unexpected_client
        .send_to(&request, relay_addr)
        .await
        .unwrap();
    let mut ignored_response = [0u8; 2048];
    assert!(
        timeout(
            Duration::from_millis(150),
            unexpected_client.recv_from(&mut ignored_response)
        )
        .await
        .is_err(),
        "UDP packet from an undeclared endpoint was unexpectedly relayed"
    );

    // RFC 1928 fragmentation is unsupported. The malformed datagram should
    // be dropped without tearing down the association, which is verified by
    // the valid round trip immediately afterwards.
    let mut fragmented_request = request.clone();
    fragmented_request[2] = 1;
    udp_client
        .send_to(&fragmented_request, relay_addr)
        .await
        .unwrap();
    assert!(
        timeout(
            Duration::from_millis(150),
            udp_client.recv_from(&mut ignored_response)
        )
        .await
        .is_err(),
        "fragmented SOCKS5 UDP packet was unexpectedly relayed"
    );

    udp_client.send_to(&request, relay_addr).await.unwrap();
    let mut response = [0u8; 2048];
    let (size, source) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut response))
        .await
        .expect("SOCKS5 UDP response timed out")
        .unwrap();
    assert_eq!(source, relay_addr);
    let response = parse_socks5_udp_packet(&response[..size]).unwrap();
    assert_eq!(response.destination, expected_source);
    assert_eq!(response.payload, payload);
}

async fn read_socks5_reply(stream: &mut TcpStream) -> std::net::SocketAddr {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix[..3], &[0x05, 0x00, 0x00]);
    match prefix[3] {
        0x01 => {
            let mut body = [0u8; 6];
            stream.read_exact(&mut body).await.unwrap();
            let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[4], body[5]]);
            std::net::SocketAddr::new(ip.into(), port)
        }
        0x04 => {
            let mut body = [0u8; 18];
            stream.read_exact(&mut body).await.unwrap();
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[16], body[17]]);
            std::net::SocketAddr::new(std::net::Ipv6Addr::from(octets).into(), port)
        }
        atyp => panic!("unexpected SOCKS5 reply address type {atyp:#x}"),
    }
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("proxy-everything-{name}-{suffix}"))
}
