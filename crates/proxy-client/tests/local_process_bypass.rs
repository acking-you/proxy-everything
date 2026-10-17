#![cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]

use std::time::Duration;

use proxy_client::client::{
    ClientConfig, ClientRuntimeConfig, run_client_with_listener_runtime_config,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn excluded_loopback_clients_bypass_http_socks_and_udp_but_internal_tun_connections_do_not() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        proxy_core::config::runtime::init_config("127.0.0.1".into(), remote.local_addr().unwrap().port(), false, None);
        let cancel = CancellationToken::new();
        let _guard = cancel.clone().drop_guard();
        let tracker = TaskTracker::new();
        let name = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let bypass = tun2proxy::ProcessBypass::new([name]);
        tracker.spawn(run_client_with_listener_runtime_config(listener, cancel.clone(), Some(tracker.clone()), Some(ClientRuntimeConfig {
            client: ClientConfig { enable_auto_proxy: false, enable_udp: false, cache_dir: None },
            process_bypass: Some(proxy_client::client::ProcessBypassConfig { processes: bypass, ..Default::default() }), ..Default::default()
        })));
        let echo_cancel = cancel.clone();
        tracker.spawn(async move {
            loop {
                let (stream, _) = tokio::select! { r = destination.accept() => r.unwrap(), _ = echo_cancel.cancelled() => break };
                let (mut read, mut write) = stream.into_split();
                tokio::select! { _ = tokio::io::copy(&mut read, &mut write) => {}, _ = echo_cancel.cancelled() => break }
            }
        });
        let echo_cancel = cancel.clone();
        tracker.spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                let (n, peer) = tokio::select! { r = udp.recv_from(&mut buffer) => r.unwrap(), _ = echo_cancel.cancelled() => break };
                udp.send_to(&buffer[..n], peer).await.unwrap();
            }
        });

        // A different PID with the selected executable name represents the
        // excluded application. All destinations remain ephemeral loopback.
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "loopback_application", "--ignored", "--nocapture"])
            .env("BYPASS_TEST_PROXY", local.to_string())
            .env("BYPASS_TEST_TCP", destination_addr.to_string())
            .env("BYPASS_TEST_UDP", udp_addr.to_string())
            .kill_on_drop(true).output().await.unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(tokio::time::timeout(Duration::from_millis(100), remote.accept()).await.is_err(), "excluded application reached remote proxy");

        // The same executable/PID as the listener represents TUN's internal
        // SOCKS caller. It must still follow normal upstream routing.
        let mut internal = TcpStream::connect(local).await.unwrap();
        internal.write_all(format!("CONNECT {destination_addr} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let (mut upstream, _) = remote.accept().await.unwrap();
        let mut prefix = [0; 8];
        upstream.read_exact(&mut prefix).await.unwrap();
        assert_ne!(&prefix[..4], b"CONN");
        drop(upstream);
        drop(internal);
        cancel.cancel();
        tracker.close();
        tracker.wait().await;
    }).await.expect("process bypass regression timed out");
}

#[tokio::test]
#[ignore = "launched as an isolated application by the parent regression"]
async fn loopback_application() {
    let Some(proxy) = std::env::var_os("BYPASS_TEST_PROXY") else {
        return;
    };
    let tcp: std::net::SocketAddr = std::env::var("BYPASS_TEST_TCP").unwrap().parse().unwrap();
    let udp: std::net::SocketAddr = std::env::var("BYPASS_TEST_UDP").unwrap().parse().unwrap();
    for connect in [false, true] {
        let mut stream = TcpStream::connect(proxy.to_str().unwrap()).await.unwrap();
        if connect {
            stream
                .write_all(format!("CONNECT {tcp} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut header = Vec::new();
            proxy_core::transport::read_http_header(&mut stream, &mut header, 4096)
                .await
                .unwrap();
            assert!(header.starts_with(b"HTTP/1.1 200"));
            stream.write_all(b"connect-ok").await.unwrap();
            let mut echoed = [0; 10];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"connect-ok");
        } else {
            let request = format!("GET http://{tcp}/game HTTP/1.1\r\nHost: {tcp}\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut echoed = vec![0; request.len()];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, request.as_bytes());
        }
    }
    let mut stream = tokio_socks_connect(proxy.to_str().unwrap(), tcp, 1).await;
    stream.0.write_all(b"socks-ok").await.unwrap();
    let mut echoed = [0; 8];
    stream.0.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"socks-ok");
    drop(stream);
    // Exclusion also bypasses the user's remote-UDP-disabled policy.
    let (control, relay) =
        tokio_socks_connect(proxy.to_str().unwrap(), "0.0.0.0:0".parse().unwrap(), 3).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for payload in [vec![], vec![42; 4096]] {
        let packet = proxy_core::datagram::encode_socks5_udp_packet(
            &proxy_core::datagram::DatagramAddress::Ip(udp),
            &payload,
        )
        .unwrap();
        socket.send_to(&packet, relay).await.unwrap();
        let mut buffer = vec![0; 65535];
        let (size, _) = socket.recv_from(&mut buffer).await.unwrap();
        assert_eq!(
            proxy_core::datagram::parse_socks5_udp_packet(&buffer[..size])
                .unwrap()
                .payload,
            payload
        );
    }
    drop(control);
}

async fn tokio_socks_connect(
    proxy: &str,
    destination: std::net::SocketAddr,
    command: u8,
) -> (TcpStream, std::net::SocketAddr) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, command, 0];
    proxy_core::datagram::encode_socks5_address(
        &proxy_core::datagram::DatagramAddress::Ip(destination),
        &mut request,
    )
    .unwrap();
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let relay = std::net::SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (stream, relay)
}
