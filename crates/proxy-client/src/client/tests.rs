#[tokio::test]
async fn a_client_that_stalls_after_socks_greeting_still_times_out() {
    let (mut client, stream) = tcp_pair().await;
    let task = tokio::spawn(super::handle_client(super::ClientProxyContext {
        stream,
        #[cfg(feature = "auto-proxy")]
        sender: None,
        force_proxy: true,
        upstream_proxy: None,
        honor_forced_direct: false,
        enable_udp: false,
    }));
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    tokio::time::pause();
    tokio::time::advance(super::CLIENT_SETUP_TIMEOUT).await;
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("handshake timed out")
    );
    tokio::time::resume();
}

#[tokio::test]
async fn client_input_deadline_does_not_cancel_outbound_setup() {
    struct SlowConnect;
    impl super::Forwarder for SlowConnect {
        async fn forward(self) -> super::Result<()> {
            Ok(())
        }
    }
    impl super::ForwarderProvider for SlowConnect {
        type Item = Self;

        fn try_new(_: super::HeaderContext<'_>) -> super::Result<Self> {
            Ok(Self)
        }

        async fn try_build_forwarder(self, _: super::ProxyContext<'_>) -> super::Result<Self> {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            Ok(self)
        }
    }
    let (_client, stream) = tcp_pair().await;
    tokio::time::pause();
    let context = super::ProxyContext {
        handshake_deadline: tokio::time::Instant::now() + super::CLIENT_SETUP_TIMEOUT,
        buffer: b"",
        #[cfg(feature = "auto-proxy")]
        sender: None,
        force_proxy: true,
        upstream_proxy: None,
        honor_forced_direct: false,
        enable_udp: false,
        stream,
    };
    let slots = tokio::sync::Semaphore::new(1);
    super::handle_proxy(context, SlowConnect, slots.acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test]
async fn upstream_failure_returns_http_and_socks_failure_replies() {
    for socks in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream =
            ExternalProxyTarget::parse(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let (client, token) = start_client_for_test(upstream).await;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_until_headers_end(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream = TcpStream::connect(client).await.unwrap();
        if socks {
            stream
                .write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut response = [0; 12];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], &[5, 0, 5, 1]);
        } else {
            stream
                .write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let (response, _) = read_until_headers_end(&mut stream).await;
            assert!(response.starts_with("HTTP/1.1 502"));
        }
        peer.await.unwrap();
        token.cancel();
    }
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (writer, reader) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (writer.unwrap(), reader.unwrap().0)
}

#[tokio::test]
async fn http_header_does_not_consume_pipelined_tunnel_bytes() {
    let (mut writer, mut reader) = tcp_pair().await;
    let header = b"CONNECT example.test:443 HTTP/1.1\r\n\r\n";
    writer
        .write_all(&[header.as_slice(), b"early data"].concat())
        .await
        .unwrap();
    assert_eq!(
        super::read_initial_header(&mut reader).await.unwrap(),
        header
    );
    let mut payload = [0; 10];
    reader.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"early data");
}

#[tokio::test]
async fn fragmented_socks_greeting_preserves_a_pipelined_request() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, mut reader) = tcp_pair().await;
    let task = tokio::spawn(async move {
        for byte in [5, 1, 0, 5, 1, 0, 1] {
            writer.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    assert_eq!(
        super::read_initial_header(&mut reader).await.unwrap(),
        [5, 1, 0]
    );
    let mut request = Vec::new();
    reader.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1]);
    task.await.unwrap();
}

#[tokio::test]
async fn fragmented_http_header_is_complete_before_protocol_selection() {
    use tokio::io::AsyncWriteExt;
    let header = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let (mut writer, mut reader) = tcp_pair().await;
    let task = tokio::spawn(async move {
        for part in header.chunks(3) {
            writer.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    assert_eq!(
        super::read_initial_header(&mut reader).await.unwrap(),
        header
    );
    task.await.unwrap();
}

#[tokio::test]
async fn oversized_http_header_is_rejected_without_waiting_for_eof() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, mut reader) = tcp_pair().await;
    writer
        .write_all(&vec![b'A'; super::MAX_HTTP_HEADER_BYTES])
        .await
        .unwrap();
    assert_eq!(
        super::read_initial_header(&mut reader)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

use proxy_core::relay::ExternalProxyTarget;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::*;

#[tokio::test]
async fn a_full_geo_queue_falls_back_to_proxy_without_waiting() {
    let (sender, _receiver) = kanal::bounded_async::<auto_proxy::SendItem>(1);
    let (notify, _reply) = kanal::bounded_async(1);
    sender.try_send(("queued.example".into(), notify)).unwrap();
    let status = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        need_proxy("full-queue.example", 443, &sender),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(status, ProxyStatus::NormalProxy));
}

/// A geo lookup must not hold up the connection. When the background task is
/// slow, the decision falls back to the proxy rather than waiting.
#[tokio::test]
async fn a_slow_geo_lookup_does_not_block_the_connection() {
    let host = format!("slow-{}.example", std::process::id());
    let (sender, receiver) = kanal::bounded_async::<auto_proxy::SendItem>(1);

    // A responder that answers far too late to be useful.
    let stub = tokio::spawn(async move {
        let (_host, notifier) = receiver.recv().await.unwrap();
        tokio::time::sleep(AUTO_PROXY_DECISION_TIMEOUT * 4).await;
        // The waiter is gone by now; the send failing is the expected path.
        let _ = notifier.send(false).await;
    });

    let started = std::time::Instant::now();
    let status = need_proxy(&host, 443, &sender).await.unwrap();
    let waited = started.elapsed();

    assert!(
        matches!(status, ProxyStatus::NormalProxy),
        "an undecided host must use the proxy, never a direct connection"
    );
    assert!(
        waited < AUTO_PROXY_DECISION_TIMEOUT * 2,
        "waited {waited:?}, which means the deadline did not apply"
    );
    stub.await.unwrap();
}

/// A lookup that answers promptly keeps its accurate decision, so the deadline
/// does not cost correctness in the common case.
#[tokio::test]
async fn a_prompt_geo_lookup_still_decides_the_connection() {
    let host = format!("prompt-{}.example", std::process::id());
    let (sender, receiver) = kanal::bounded_async::<auto_proxy::SendItem>(1);

    let stub = tokio::spawn(async move {
        let (_host, notifier) = receiver.recv().await.unwrap();
        // `false` = no proxy needed, i.e. a CN host in normal mode.
        notifier.send(false).await.unwrap();
    });

    let status = need_proxy(&host, 443, &sender).await.unwrap();
    assert!(
        matches!(status, ProxyStatus::NoProxy(_)),
        "a resolved direct decision must be honoured"
    );
    stub.await.unwrap();
}

/// TUN must no longer be a reason to disable auto-proxy, and the user's own
/// setting must remain the switch.
#[test]
fn auto_proxy_follows_the_user_setting_not_tun() {
    assert!(auto_proxy_applies(true, false));
    assert!(!auto_proxy_applies(false, false));
    // An upstream proxy leaves no direct decision to make.
    assert!(!auto_proxy_applies(true, true));
    assert!(!auto_proxy_applies(false, true));
}

async fn start_client_for_test(upstream_proxy: ExternalProxyTarget) -> (String, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let token = CancellationToken::new();
    tokio::spawn(run_client_with_listener_runtime_config(
        listener,
        token.clone(),
        None,
        Some(ClientRuntimeConfig {
            client: ClientConfig {
                enable_auto_proxy: false,
                enable_udp: true,
                cache_dir: None,
            },
            upstream_proxy: Some(upstream_proxy),
            tun: None,
            force_proxy: None,
        }),
    ));
    (addr, token)
}

async fn start_echo_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    addr
}

async fn start_auth_http_connect_proxy(expected_auth: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = inbound.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
        let connect_target = request
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("CONNECT "))
            .and_then(|line| line.split_whitespace().next())
            .unwrap();
        let (host, port) = connect_target.rsplit_once(':').unwrap();
        let mut outbound = TcpStream::connect((host, port.parse::<u16>().unwrap()))
            .await
            .unwrap();
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    });
    addr
}

async fn start_plain_http_proxy(expected_auth: String) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = inbound.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request).into_owned();
        assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
        let _ = tx.send(request);
        inbound
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
    });
    (addr, rx)
}

async fn start_auth_socks5_proxy(username: &'static str, password: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        assert_eq!(inbound.read_u8().await.unwrap(), 0x05);
        let methods_len = inbound.read_u8().await.unwrap() as usize;
        let mut methods = vec![0u8; methods_len];
        inbound.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0x02));
        inbound.write_all(&[0x05, 0x02]).await.unwrap();

        assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
        let username_len = inbound.read_u8().await.unwrap() as usize;
        let mut username_buf = vec![0u8; username_len];
        inbound.read_exact(&mut username_buf).await.unwrap();
        let password_len = inbound.read_u8().await.unwrap() as usize;
        let mut password_buf = vec![0u8; password_len];
        inbound.read_exact(&mut password_buf).await.unwrap();
        assert_eq!(String::from_utf8(username_buf).unwrap(), username);
        assert_eq!(String::from_utf8(password_buf).unwrap(), password);
        inbound.write_all(&[0x01, 0x00]).await.unwrap();

        assert_eq!(inbound.read_u8().await.unwrap(), 0x05);
        assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
        assert_eq!(inbound.read_u8().await.unwrap(), 0x00);
        let atyp = inbound.read_u8().await.unwrap();
        let host = match atyp {
            0x01 => {
                let mut buf = [0u8; 4];
                inbound.read_exact(&mut buf).await.unwrap();
                std::net::Ipv4Addr::from(buf).to_string()
            }
            0x03 => {
                let len = inbound.read_u8().await.unwrap() as usize;
                let mut buf = vec![0u8; len];
                inbound.read_exact(&mut buf).await.unwrap();
                String::from_utf8(buf).unwrap()
            }
            other => panic!("unexpected ATYP: {other:#x}"),
        };
        let port = inbound.read_u16().await.unwrap();
        let mut outbound = TcpStream::connect((host.as_str(), port)).await.unwrap();
        inbound
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    });
    addr
}

async fn read_until_headers_end(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut response = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        assert_ne!(n, 0);
        response.extend_from_slice(&buf[..n]);
        if let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = headers_end + 4;
            return (
                String::from_utf8_lossy(&response[..body_start]).into_owned(),
                response[body_start..].to_vec(),
            );
        }
    }
}

#[tokio::test]
async fn local_socks5_forwards_through_authenticated_socks5_upstream() {
    let target_addr = start_echo_server().await;
    let (_, target_port) = target_addr.rsplit_once(':').unwrap();
    let target_port = target_port.parse::<u16>().unwrap();
    let upstream_addr = start_auth_socks5_proxy("user", "secret").await;
    let upstream_proxy =
        ExternalProxyTarget::parse(&format!("socks5://user:secret@{upstream_addr}")).unwrap();
    let (client_addr, token) = start_client_for_test(upstream_proxy).await;

    let mut stream = TcpStream::connect(client_addr).await.unwrap();
    stream.write_all(&[0x05]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    // The rest of the greeting and the request arrive together.
    stream
        .write_all(&[
            0x01,
            0x00,
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (target_port >> 8) as u8,
            target_port as u8,
        ])
        .await
        .unwrap();
    let mut handshake = [0u8; 2];
    stream.read_exact(&mut handshake).await.unwrap();
    assert_eq!(handshake, [0x05, 0x00]);
    let mut response = [0u8; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0..2], [0x05, 0x00]);

    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    token.cancel();
}

#[tokio::test]
async fn local_http_connect_forwards_through_authenticated_http_upstream() {
    let target_addr = start_echo_server().await;
    let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
    let upstream_addr = start_auth_http_connect_proxy(expected_auth).await;
    let upstream_proxy =
        ExternalProxyTarget::parse(&format!("http://user:secret@{upstream_addr}")).unwrap();
    let (client_addr, token) = start_client_for_test(upstream_proxy).await;

    let mut stream = TcpStream::connect(client_addr).await.unwrap();
    stream.write_all(b"CON").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    stream
        .write_all(format!("NECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (response, _) = read_until_headers_end(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));

    stream.write_all(b"pong").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    token.cancel();
}

#[tokio::test]
async fn local_plain_http_replaces_proxy_authorization_for_http_upstream() {
    let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
    let (upstream_addr, request_rx) = start_plain_http_proxy(expected_auth.clone()).await;
    let upstream_proxy =
        ExternalProxyTarget::parse(&format!("http://user:secret@{upstream_addr}")).unwrap();
    let (client_addr, token) = start_client_for_test(upstream_proxy).await;

    let mut stream = TcpStream::connect(client_addr).await.unwrap();
    stream
            .write_all(
                b"GET http://example.test/path HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic d3Jvbmc=\r\n\r\n",
            )
            .await
            .unwrap();
    let (response, mut body) = read_until_headers_end(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    while body.len() < 2 {
        let mut buf = [0u8; 2];
        let n = stream.read(&mut buf).await.unwrap();
        assert_ne!(n, 0);
        body.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&body[..2], b"OK");

    let request = request_rx.await.unwrap();
    assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
    assert!(!request.contains("Proxy-Authorization: Basic d3Jvbmc="));
    token.cancel();
}
