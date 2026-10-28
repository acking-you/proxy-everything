use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::control::{
    CONTROL_HOST, ControlCodec, ControlOp, ControlRequest, ControlResponse, ControlResult,
};
use proxy_core::datagram::{
    DatagramAddress, encode_socks5_address, encode_socks5_udp_packet, parse_socks5_udp_packet,
};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::relay::UpstreamTarget;
use proxy_core::secure_transport::WireProtocol;
use proxy_core::socks5::{Socks5Config, Socks5Status, Socks5Update};
use proxy_server::server::Socks5Manager;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "managed-socks5-test-admin";

struct Server {
    address: SocketAddr,
    manager: Arc<Socks5Manager>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Server {
    async fn start(path: &Path) -> Self {
        Self::start_with(path, Some(TOKEN), None).await
    }

    async fn start_with(
        path: &Path,
        admin_token: Option<&str>,
        relay_to: Option<SocketAddr>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let manager = Arc::new(Socks5Manager::load(path.join("socks5.json")));
        let nodes = Arc::new(NodeStore::new(path.join("nodes.json")));
        let relay = Arc::new(RelayManager::new(nodes.clone(), path));
        if let Some(upstream) = relay_to {
            relay.add_target(UpstreamTarget::node(upstream.to_string()));
            relay.set_enabled(true);
        }
        let config = ServerConfig {
            quic_endpoint: None,
            socks5: manager.clone(),
            metrics: Arc::new(MetricsStore::with_default_config()),
            relay,
            nodes,
            admin_token: admin_token.map(str::to_owned),
            require_control_encryption: false,
            require_secure_transport: false,
            control_session_key: None,
            self_node_id: None,
        };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_server_with_listener(
            listener,
            config,
            cancel.clone(),
            None,
        ));
        let server = Self {
            address,
            manager,
            cancel,
            task: Some(task),
        };
        // A control exchange is also a readiness barrier for listener restoration.
        assert!(
            server
                .call(ControlOp::Ping, WireProtocol::Legacy, true, None)
                .await
                .ok
        );
        server
    }

    async fn call(
        &self,
        op: ControlOp,
        protocol: WireProtocol,
        encrypted: bool,
        token: Option<&str>,
    ) -> ControlResponse {
        tokio::time::timeout(Duration::from_secs(5), async {
            let key =
                encrypted.then(|| std::borrow::Cow::Owned(proxy_core::config::gen_random_key()));
            let stream = proxy_core::transport::get_tcp_proxy_stream_with_protocol(
                CONTROL_HOST,
                0,
                "127.0.0.1",
                self.address.port(),
                key.clone(),
                "test managed SOCKS5",
                protocol,
            )
            .await
            .unwrap();
            let (reader, writer) = stream.into_split();
            let mut codec = ControlCodec::new(
                AsyncReader::new(reader),
                AsyncWriter::new(writer),
                if protocol == WireProtocol::V3 {
                    None
                } else {
                    key.as_deref()
                },
            )
            .unwrap();
            codec
                .write_request(&ControlRequest {
                    token: token.map(str::to_owned),
                    op,
                })
                .await
                .unwrap();
            codec.read_response().await.unwrap().unwrap()
        })
        .await
        .expect("control request completed")
    }

    async fn admin(&self, op: ControlOp) -> ControlResult {
        let response = self.call(op, WireProtocol::V3, true, Some(TOKEN)).await;
        assert!(response.ok, "control failed: {:?}", response.error);
        response.result.unwrap()
    }

    async fn change(&self, op: ControlOp, protocol: WireProtocol) -> Socks5Status {
        let response = self.call(op, protocol, true, Some(TOKEN)).await;
        assert!(response.ok, "control failed: {:?}", response.error);
        match response.result.unwrap() {
            ControlResult::Socks5Status { status } => status,
            _ => panic!("unexpected response type"),
        }
    }

    async fn update(&self, update: Socks5Update) -> Socks5Status {
        self.change(ControlOp::UpdateSocks5Config { update }, WireProtocol::V3)
            .await
    }

    async fn enable(&self, listen: &str, protocol: WireProtocol) -> Socks5Status {
        self.change(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: Some(listen.parse().unwrap()),
            },
            protocol,
        )
        .await
    }

    /// Serve on loopback, where the test destinations also live.
    async fn serve(&self, protocol: WireProtocol) -> Socks5Status {
        self.serve_at(SocketAddr::from(([127, 0, 0, 1], 0)), protocol)
            .await
    }

    async fn serve_at(&self, listen: SocketAddr, protocol: WireProtocol) -> Socks5Status {
        self.update(Socks5Update {
            allow_private_destinations: Some(true),
            ..Default::default()
        })
        .await;
        self.enable(&listen.to_string(), protocol).await
    }

    async fn stop(mut self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A free loopback address below every ephemeral port range (Linux starts at
/// 32768, macOS and Windows at 49152), for tests that release a listener's port
/// and bind it again. The kernel can hand a just-released ephemeral port to any
/// socket the parallel tests open, so binding it again fails intermittently; a
/// port outside that range is taken only by an explicit bind.
fn restartable_address() -> SocketAddr {
    static HANDED_OUT: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut handed_out = HANDED_OUT.lock().unwrap();
    // Start at a per-process offset so concurrent test binaries rarely probe
    // the same ports.
    let first = (std::process::id() % 10_000) as u16;
    let port = (0..10_000)
        .map(|offset| 20_000 + (first + offset) % 10_000)
        .find(|port| {
            !handed_out.contains(port) && std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok()
        })
        .expect("a free loopback port below the ephemeral range");
    handed_out.push(port);
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Echo {
    address: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Echo {
    async fn tcp(bind: &str) -> Self {
        let listener = TcpListener::bind(bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(async move {
            let tasks = tokio_util::task::TaskTracker::new();
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let token = token.clone();
                        tasks.spawn(async move {
                            let (mut reader, mut writer) = stream.into_split();
                            tokio::select! {
                                _ = token.cancelled() => {},
                                _ = async { let _ = tokio::io::copy(&mut reader, &mut writer).await; let _ = writer.shutdown().await; } => {},
                            }
                        });
                    }
                }
            }
            tasks.close();
            tasks.wait().await;
        });
        Self {
            address,
            cancel,
            task,
        }
    }

    async fn udp() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65535];
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    received = socket.recv_from(&mut buffer) => {
                        let (size, peer) = received.unwrap();
                        socket.send_to(&buffer[..size], peer).await.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            cancel,
            task,
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.cancel.cancel();
        // UDP has no children; TCP children observe the same cancelled token.
        self.task.abort();
    }
}

async fn authenticate(config: &Socks5Config, password: &str) -> (TcpStream, [u8; 2]) {
    let mut client = TcpStream::connect(config.listen).await.unwrap();
    client.write_all(&[5, 2, 0, 2]).await.unwrap();
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    let mut request = vec![1, config.username.len() as u8];
    request.extend_from_slice(config.username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    client.write_all(&request).await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    (client, response)
}

async fn authenticated(config: &Socks5Config) -> TcpStream {
    let (client, reply) = authenticate(config, &config.password).await;
    assert_eq!(reply, [1, 0]);
    client
}

async fn request(
    client: &mut TcpStream,
    command: u8,
    address: DatagramAddress,
) -> (u8, DatagramAddress) {
    let mut frame = vec![5, command, 0];
    encode_socks5_address(&address, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();
    let mut reply = [0; 3];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!([reply[0], reply[2]], [5, 0]);
    (
        reply[1],
        proxy_core::socks5::read_address(client).await.unwrap(),
    )
}

async fn closed(client: &mut TcpStream) {
    let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut [0; 1]))
        .await
        .expect("connection revoked promptly");
    assert!(matches!(read, Ok(0)) || read.is_err());
}

async fn echoes(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut response = vec![0; payload.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, payload);
}

/// Send one datagram through a UDP association and return the echoed payload.
async fn udp_round_trip(
    socket: &UdpSocket,
    relay: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let packet = encode_socks5_udp_packet(&DatagramAddress::Ip(destination), payload).unwrap();
    socket.send_to(&packet, relay).await.unwrap();
    let mut buffer = [0u8; 65535];
    let size = tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buffer))
        .await
        .ok()?
        .unwrap();
    Some(
        parse_socks5_udp_packet(&buffer[..size])
            .unwrap()
            .payload
            .to_vec(),
    )
}

#[tokio::test]
async fn encrypted_management_supports_legacy_and_v3_and_rejects_unauthorized_reads() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
        let initial = server.change(ControlOp::GetSocks5Status, protocol).await;
        assert!(!initial.config.enabled && !initial.running);
        assert_eq!(initial.config.password.len(), 43);
        let denied = server
            .call(
                ControlOp::GetSocks5Status,
                protocol,
                true,
                Some("wrong-token"),
            )
            .await;
        assert!(!denied.ok && denied.result.is_none());
        assert!(!format!("{denied:?}").contains(&initial.config.password));
    }
    let plaintext = server
        .call(
            ControlOp::GetSocks5Status,
            WireProtocol::Legacy,
            false,
            Some(TOKEN),
        )
        .await;
    assert!(!plaintext.ok && plaintext.error.unwrap().contains("encrypted"));
    server.stop().await;
}

#[tokio::test]
async fn client_reads_need_only_the_session_key_and_management_needs_a_private_admin_token() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let endpoint = || async {
        let response = server
            .call(
                ControlOp::GetSocks5Endpoint,
                WireProtocol::Legacy,
                true,
                None,
            )
            .await;
        match response.result {
            Some(ControlResult::Socks5Endpoint { endpoint }) if response.ok => endpoint,
            _ => panic!("endpoint read failed: {:?}", response.error),
        }
    };
    assert!(endpoint().await.is_none());
    for (op, readable) in [
        (ControlOp::ListNodes, true),
        (ControlOp::ListGroups, true),
        (ControlOp::GetRecentConnections, false),
        (ControlOp::GetSocks5Status, false),
    ] {
        let response = server.call(op, WireProtocol::V3, true, None).await;
        assert_eq!(response.ok, readable, "{:?}", response.error);
    }
    let status = server.serve(WireProtocol::V3).await;
    let link = endpoint().await.expect("serving SOCKS5");
    assert_eq!(
        link.url("127.0.0.1"),
        format!(
            "socks5://cipherrelay:{}@127.0.0.1:{}",
            status.config.password,
            status.config.listen.port()
        )
    );
    server.stop().await;

    // Proxy users hold the native key, so it cannot double as the admin token.
    for admin_token in [None, Some(proxy_core::config::DEFAULT_SECRET_KEY)] {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start_with(dir.path(), admin_token, None).await;
        let denied = server
            .call(
                ControlOp::SetSocks5Enabled {
                    enabled: true,
                    listen: Some("127.0.0.1:0".parse().unwrap()),
                },
                WireProtocol::V3,
                true,
                admin_token,
            )
            .await;
        assert!(!denied.ok && denied.error.unwrap().contains("CONTROL_ADMIN_TOKEN"));
        assert!(!server.manager.status().await.running);
        server.stop().await;
    }
}

#[tokio::test]
async fn authentication_connect_and_large_half_close_work() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let status = server.serve(WireProtocol::Legacy).await;
    assert!(status.config.enabled && status.running);
    let mut anonymous = TcpStream::connect(status.config.listen).await.unwrap();
    anonymous.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    anonymous.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 255]);
    closed(&mut anonymous).await;
    let (mut wrong, reply) = authenticate(&status.config, "incorrect-password").await;
    assert_eq!(reply, [1, 1]);
    closed(&mut wrong).await;

    let echo = Echo::tcp("127.0.0.1:0").await;
    for destination in [
        DatagramAddress::Ip(echo.address),
        DatagramAddress::Domain("localhost".into(), echo.address.port()),
    ] {
        let mut client = authenticated(&status.config).await;
        assert_eq!(request(&mut client, 1, destination).await.0, 0);
        let payload = vec![0x5a; 256 * 1024];
        let (mut reader, mut writer) = client.into_split();
        let upload = async {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let download = async {
            let mut data = Vec::new();
            reader.read_to_end(&mut data).await.unwrap();
            data
        };
        let (_, response) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(upload, download)
        })
        .await
        .unwrap();
        assert_eq!(response, payload);
    }
    let mut unsupported = authenticated(&status.config).await;
    assert_eq!(
        request(&mut unsupported, 2, DatagramAddress::Ip(echo.address))
            .await
            .0,
        7
    );
    closed(&mut unsupported).await;
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_addr = unavailable.local_addr().unwrap();
    drop(unavailable);
    let mut refused = authenticated(&status.config).await;
    assert_ne!(
        request(&mut refused, 1, DatagramAddress::Ip(unavailable_addr))
            .await
            .0,
        0
    );
    server.stop().await;
}

#[tokio::test]
async fn destination_policy_and_source_allowlist_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let status = server.enable("127.0.0.1:0", WireProtocol::V3).await;
    assert!(!status.config.allow_private_destinations);
    let echo = Echo::tcp("127.0.0.1:0").await;
    // Names are checked after resolution, so `localhost` is refused too.
    for destination in [
        DatagramAddress::Ip(echo.address),
        DatagramAddress::Domain("localhost".into(), echo.address.port()),
    ] {
        let mut client = authenticated(&status.config).await;
        assert_eq!(request(&mut client, 1, destination).await.0, 2);
    }
    let udp_echo = Echo::udp().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = authenticated(&status.config).await;
    let (code, DatagramAddress::Ip(relay)) = request(
        &mut control,
        3,
        DatagramAddress::Ip(socket.local_addr().unwrap()),
    )
    .await
    else {
        panic!("IP bound address")
    };
    assert_eq!(code, 0);
    assert!(
        udp_round_trip(&socket, relay, udp_echo.address, b"private")
            .await
            .is_none()
    );
    drop(control);

    let status = server
        .update(Socks5Update {
            allow_private_destinations: Some(true),
            add_allowed_sources: vec!["10.0.0.0/8".parse().unwrap()],
            ..Default::default()
        })
        .await;
    let mut outsider = TcpStream::connect(status.config.listen).await.unwrap();
    let _ = outsider.write_all(&[5, 1, 2]).await;
    closed(&mut outsider).await;
    let status = server
        .update(Socks5Update {
            clear_allowed_sources: true,
            ..Default::default()
        })
        .await;
    let mut client = authenticated(&status.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    echoes(&mut client, b"allowed").await;
    server.stop().await;
}

#[tokio::test]
async fn rotation_revokes_sessions_and_persists_credentials_and_enabled_state() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    // The restarted server restores this exact port.
    let old = server
        .serve_at(restartable_address(), WireProtocol::V3)
        .await;
    let echo = Echo::tcp("127.0.0.1:0").await;
    let mut client = authenticated(&old.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    echoes(&mut client, b"hello").await;
    let rotated = server
        .change(ControlOp::RotateSocks5Key, WireProtocol::Legacy)
        .await;
    assert_ne!(rotated.config.password, old.config.password);
    assert_eq!(rotated.config.listen, old.config.listen);
    closed(&mut client).await;
    let (mut rejected, reply) = authenticate(&old.config, &old.config.password).await;
    assert_eq!(reply, [1, 1]);
    closed(&mut rejected).await;
    let mut accepted = authenticated(&rotated.config).await;
    server.stop().await;
    closed(&mut accepted).await;

    // Restoring the saved listener does not rewrite its state file.
    let file = dir.path().join("socks5.json");
    let saved = std::fs::metadata(&file).unwrap().modified().unwrap();
    let restarted = Server::start(dir.path()).await;
    let status = restarted
        .change(ControlOp::GetSocks5Status, WireProtocol::V3)
        .await;
    assert_eq!(status.config, rotated.config);
    assert!(status.running);
    assert_eq!(std::fs::metadata(&file).unwrap().modified().unwrap(), saved);
    let mut after_restart = authenticated(&status.config).await;
    let disabled = restarted
        .change(
            ControlOp::SetSocks5Enabled {
                enabled: false,
                listen: None,
            },
            WireProtocol::Legacy,
        )
        .await;
    assert!(!disabled.config.enabled && !disabled.running);
    closed(&mut after_restart).await;
    assert!(TcpStream::connect(status.config.listen).await.is_err());
    restarted.stop().await;
    let disabled_restart = Server::start(dir.path()).await;
    assert!(!disabled_restart.manager.status().await.config.enabled);
    disabled_restart.stop().await;
}

#[tokio::test]
async fn bind_and_persistence_failures_leave_previous_state_and_key_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let original = server.serve(WireProtocol::Legacy).await;
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let denied = server
        .call(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: Some(occupied.local_addr().unwrap()),
            },
            WireProtocol::Legacy,
            true,
            Some(TOKEN),
        )
        .await;
    assert!(!denied.ok);
    assert_eq!(server.manager.status().await.config, original.config);
    let file = dir.path().join("socks5.json");
    let saved = std::fs::read(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    let denied = server
        .call(
            ControlOp::RotateSocks5Key,
            WireProtocol::V3,
            true,
            Some(TOKEN),
        )
        .await;
    assert!(!denied.ok);
    assert_eq!(server.manager.status().await.config, original.config);
    drop(authenticated(&original.config).await);
    std::fs::remove_dir(&file).unwrap();
    std::fs::write(&file, saved).unwrap();
    server.stop().await;
}

#[tokio::test]
async fn udp_preserves_boundaries_drops_fragments_and_spoofed_sources_and_closes_with_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let status = server.serve(WireProtocol::V3).await;
    let echo = Echo::udp().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = authenticated(&status.config).await;
    let (code, bound) = request(
        &mut control,
        3,
        DatagramAddress::Ip(socket.local_addr().unwrap()),
    )
    .await;
    assert_eq!(code, 0);
    let DatagramAddress::Ip(relay) = bound else {
        panic!("IP bound address")
    };
    let mut buffer = [0u8; 65535];
    let packet = encode_socks5_udp_packet(&DatagramAddress::Ip(echo.address), b"valid").unwrap();
    let mut fragment = packet.clone();
    fragment[2] = 1;
    socket.send_to(&fragment, relay).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut buffer))
            .await
            .is_err()
    );
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    spoof.send_to(&packet, relay).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), spoof.recv(&mut buffer))
            .await
            .is_err()
    );
    for payload in [
        b"first".as_slice(),
        b"second-datagram".as_slice(),
        &[7; 4096],
    ] {
        assert_eq!(
            udp_round_trip(&socket, relay, echo.address, payload)
                .await
                .unwrap(),
            payload
        );
    }
    control.shutdown().await.unwrap();
    drop(control);
    let rebound = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(bound) = UdpSocket::bind(relay).await {
                break bound;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(rebound);
    let mut mismatched = authenticated(&status.config).await;
    assert_eq!(
        request(
            &mut mismatched,
            3,
            DatagramAddress::Ip("127.0.0.2:0".parse().unwrap())
        )
        .await
        .0,
        2
    );
    server.stop().await;
}

/// Without `IPV6_V6ONLY` an IPv4 client of a `[::]` listener appears as an
/// IPv4-mapped peer while naming its plain IPv4 address in the request.
#[cfg(not(windows))]
#[tokio::test]
async fn dual_stack_listener_relays_ipv4_udp_clients() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    server
        .update(Socks5Update {
            allow_private_destinations: Some(true),
            ..Default::default()
        })
        .await;
    let status = server.enable("[::]:0", WireProtocol::V3).await;
    let config = Socks5Config {
        listen: SocketAddr::from(([127, 0, 0, 1], status.config.listen.port())),
        ..status.config
    };
    let echo = Echo::udp().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = authenticated(&config).await;
    let (code, bound) = request(
        &mut control,
        3,
        DatagramAddress::Ip(socket.local_addr().unwrap()),
    )
    .await;
    assert_eq!(code, 0);
    let DatagramAddress::Ip(relay) = bound else {
        panic!("IP bound address")
    };
    assert!(relay.is_ipv4());
    assert_eq!(
        udp_round_trip(&socket, relay, echo.address, b"dual-stack").await,
        Some(b"dual-stack".to_vec())
    );
    server.stop().await;
}

#[tokio::test]
async fn unusable_state_never_blocks_startup_or_replaces_saved_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("socks5.json");
    let first = Socks5Manager::load(path.clone()).status().await;
    let second = Socks5Manager::load(path.clone()).status().await;
    assert_eq!(first.config, second.config);
    let another = Socks5Manager::in_memory().unwrap().status().await;
    assert_ne!(first.config.password, another.config.password);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // An unwritable state directory leaves SOCKS5 disabled, not the server down.
        let readonly = dir.path().join("readonly");
        std::fs::create_dir(&readonly).unwrap();
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o500)).unwrap();
        let status = Socks5Manager::load(readonly.join("socks5.json"))
            .status()
            .await;
        // Root ignores directory permissions and saves the file.
        if !readonly.join("socks5.json").exists() {
            assert!(status.last_error.unwrap().contains("could not save"));
        }
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    std::fs::write(&path, b"invalid-json").unwrap();
    let corrupt = Socks5Manager::load(path.clone()).status().await;
    assert!(!corrupt.running);
    assert!(
        corrupt
            .last_error
            .unwrap()
            .contains("invalid SOCKS5 state file")
    );
    let server = Server::start(dir.path()).await;
    let denied = server
        .call(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: Some("127.0.0.1:0".parse().unwrap()),
            },
            WireProtocol::V3,
            true,
            Some(TOKEN),
        )
        .await;
    assert!(!denied.ok);
    server.stop().await;
    assert_eq!(std::fs::read(path).unwrap(), b"invalid-json");
}

#[tokio::test]
async fn admin_cli_manages_listener_and_returns_failure_for_occupied_port() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let run = |args: &[&str]| {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_http-proxy-admin"));
        command
            .args(["-H", "127.0.0.1", "-p", &server.address.port().to_string()])
            .env("CONTROL_ADMIN_TOKEN", TOKEN)
            .env("PROXY_WIRE_PROTOCOL", "v3")
            .env(
                "CONTROL_SESSION_KEY",
                std::env::var("SECRET_KEY")
                    .unwrap_or_else(|_| proxy_core::config::DEFAULT_SECRET_KEY.into()),
            )
            .arg("socks5")
            .args(args)
            .kill_on_drop(true);
        async move {
            let output = tokio::time::timeout(Duration::from_secs(10), command.output())
                .await
                .unwrap()
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            (output.status.success(), json)
        }
    };
    let status = |json: &serde_json::Value| -> Socks5Status {
        serde_json::from_value(json["result"]["status"].clone()).unwrap()
    };

    let (ok, json) = run(&["status"]).await;
    assert!(ok && !status(&json).running);
    let (ok, json) = run(&[
        "set-policy",
        "--private-destinations",
        "allow",
        "--handshake-timeout",
        "5",
    ])
    .await;
    assert!(ok && status(&json).config.allow_private_destinations);
    let (ok, json) = run(&["enable", "--listen", "127.0.0.1:0"]).await;
    let enabled = status(&json);
    assert!(ok && enabled.running && enabled.config.handshake_timeout_secs == 5);
    let (ok, json) = run(&["set-advertise", "proxy.example:8443"]).await;
    assert!(ok && status(&json).running);
    let (ok, json) = run(&["link"]).await;
    assert!(ok);
    assert_eq!(
        json["result"]["url"],
        format!(
            "socks5://cipherrelay:{}@proxy.example:8443",
            enabled.config.password
        )
    );
    let (ok, json) = run(&["set-credentials", "--username", "relay"]).await;
    assert!(ok && status(&json).config.username == "relay");
    let (ok, json) = run(&["rotate-key"]).await;
    assert!(ok && status(&json).config.password != enabled.config.password);
    let config = status(&json).config;
    let mut client = authenticated(&config).await;
    let (ok, json) = run(&["sessions"]).await;
    assert!(ok && json["result"]["sessions"].as_array().unwrap().len() == 1);
    let (ok, json) = run(&["kick", "--all"]).await;
    assert!(ok && json["result"]["closed"] == 1);
    closed(&mut client).await;
    let (ok, json) = run(&["disable"]).await;
    assert!(ok && !status(&json).running);
    let (ok, json) = run(&["link"]).await;
    assert!(!ok && json["ok"] == false);

    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    let (ok, json) = run(&["enable", "--listen", &address]).await;
    assert!(!ok && json["ok"] == false);
    server.stop().await;
}

#[tokio::test]
async fn failed_restore_keeps_management_available_and_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    // The test occupies, releases and binds this exact port again.
    let enabled = server
        .serve_at(restartable_address(), WireProtocol::Legacy)
        .await;
    server.stop().await;
    let occupied = TcpListener::bind(enabled.config.listen).await.unwrap();
    let server = Server::start(dir.path()).await;
    let failed = server
        .change(ControlOp::GetSocks5Status, WireProtocol::V3)
        .await;
    assert_eq!(failed.config, enabled.config);
    assert!(!failed.running && failed.last_error.is_some());
    // Credentials still rotate while the address is unavailable.
    let rotated = server
        .change(ControlOp::RotateSocks5Key, WireProtocol::V3)
        .await;
    assert!(!rotated.running && rotated.last_error.is_some());
    assert_ne!(rotated.config.password, enabled.config.password);
    drop(occupied);
    let retried = server
        .change(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: None,
            },
            WireProtocol::V3,
        )
        .await;
    assert!(retried.running && retried.last_error.is_none());
    assert_eq!(retried.config.password, rotated.config.password);
    drop(authenticated(&retried.config).await);
    server.stop().await;
}

#[tokio::test]
async fn overlapping_listen_addresses_on_one_port_can_be_switched() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    // Switching releases the port and binds it again (see `restartable_address`).
    let status = server
        .serve_at(restartable_address(), WireProtocol::V3)
        .await;
    let port = status.config.listen.port();
    let loopback = SocketAddr::from(([127, 0, 0, 1], port));
    let moved = server
        .enable(&format!("0.0.0.0:{port}"), WireProtocol::V3)
        .await;
    assert!(moved.running);
    assert_eq!(moved.config.listen, SocketAddr::from(([0, 0, 0, 0], port)));
    drop(
        authenticated(&Socks5Config {
            listen: loopback,
            ..moved.config.clone()
        })
        .await,
    );
    let back = server.enable(&loopback.to_string(), WireProtocol::V3).await;
    assert!(back.running && back.config.listen == loopback);
    drop(authenticated(&back.config).await);
    server.stop().await;
}

#[tokio::test]
async fn sessions_can_be_listed_and_closed_individually() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let status = server.serve(WireProtocol::V3).await;
    let echo = Echo::tcp("127.0.0.1:0").await;
    let mut clients = Vec::new();
    for _ in 0..2 {
        let mut client = authenticated(&status.config).await;
        assert_eq!(
            request(&mut client, 1, DatagramAddress::Ip(echo.address))
                .await
                .0,
            0
        );
        clients.push(client);
    }
    let ControlResult::Socks5Sessions { sessions } =
        server.admin(ControlOp::ListSocks5Sessions).await
    else {
        panic!("unexpected response type")
    };
    assert_eq!(sessions.len(), 2);
    let destination = echo.address.to_string();
    assert!(sessions.iter().all(|session| {
        session.command.as_deref() == Some("connect")
            && session.destination.as_deref() == Some(destination.as_str())
    }));
    let closed_one = server
        .admin(ControlOp::CloseSocks5Sessions {
            id: Some(sessions[0].id),
            peer: None,
        })
        .await;
    assert!(matches!(
        closed_one,
        ControlResult::Socks5SessionsClosed { closed: 1 }
    ));
    let mut second = clients.pop().unwrap();
    let mut first = clients.pop().unwrap();
    closed(&mut first).await;
    echoes(&mut second, b"still open").await;
    let closed_peer = server
        .admin(ControlOp::CloseSocks5Sessions {
            id: None,
            peer: Some("::ffff:127.0.0.1".parse().unwrap()),
        })
        .await;
    assert!(matches!(
        closed_peer,
        ControlResult::Socks5SessionsClosed { closed: 1 }
    ));
    closed(&mut second).await;
    server.stop().await;
}

#[tokio::test]
async fn relay_routes_carry_socks5_tcp_and_udp() {
    let upstream_dir = tempfile::tempdir().unwrap();
    let upstream = Server::start(upstream_dir.path()).await;
    let entry_dir = tempfile::tempdir().unwrap();
    let entry = Server::start_with(entry_dir.path(), Some(TOKEN), Some(upstream.address)).await;
    let status = entry.serve(WireProtocol::V3).await;

    let echo = Echo::tcp("127.0.0.1:0").await;
    let mut client = authenticated(&status.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    echoes(&mut client, b"relayed").await;
    drop(client);
    // The upstream node, not the entry, opened the destination connection.
    let carried = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let ControlResult::Connections { connections } =
                upstream.admin(ControlOp::GetRecentConnections).await
                && connections
                    .iter()
                    .any(|record| record.dest_port == echo.address.port())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(carried.is_ok());

    let udp_echo = Echo::udp().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = authenticated(&status.config).await;
    let (code, DatagramAddress::Ip(relay)) = request(
        &mut control,
        3,
        DatagramAddress::Ip(socket.local_addr().unwrap()),
    )
    .await
    else {
        panic!("IP bound address")
    };
    assert_eq!(code, 0);
    assert_eq!(
        udp_round_trip(&socket, relay, udp_echo.address, b"relayed datagram").await,
        Some(b"relayed datagram".to_vec())
    );
    drop(control);
    entry.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn ipv6_connect_and_udp_revocation_work() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    server
        .update(Socks5Update {
            allow_private_destinations: Some(true),
            ..Default::default()
        })
        .await;
    let status = server.enable("[::1]:0", WireProtocol::V3).await;
    let echo = Echo::tcp("[::1]:0").await;
    let mut client = authenticated(&status.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    echoes(&mut client, b"ipv6").await;
    for operation in [
        ControlOp::RotateSocks5Key,
        ControlOp::SetSocks5Enabled {
            enabled: false,
            listen: None,
        },
    ] {
        let config = server.manager.status().await.config;
        let mut control = authenticated(&config).await;
        let (code, bound) = request(
            &mut control,
            3,
            DatagramAddress::Ip("[::]:0".parse().unwrap()),
        )
        .await;
        assert_eq!(code, 0);
        let DatagramAddress::Ip(bound) = bound else {
            panic!("UDP address")
        };
        server.change(operation, WireProtocol::V3).await;
        closed(&mut control).await;
        // A completed mutation releases the old UDP endpoint before replying.
        drop(UdpSocket::bind(bound).await.unwrap());
    }
    closed(&mut client).await;
    server.stop().await;
}

#[tokio::test]
async fn incomplete_authentication_expires_without_disabling_listener() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    server
        .update(Socks5Update {
            handshake_timeout_secs: Some(1),
            ..Default::default()
        })
        .await;
    let status = server.serve(WireProtocol::Legacy).await;
    let mut stalled = TcpStream::connect(status.config.listen).await.unwrap();
    stalled.write_all(&[5, 1]).await.unwrap();
    closed(&mut stalled).await;
    drop(authenticated(&status.config).await);
    server.stop().await;
}
