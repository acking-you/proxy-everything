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
use proxy_core::secure_transport::WireProtocol;
use proxy_core::socks5::{Socks5Config, Socks5Status};
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let manager = Arc::new(Socks5Manager::load(path.join("socks5.json")).unwrap());
        let nodes = Arc::new(NodeStore::new(path.join("nodes.json")));
        let config = ServerConfig {
            socks5: manager.clone(),
            metrics: Arc::new(MetricsStore::with_default_config()),
            relay: Arc::new(RelayManager::new(nodes.clone(), path)),
            nodes,
            admin_token: Some(TOKEN.into()),
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
                .call(ControlOp::Ping, WireProtocol::Legacy, true, Some(TOKEN))
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

    async fn change(&self, op: ControlOp, protocol: WireProtocol) -> Socks5Status {
        let response = self.call(op, protocol, true, Some(TOKEN)).await;
        assert!(response.ok, "control failed: {:?}", response.error);
        match response.result.unwrap() {
            ControlResult::Socks5Status { status } => status,
            _ => panic!("unexpected response type"),
        }
    }

    async fn enable(&self, protocol: WireProtocol) -> Socks5Status {
        self.change(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: Some("127.0.0.1:0".parse().unwrap()),
            },
            protocol,
        )
        .await
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
async fn authentication_connect_and_large_half_close_work_with_both_management_protocols() {
    for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start(dir.path()).await;
        let status = server.enable(protocol).await;
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
}

#[tokio::test]
async fn rotation_revokes_sessions_and_persists_credentials_and_enabled_state() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let old = server.enable(WireProtocol::V3).await;
    let echo = Echo::tcp("127.0.0.1:0").await;
    let mut client = authenticated(&old.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    client.write_all(b"hello").await.unwrap();
    client.read_exact(&mut [0; 5]).await.unwrap();
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
    let restarted = Server::start(dir.path()).await;
    let status = restarted
        .change(ControlOp::GetSocks5Status, WireProtocol::V3)
        .await;
    assert_eq!(status.config, rotated.config);
    assert!(status.running);
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
    let original = server.enable(WireProtocol::Legacy).await;
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
    let status = server.enable(WireProtocol::V3).await;
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
        let packet = encode_socks5_udp_packet(&DatagramAddress::Ip(echo.address), payload).unwrap();
        socket.send_to(&packet, relay).await.unwrap();
        let size = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            parse_socks5_udp_packet(&buffer[..size]).unwrap().payload,
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

#[tokio::test]
async fn generated_keys_are_unique_persistent_and_not_replaced_after_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("socks5.json");
    let first = Socks5Manager::load(path.clone()).unwrap().status().await;
    let second = Socks5Manager::load(path.clone()).unwrap().status().await;
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
    }
    std::fs::write(&path, b"invalid-json").unwrap();
    assert!(Socks5Manager::load(path.clone()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"invalid-json");
}

#[tokio::test]
async fn admin_cli_manages_listener_and_returns_failure_for_occupied_port() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let run = |args: Vec<String>| {
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
            tokio::time::timeout(Duration::from_secs(10), command.output())
                .await
                .unwrap()
                .unwrap()
        }
    };
    let mut previous = None;
    for args in [
        vec!["status"],
        vec!["enable", "--listen", "127.0.0.1:0"],
        vec!["rotate-key"],
        vec!["disable"],
    ] {
        let output = run(args.iter().map(|arg| (*arg).into()).collect()).await;
        assert!(output.status.success());
        let response: ControlResponse = serde_json::from_slice(&output.stdout).unwrap();
        let Some(ControlResult::Socks5Status { status }) = response.result else {
            panic!("CLI must return the typed status JSON");
        };
        assert_eq!(status.running, matches!(args[0], "enable" | "rotate-key"));
        if args[0] == "rotate-key" {
            assert_ne!(previous.as_ref(), Some(&status.config.password));
        }
        previous = Some(status.config.password);
    }
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let output = run(vec![
        "enable".into(),
        "--listen".into(),
        occupied.local_addr().unwrap().to_string(),
    ])
    .await;
    assert!(!output.status.success());
    let response: ControlResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!response.ok);
    server.stop().await;
}

#[tokio::test]
async fn failed_restore_keeps_management_available_and_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let enabled = server.enable(WireProtocol::Legacy).await;
    server.stop().await;
    let occupied = TcpListener::bind(enabled.config.listen).await.unwrap();
    let server = Server::start(dir.path()).await;
    let failed = server
        .change(ControlOp::GetSocks5Status, WireProtocol::V3)
        .await;
    assert_eq!(failed.config, enabled.config);
    assert!(!failed.running && failed.last_error.is_some());
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
    drop(authenticated(&retried.config).await);
    server.stop().await;
}

#[tokio::test]
async fn ipv6_connect_and_udp_revocation_work() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path()).await;
    let status = server
        .change(
            ControlOp::SetSocks5Enabled {
                enabled: true,
                listen: Some("[::1]:0".parse().unwrap()),
            },
            WireProtocol::V3,
        )
        .await;
    let echo = Echo::tcp("[::1]:0").await;
    let mut client = authenticated(&status.config).await;
    assert_eq!(
        request(&mut client, 1, DatagramAddress::Ip(echo.address))
            .await
            .0,
        0
    );
    client.write_all(b"ipv6").await.unwrap();
    let mut response = [0; 4];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ipv6");
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
    let status = server.enable(WireProtocol::Legacy).await;
    let mut stalled = TcpStream::connect(status.config.listen).await.unwrap();
    stalled.write_all(&[5, 1]).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(15), stalled.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0)) || read.is_err());
    drop(authenticated(&status.config).await);
    server.stop().await;
}
