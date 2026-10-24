//! The deployed binary keeps TCP and QUIC compatible with existing default-key clients.
use std::process::Stdio;
use std::time::Duration;

use proxy_core::config::{DEFAULT_SECRET_KEY, runtime};
use proxy_core::control::{ControlClient, ControlOp, ControlRequest, ControlResult};
use proxy_core::secure_transport::{WireProtocol, set_wire_protocol};

#[tokio::test]
async fn default_key_server_serves_both_carriers_and_both_wire_protocols() {
    let state = tempfile::tempdir().unwrap();
    let cert = state.path().join("cert.pem");
    let key = state.path().join("key.pem");
    std::fs::write(
        &cert,
        include_bytes!("../../proxy-core/tests/fixtures/quic-cert.pem"),
    )
    .unwrap();
    std::fs::write(
        &key,
        include_bytes!("../../proxy-core/tests/fixtures/quic-key.pem"),
    )
    .unwrap();
    proxy_core::quic::configure_trust(Some(&cert)).unwrap();
    runtime::set_secret_key(Some(DEFAULT_SECRET_KEY.into()));
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut server = tokio::process::Command::new(env!("CARGO_BIN_EXE_http-proxy-server"))
        .args([
            "-H",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "--quic-listen",
            "127.0.0.1:0",
        ])
        .arg("--quic-cert")
        .arg(&cert)
        .arg("--quic-key")
        .arg(&key)
        .env("SECRET_KEY", DEFAULT_SECRET_KEY)
        .env("CONTROL_SESSION_KEY", DEFAULT_SECRET_KEY)
        .env("PROXY_DATA_DIR", state.path())
        .env("NODE_ADVERTISE_ADDR", format!("127.0.0.1:{port}"))
        .env("CONTROL_ADMIN_TOKEN", "test-admin-only-token")
        .env_remove("PROXY_REQUIRE_V3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(
                server.try_wait().unwrap().is_none(),
                "server exited during startup"
            );
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let mut control =
            ControlClient::connect("127.0.0.1", port, Some(DEFAULT_SECRET_KEY.into()))
                .await
                .unwrap();
        let response = control
            .request(ControlRequest {
                token: None,
                op: ControlOp::GetQuicEndpoint,
            })
            .await
            .unwrap();
        let Some(ControlResult::QuicEndpoint {
            endpoint: Some(endpoint),
        }) = response.result
        else {
            panic!("QUIC endpoint was not advertised");
        };
        drop(control);
        for protocol in [WireProtocol::Legacy, WireProtocol::V3] {
            set_wire_protocol(protocol);
            for (host, port) in [("127.0.0.1", port), ("quic://127.0.0.1", endpoint.port)] {
                let mut client =
                    ControlClient::connect(host, port, Some(DEFAULT_SECRET_KEY.into()))
                        .await
                        .unwrap();
                for op in [
                    ControlOp::Ping,
                    ControlOp::ListNodes,
                    ControlOp::ListGroups,
                    ControlOp::GetQuicEndpoint,
                    ControlOp::GetSocks5Endpoint,
                ] {
                    assert!(
                        client
                            .request(ControlRequest { token: None, op })
                            .await
                            .unwrap()
                            .ok
                    );
                }
            }
        }
    })
    .await
    .unwrap();
    proxy_core::quic::shutdown_clients().await;
    server.kill().await.unwrap();
    server.wait().await.unwrap();
}
