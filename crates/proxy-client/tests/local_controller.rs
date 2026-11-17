use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::test]
async fn cli_switches_carrier_without_rebinding_and_can_drain_existing_sessions() {
    tokio::time::timeout(Duration::from_secs(20), exercise_cli())
        .await
        .unwrap();
}

async fn exercise_cli() {
    let home = tempfile::tempdir().unwrap();
    let quic = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let quic_port = quic.local_addr().unwrap().port();
    let mut config = tempfile::NamedTempFile::new_in(home.path()).unwrap();
    writeln!(
        config,
        r#"server_host = "127.0.0.1"
listen_host = "127.0.0.1"
client_port = 0
auto_proxy = false
udp = false
[controller_nodes]
second = ["quic://127.0.0.1:{quic_port}"]"#
    )
    .unwrap();

    let token = "local-controller-integration-test-only";
    let mut process = tokio::process::Command::new(env!("CARGO_BIN_EXE_http-proxy-cli"))
        .arg("-f")
        .arg(config.path())
        .args(["--controller-port", "0"])
        .env("CIPHERRELAY_CONTROLLER_TOKEN", token)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("PROXY_DATA_DIR", home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(process.stderr.take().unwrap()).lines();
    let base = loop {
        let line = lines
            .next_line()
            .await
            .unwrap()
            .expect("CLI exited before binding controller");
        if let Some(base) = line.strip_prefix("Local controller: ") {
            break base.to_owned();
        }
    };

    let http = proxy_core::util::http_client_builder()
        .no_proxy()
        .build()
        .unwrap();
    let status_url = format!("{base}/v1/status");
    let denied = http.get(&status_url).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        denied.json::<Value>().await.unwrap()["error"]["kind"],
        "unauthorized"
    );
    let status: Value = http
        .get(&status_url)
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxy = (
        "127.0.0.1",
        u16::try_from(status["local_port"].as_u64().unwrap()).unwrap(),
    );
    assert_eq!(status["active"]["node_id"], "startup");
    let nodes: Value = http
        .get(format!("{base}/v1/nodes"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let node = nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "second")
        .unwrap();
    let switch = |selection: Value| {
        http.post(format!("{base}/v1/switch"))
            .bearer_auth(token)
            .json(&selection)
            .send()
    };
    let invalid = switch(json!({"node_id":"second","transport":"tcp"}))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        invalid.json::<Value>().await.unwrap()["error"]["kind"],
        "unsupported_transport"
    );

    // Complete the SOCKS greeting before selecting the new carrier. The old
    // connection can still send its request after a non-draining switch.
    let mut existing = TcpStream::connect(proxy).await.unwrap();
    existing.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    existing.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let selection = json!({"node_id":node["id"],"transport":node["endpoints"][0]["transport"]});
    let committed: Value = switch(selection.clone())
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(committed["active"]["endpoint"]["port"], quic_port);
    assert_eq!(committed["local_port"], status["local_port"]);
    // The disabled UDP association receives its policy reply on the retained socket.
    existing
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    existing.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 7);

    let mut dialing = TcpStream::connect(proxy).await.unwrap();
    dialing.write_all(&[5, 1, 0]).await.unwrap();
    dialing.read_exact(&mut greeting).await.unwrap();
    dialing
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut datagram = [0; 2048];
    assert!(quic.recv(&mut datagram).await.unwrap() >= 1200);
    let mut drain = selection;
    drain["close_existing"] = true.into();
    switch(drain).await.unwrap().error_for_status().unwrap();
    let mut tail = Vec::new();
    match dialing.read_to_end(&mut tail).await {
        Ok(_) => {}
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
    }
    let mut next = TcpStream::connect(proxy).await.unwrap();
    next.write_all(&[5, 1, 0]).await.unwrap();
    next.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    process.kill().await.unwrap();
}
