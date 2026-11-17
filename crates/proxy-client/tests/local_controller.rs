use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::test]
async fn cli_controller_switches_drains_and_routes_website_rules() {
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

    // Both upstreams are unreachable, so only a direct rule reaches this echo.
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let (mut read, mut write) = stream.split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
    });
    let rules = |method: reqwest::Method, body: Value| {
        http.request(method, format!("{base}/v1/rules"))
            .bearer_auth(token)
            .json(&body)
            .send()
    };
    let site = format!("127.0.0.1:{echo_port}");
    let unknown = rules(
        reqwest::Method::PUT,
        json!({"site": site, "target": {"action":"node","node_id":"missing","transport":"tcp"}}),
    )
    .await
    .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let saved: Value = rules(
        reqwest::Method::PUT,
        json!({"site": format!("http://{site}/ignored?path"), "target": {"action":"direct"}}),
    )
    .await
    .unwrap()
    .error_for_status()
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(saved["rules"][0]["site"], site);
    let mut routed = TcpStream::connect(proxy).await.unwrap();
    routed.write_all(&[5, 1, 0]).await.unwrap();
    routed.read_exact(&mut greeting).await.unwrap();
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend_from_slice(&echo_port.to_be_bytes());
    routed.write_all(&connect).await.unwrap();
    let mut reply = [0; 10];
    routed.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "the direct rule should connect");
    routed.write_all(b"ping").await.unwrap();
    let mut echoed = [0; 4];
    routed.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    let removed: Value = rules(reqwest::Method::DELETE, json!({ "site": site }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(removed["rules"], json!([]));

    // The same operations as MCP tools, called the way an agent host does.
    let mcp_url = format!("{base}/mcp");
    let anonymous = http.post(&mcp_url).json(&json!({})).send().await.unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let rpc = |id: u64, method: &str, params: Value| {
        http.post(&mcp_url)
            .bearer_auth(token)
            .header("Accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .send()
    };
    let call = |id: u64, name: &str, arguments: Value| {
        rpc(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    };
    let answer = |response: reqwest::Response| async move {
        let body: Value = response.error_for_status().unwrap().json().await.unwrap();
        body["result"].clone()
    };
    let initialized = answer(
        rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1"},
            }),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(initialized["serverInfo"]["name"], "cipherrelay");
    let listed = answer(rpc(2, "tools/list", json!({})).await.unwrap()).await;
    let mut names = listed["tools"]
        .as_array()
        .unwrap()
        .iter()
        .inspect(|tool| assert!(tool["outputSchema"].is_object(), "{tool}"))
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["get_proxy_state", "set_website_rule", "switch_node"]
    );

    let routed = answer(
        call(
            3,
            "set_website_rule",
            json!({"site": site, "route": "direct"}),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(
        routed["structuredContent"]["website_rules"],
        json!([{"site": site, "route": "direct"}])
    );
    let refused = answer(
        call(4, "switch_node", json!({"node_id": "missing"}))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused["isError"], true);
    assert!(
        refused["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("unknown_node:")
    );
    let state = answer(call(5, "get_proxy_state", json!({})).await.unwrap()).await;
    let state = &state["structuredContent"];
    assert_eq!(state["active"]["node_id"], "second");
    assert!(state["nodes"].as_array().unwrap().len() >= 2);
    let reset = answer(
        call(
            6,
            "set_website_rule",
            json!({"site": site, "route": "default"}),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(reset["structuredContent"]["website_rules"], json!([]));
    process.kill().await.unwrap();
}
