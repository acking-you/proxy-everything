//! End-to-end compatibility coverage for the proxy connection header.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use proxy_core::Aes256GcmCryption;
use proxy_core::config::{DEFAULT_SECRET_KEY, runtime};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::protocol::get_check_sum;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// This is the exact header shape emitted before `ProxyTransport` existed.
#[derive(Serialize)]
struct LegacyProxyHeader<'a> {
    host: &'a str,
    port: u16,
    key: Option<&'a str>,
}

#[tokio::test]
async fn current_server_accepts_legacy_tcp_header_without_transport() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    runtime::init_config(
        server_addr.ip().to_string(),
        server_addr.port(),
        false,
        Vec::new(),
        Some(DEFAULT_SECRET_KEY.to_string()),
    );

    let state_dir = unique_temp_dir("legacy-header");
    std::fs::create_dir_all(&state_dir).unwrap();
    let nodes = Arc::new(NodeStore::new(state_dir.join("nodes.json")));
    let server_config = ServerConfig {
        metrics: Arc::new(MetricsStore::with_default_config()),
        relay: Arc::new(RelayManager::new(nodes.clone(), &state_dir)),
        nodes,
        admin_token: None,
        require_control_encryption: false,
        require_secure_transport: false,
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

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let echo_host = echo_addr.ip().to_string();
    send_legacy_header(&mut client, &echo_host, echo_addr.port()).await;

    client.write_all(b"legacy-client-payload").await.unwrap();
    let mut response = [0u8; 21];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"legacy-client-payload");

    drop(client);
    server_cancel.cancel();
    server_task.await.unwrap();
    echo_task.await.unwrap();
    let _ = std::fs::remove_dir_all(state_dir);
}

async fn send_legacy_header(stream: &mut TcpStream, host: &str, port: u16) {
    let header = LegacyProxyHeader {
        host,
        port,
        key: None,
    };
    let mut encrypted_header = serde_json::to_vec(&header).unwrap();
    let mut cryption = Aes256GcmCryption::try_new_with_default_key().unwrap();
    let tag = cryption.encrypt(&mut encrypted_header).unwrap();
    let frame_len = u32::try_from(encrypted_header.len() + tag.as_ref().len()).unwrap();

    // Legacy clients use the same checksum/length envelope as current ones;
    // only the JSON payload intentionally omits the transport field.
    stream.write_u32(get_check_sum(frame_len)).await.unwrap();
    stream.write_u32(frame_len).await.unwrap();
    stream.write_all(&encrypted_header).await.unwrap();
    stream.write_all(tag.as_ref()).await.unwrap();
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("proxy-everything-{name}-{suffix}"))
}
