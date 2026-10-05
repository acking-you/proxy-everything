//! End-to-end compatibility coverage for the proxy connection header.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use proxy_core::Aes256GcmCryption;
use proxy_core::config::{DEFAULT_SECRET_KEY, runtime};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::protocol::get_check_sum;
use proxy_core::secure_transport::WireProtocol;
use proxy_core::transport::get_tcp_proxy_stream_with_protocol;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// This is the exact header shape emitted before `ProxyTransport` existed.
#[derive(Serialize)]
struct LegacyProxyHeader<'a> {
    host: &'a str,
    port: u16,
    key: Option<&'a str>,
}

const DATA_KEY: &str = "0123456789abcdef0123456789abcdef";
const PAYLOAD: &[u8] = b"legacy-client-payload";

#[tokio::test]
async fn current_server_accepts_legacy_tcp_header_without_transport() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        }
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

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for key in [None, Some(DATA_KEY)] {
            let mut client = TcpStream::connect(server_addr).await.unwrap();
            let echo_host = echo_addr.ip().to_string();
            send_legacy_header(&mut client, &echo_host, echo_addr.port(), key).await;
            round_trip(&mut client, key).await;
        }
        echo_task.await.unwrap();
    })
    .await
    .unwrap();
    server_cancel.cancel();
    server_task.await.unwrap();
    let _ = std::fs::remove_dir_all(state_dir);
}

#[tokio::test]
async fn current_legacy_client_interoperates_with_historical_server_wire_format() {
    runtime::init_config(
        "127.0.0.1".into(),
        1081,
        false,
        Vec::new(),
        Some(DEFAULT_SECRET_KEY.into()),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for key in [None, Some(DATA_KEY)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let old_server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                // Decode the historical envelope directly, without the current
                // server parser, and demand the exact original TCP JSON shape.
                let mut header_codec = Aes256GcmCryption::try_new_with_default_key().unwrap();
                let header = read_frame(&mut stream, &mut header_codec).await;
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&header).unwrap(),
                    serde_json::json!({"host": "legacy.example", "port": 443, "key": key})
                );
                let mut data_codec = key.map(|k| Aes256GcmCryption::try_new(k.as_bytes()).unwrap());
                let payload = match data_codec.as_mut() {
                    Some(codec) => read_frame(&mut stream, codec).await,
                    None => {
                        let mut payload = vec![0; PAYLOAD.len()];
                        stream.read_exact(&mut payload).await.unwrap();
                        payload
                    }
                };
                assert_eq!(payload, PAYLOAD);
                match data_codec.as_mut() {
                    Some(codec) => write_frame(&mut stream, codec, &payload).await,
                    None => stream.write_all(&payload).await.unwrap(),
                }
            });
            let mut stream = get_tcp_proxy_stream_with_protocol(
                "legacy.example",
                443,
                "127.0.0.1",
                addr.port(),
                key.map(Into::into),
                "legacy compatibility",
                WireProtocol::Legacy,
            )
            .await
            .unwrap();
            assert!(!stream.is_secure());
            round_trip(&mut stream, key).await;
            old_server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_v3_handshake_does_not_open_a_legacy_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let old_server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 40];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello[..4], b"PXY3");
        drop(stream);
        listener
    });
    let stream = get_tcp_proxy_stream_with_protocol(
        "legacy.example",
        443,
        "127.0.0.1",
        addr.port(),
        None,
        "v3 must stay v3",
        WireProtocol::V3,
    )
    .await;
    if let Ok(mut stream) = stream {
        assert!(stream.read_u8().await.is_err());
    }
    let listener = old_server.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, key: Option<&str>) {
    if let Some(key) = key {
        let mut codec = Aes256GcmCryption::try_new(key.as_bytes()).unwrap();
        write_frame(stream, &mut codec, PAYLOAD).await;
        assert_eq!(read_frame(stream, &mut codec).await, PAYLOAD);
    } else {
        stream.write_all(PAYLOAD).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
    }
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    codec: &mut Aes256GcmCryption,
) -> Vec<u8> {
    let checksum = stream.read_u32().await.unwrap();
    let len = stream.read_u32().await.unwrap();
    assert_eq!(checksum, get_check_sum(len));
    assert!(len <= 1024);
    let mut bytes = vec![0; len as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    codec.decrypt_with_tag(&mut bytes).unwrap().to_vec()
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    codec: &mut Aes256GcmCryption,
    payload: &[u8],
) {
    let mut bytes = payload.to_vec();
    let tag = codec.encrypt(&mut bytes).unwrap();
    let len = u32::try_from(bytes.len() + tag.as_ref().len()).unwrap();
    stream.write_u32(get_check_sum(len)).await.unwrap();
    stream.write_u32(len).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.write_all(tag.as_ref()).await.unwrap();
}

async fn send_legacy_header(stream: &mut TcpStream, host: &str, port: u16, key: Option<&str>) {
    let header = LegacyProxyHeader { host, port, key };
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
