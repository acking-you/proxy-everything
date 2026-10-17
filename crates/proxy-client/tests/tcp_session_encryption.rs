//! Legacy TCP protection through real HTTP/SOCKS listeners, without adapters,
//! system proxy changes, public services, or the user's configuration/cache.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use proxy_client::client::{ClientConfig, run_client_with_listener};
use proxy_core::Aes256GcmCryption;
use proxy_core::config::{DEFAULT_SECRET_KEY, runtime};
use proxy_core::protocol::get_check_sum;
use proxy_core::secure_transport::{WireProtocol, set_wire_protocol};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const HOST: &str = "youtube.example";
const HTTP_REQUEST: &[u8] = b"POST http://youtube.example/upload HTTP/1.1\r\nHost: youtube.example\r\nContent-Length: 7\r\n\r\npayload";

#[derive(Clone, Copy, Debug)]
enum Frontend {
    Connect,
    Socks,
    Http,
}

/// An independent historical reader: exactly the original three JSON fields,
/// checksum/length framing, and AES-GCM counters. No current server parser or
/// forwarding codec is used to decode the client's output.
#[derive(Deserialize)]
struct HistoricalHeader {
    host: String,
    port: u16,
    key: String,
}

struct TestCache(PathBuf);

impl TestCache {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("proxy-tcp-codec-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn default_tcp_hides_tls_and_http_from_a_stream_filter_with_a_legacy_peer() {
    set_wire_protocol(WireProtocol::Legacy);
    tokio::time::timeout(Duration::from_secs(20), async {
        for keyword_route in [false, true] {
            for frontend in [Frontend::Connect, Frontend::Socks, Frontend::Http] {
                legacy_round_trip(frontend, keyword_route).await;
            }
        }
    })
    .await
    .expect("loopback compatibility exchange must complete without retry/fallback");
}

async fn legacy_round_trip(frontend: Frontend, keyword_route: bool) {
    let cache = TestCache::new();
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local.local_addr().unwrap();
    runtime::init_config(
        "127.0.0.1".into(),
        remote.local_addr().unwrap().port(),
        false,
        Some(DEFAULT_SECRET_KEY.into()),
    );
    // The built-in rule resolves locally before any geo lookup or target DNS.
    assert!(
        runtime::proxy_keywords()
            .iter()
            .any(|rule| HOST.contains(&rule.name_server))
    );
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    let tracker = TaskTracker::new();
    let config = Some(ClientConfig {
        enable_auto_proxy: keyword_route,
        enable_udp: false,
        cache_dir: Some(cache.0.clone()),
    });
    tracker.spawn(run_client_with_listener(
        local,
        cancel.clone(),
        Some(tracker.clone()),
        config,
    ));
    let payload = match frontend {
        Frontend::Http => HTTP_REQUEST.to_vec(),
        _ => client_hello(HOST),
    };
    let peer = historical_peer(remote, &payload, frontend);
    let application = async {
        let mut client = open_frontend(local_addr, frontend).await;
        if matches!(frontend, Frontend::Http) {
            // Include a body: the initial parsed HTTP header and unread body
            // must share the same encryption nonce sequence.
            client.write_all(&payload).await.unwrap();
        } else {
            // Send the record header and SNI in separate application writes.
            // Protection must hold even when neither OS coalesces these writes.
            for chunk in payload.chunks(7) {
                client.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        }
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload, "{frontend:?}");
    };
    tokio::join!(peer, application);
    cancel.cancel();
    tracker.close();
    tracker.wait().await;
}

async fn open_frontend(address: SocketAddr, frontend: Frontend) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.set_nodelay(true).unwrap();
    match frontend {
        Frontend::Connect => {
            stream
                .write_all(
                    format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.unwrap());
                assert!(response.len() < 1024);
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
        }
        Frontend::Socks => {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, 1, 0, 3, HOST.len() as u8];
            request.extend_from_slice(HOST.as_bytes());
            request.extend_from_slice(&443u16.to_be_bytes());
            stream.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        }
        Frontend::Http => {}
    }
    stream
}

async fn historical_peer(listener: TcpListener, payload: &[u8], frontend: Frontend) {
    let (mut stream, _) = listener.accept().await.unwrap();
    stream.set_nodelay(true).unwrap();
    let mut wire = Vec::new();
    let mut header_cipher = Aes256GcmCryption::try_new(DEFAULT_SECRET_KEY.as_bytes()).unwrap();
    let header = read_historical_frame(&mut stream, &mut header_cipher, &mut wire).await;
    let shape: serde_json::Value = serde_json::from_slice(&header).unwrap();
    assert_eq!(
        shape.as_object().unwrap().len(),
        3,
        "retain historical TCP JSON shape"
    );
    let header: HistoricalHeader = serde_json::from_slice(&header).unwrap();
    assert_eq!(header.host, HOST);
    assert_eq!(
        header.port,
        if matches!(frontend, Frontend::Http) {
            80
        } else {
            443
        }
    );
    assert_eq!(
        header.key.len(),
        32,
        "default TCP requires a negotiated legacy key"
    );
    let mut cipher = Aes256GcmCryption::try_new(header.key.as_bytes()).unwrap();
    let mut received = Vec::new();
    while received.len() < payload.len() {
        received.extend(read_historical_frame(&mut stream, &mut cipher, &mut wire).await);
        assert!(received.len() <= payload.len());
    }
    assert_eq!(received, payload);
    // A content filter sees the whole upstream byte stream, a stronger check
    // than looking only at packet starts. Neither write boundaries nor Nagle
    // can hide plaintext from this assertion.
    assert!(!wire.windows(HOST.len()).any(|part| part == HOST.as_bytes()));
    assert!(!wire.windows(payload.len()).any(|part| part == payload));
    // Return several independently framed records, fragmented below each
    // frame boundary, after the application has half-closed its request.
    for chunk in payload.chunks(19) {
        let mut frame = chunk.to_vec();
        let tag = cipher.encrypt(&mut frame).unwrap();
        frame.extend_from_slice(tag.as_ref());
        let len = frame.len() as u32;
        let mut bytes = get_check_sum(len).to_be_bytes().to_vec();
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend(frame);
        for fragment in bytes.chunks(3) {
            stream.write_all(fragment).await.unwrap();
            tokio::task::yield_now().await;
        }
    }
    stream.shutdown().await.unwrap();
}

async fn read_historical_frame(
    stream: &mut TcpStream,
    cipher: &mut Aes256GcmCryption,
    wire: &mut Vec<u8>,
) -> Vec<u8> {
    let mut prefix = [0; 8];
    read_fragmented(stream, &mut prefix, wire).await;
    let checksum = u32::from_be_bytes(prefix[..4].try_into().unwrap());
    let len = u32::from_be_bytes(prefix[4..].try_into().unwrap());
    assert_eq!(checksum, get_check_sum(len));
    assert!((16..=4096).contains(&len));
    let mut body = vec![0; len as usize];
    read_fragmented(stream, &mut body, wire).await;
    cipher.decrypt_with_tag(&mut body).unwrap().to_vec()
}

async fn read_fragmented(stream: &mut TcpStream, bytes: &mut [u8], wire: &mut Vec<u8>) {
    for fragment in bytes.chunks_mut(3) {
        stream.read_exact(fragment).await.unwrap();
        wire.extend_from_slice(fragment);
    }
}

fn client_hello(sni: &str) -> Vec<u8> {
    let mut names = vec![0];
    names.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    names.extend_from_slice(sni.as_bytes());
    let mut extension = vec![0, 0]; // server_name
    extension.extend_from_slice(&((names.len() + 2) as u16).to_be_bytes());
    extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
    extension.extend(names);
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[42; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0xc0, 0x2f, 1, 0]);
    hello.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    hello.extend(extension);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend(hello);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}
