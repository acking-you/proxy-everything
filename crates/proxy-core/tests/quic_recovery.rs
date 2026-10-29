//! A real one-way UDP black hole must retire only admission to that connection.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use proxy_core::quic::{self, AuthenticatedConnection, EndpointOwner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const CERT: &[u8] = include_bytes!("fixtures/quic-cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/quic-key.pem");
const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn isolated_connection_is_replaced_without_replay_or_closing_its_existing_streams() {
    tokio::time::timeout(Duration::from_secs(40), scenario())
        .await
        .unwrap();
}

async fn scenario() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    // This integration binary owns its process; no parallel test changes trust
    // or the runtime credential, and no process environment is modified.
    proxy_core::config::runtime::set_secret_key(Some(SECRET.into()));
    quic::configure_trust(Some(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quic-cert.pem"),
    ))
    .unwrap();
    let endpoint = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            quic::server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let cancel = CancellationToken::new();
    let _guard = cancel.clone().drop_guard();
    let (connections_tx, mut connections_rx) = mpsc::unbounded_channel();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel();
    let server_endpoint = endpoint.clone();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = server_cancel.cancelled() => break,
                Some(result) = tasks.join_next(), if !tasks.is_empty() => { result.unwrap(); }
                incoming = server_endpoint.0.accept() => {
                    let owner = server_endpoint.clone();
                    let connections = connections_tx.clone();
                    let received = received_tx.clone();
                    tasks.spawn(async move {
                        let connection = Arc::new(AuthenticatedConnection::accept(
                            incoming.unwrap(), owner, SECRET.as_bytes(),
                        ).await.unwrap());
                        connections.send(connection.clone()).unwrap();
                        let mut streams = JoinSet::new();
                        loop {
                            tokio::select! {
                                Some(result) = streams.join_next(), if !streams.is_empty() => { result.unwrap(); }
                                stream = connection.accept_stream() => {
                                    let Ok(mut stream) = stream else { break };
                                    let received = received.clone();
                                    streams.spawn(async move {
                                        while let Ok(byte) = stream.read_u8().await {
                                            received.send(byte).unwrap();
                                            if stream.write_u8(byte).await.is_err() { break; }
                                        }
                                    });
                                }
                            }
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_port = socket.local_addr().unwrap().port();
    let blocked_port = Arc::new(AtomicU16::new(0));
    let relay = tokio::spawn(forward_udp(
        socket,
        endpoint.0.local_addr().unwrap(),
        blocked_port.clone(),
        cancel.clone(),
    ));
    let mut original = quic::connect("127.0.0.1", relay_port).await.unwrap();
    let old_server = connections_rx.recv().await.unwrap();
    original.write_u8(1).await.unwrap();
    assert_eq!(original.read_u8().await.unwrap(), 1);
    assert_eq!(received_rx.recv().await, Some(1));

    // Exhaust stream credit without sending application data. Admission must
    // wake even when open_bi is pending on the old connection's stream limit.
    let mut held = Vec::new();
    let mut exhausted = false;
    for _ in 0..=quic::MAX_STREAMS {
        match tokio::time::timeout(
            Duration::from_millis(100),
            quic::connect("127.0.0.1", relay_port),
        )
        .await
        {
            Ok(stream) => held.push(stream.unwrap()),
            Err(_) => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted, "the peer's stream limit must bound admission");

    // The server receives the request, but its ACKs and response disappear.
    // A fresh client UDP port remains reachable throughout the failure.
    blocked_port.store(original.local_addr().unwrap().port(), Ordering::SeqCst);
    original.write_u8(2).await.unwrap();
    assert_eq!(received_rx.recv().await, Some(2));
    let started = std::time::Instant::now();
    // Start waiters after the stall begins so isolation fits inside their
    // original 10-second deadline, without restarting that deadline on retry.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut concurrent = JoinSet::new();
    for _ in 0..16 {
        concurrent.spawn(async move { quic::connect("127.0.0.1", relay_port).await.unwrap() });
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), concurrent.join_next())
            .await
            .is_err(),
        "admission must initially wait for stream credit"
    );
    let mut replacement = concurrent.join_next().await.unwrap().unwrap();
    assert_ne!(replacement.connection_id(), original.connection_id());
    assert!(started.elapsed() < Duration::from_secs(20));
    println!("isolated connection replaced after {:?}", started.elapsed());
    let new_server = connections_rx.recv().await.unwrap();
    replacement.write_u8(3).await.unwrap();
    assert_eq!(replacement.read_u8().await.unwrap(), 3);
    assert_eq!(received_rx.recv().await, Some(3));
    while let Some(stream) = concurrent.join_next().await {
        assert_eq!(stream.unwrap().connection_id(), replacement.connection_id());
    }
    drop(held);

    // Restoring the old path delivers its existing stream, not a replay on the
    // replacement. Closing that old connection cannot evict the new pool slot.
    blocked_port.store(0, Ordering::SeqCst);
    assert_eq!(original.read_u8().await.unwrap(), 2);
    old_server.close();
    let mut eof = [0];
    assert!(original.read(&mut eof).await.is_err());
    let next = quic::connect("127.0.0.1", relay_port).await.unwrap();
    assert_eq!(next.connection_id(), replacement.connection_id());
    assert!(
        received_rx.try_recv().is_err(),
        "application bytes must not replay"
    );
    drop(next);
    drop(original);
    drop(replacement);
    new_server.close();
    quic::shutdown_clients().await;
    cancel.cancel();
    server.await.unwrap();
    relay.await.unwrap();
}

async fn forward_udp(
    front: Arc<UdpSocket>,
    server: SocketAddr,
    blocked_port: Arc<AtomicU16>,
    cancel: CancellationToken,
) {
    let mut routes = HashMap::<SocketAddr, Arc<UdpSocket>>::new();
    let mut replies = JoinSet::new();
    let mut buffer = [0; 65536];
    loop {
        let (len, client) = tokio::select! {
            _ = cancel.cancelled() => break,
            packet = front.recv_from(&mut buffer) => packet.unwrap(),
        };
        let upstream = match routes.get(&client) {
            Some(upstream) => upstream.clone(),
            None => {
                let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                upstream.connect(server).await.unwrap();
                let incoming = upstream.clone();
                let outgoing = front.clone();
                let blocked = blocked_port.clone();
                replies.spawn(async move {
                    let mut buffer = [0; 65536];
                    loop {
                        let len = incoming.recv(&mut buffer).await.unwrap();
                        if blocked.load(Ordering::SeqCst) != client.port() {
                            outgoing.send_to(&buffer[..len], client).await.unwrap();
                        }
                    }
                });
                routes.insert(client, upstream.clone());
                upstream
            }
        };
        upstream.send(&buffer[..len]).await.unwrap();
    }
    replies.abort_all();
    while replies.join_next().await.is_some() {}
}
