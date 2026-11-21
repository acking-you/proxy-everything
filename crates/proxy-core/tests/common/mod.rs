//! Shared loopback QUIC server and controllable dual-ingress UDP forwarder for recovery tests.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use proxy_core::quic::{self, AuthenticatedConnection, EndpointOwner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

pub const CERT: &[u8] = include_bytes!("../fixtures/quic-cert.pem");
pub const KEY: &[u8] = include_bytes!("../fixtures/quic-key.pem");
pub const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultMode {
    Pass = 0,
    DropAll = 1,
    DropReturn = 2,
}

impl FaultMode {
    fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Pass,
            1 => Self::DropAll,
            _ => Self::DropReturn,
        }
    }
}

pub struct IngressControl {
    port: u16,
    mode: AtomicU8,
    blocked_client_port: AtomicU16,
    client_datagrams: AtomicU64,
}

impl IngressControl {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_fault(&self, mode: FaultMode, blocked_client_port: u16) {
        self.blocked_client_port
            .store(blocked_client_port, Ordering::SeqCst);
        self.mode.store(mode as u8, Ordering::SeqCst);
    }

    pub fn client_datagrams(&self) -> u64 {
        self.client_datagrams.load(Ordering::SeqCst)
    }

    fn mode(&self) -> FaultMode {
        FaultMode::from_u8(self.mode.load(Ordering::SeqCst))
    }
}

pub struct DualIngressHarness {
    pub endpoint: Arc<EndpointOwner>,
    pub primary: Arc<IngressControl>,
    pub standby: Arc<IngressControl>,
    pub connections_rx: mpsc::UnboundedReceiver<Arc<AuthenticatedConnection>>,
    pub received_rx: mpsc::UnboundedReceiver<u8>,
    cancel: CancellationToken,
    server_task: JoinHandle<()>,
    primary_task: JoinHandle<()>,
    standby_task: JoinHandle<()>,
}

impl DualIngressHarness {
    pub async fn start(response_delay: Duration) -> Self {
        proxy_core::config::runtime::set_secret_key(Some(SECRET.into()));
        quic::configure_trust(Some(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quic-cert.pem"),
        ))
        .unwrap();

        let endpoint = Arc::new(EndpointOwner(
            quinn::Endpoint::server(
                quic::server_config(CERT, KEY).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap(),
        ));
        let backend_addr = endpoint.0.local_addr().unwrap();
        let cancel = CancellationToken::new();

        let (connections_tx, connections_rx) = mpsc::unbounded_channel();
        let (received_tx, received_rx) = mpsc::unbounded_channel();
        let server_endpoint = Arc::clone(&endpoint);
        let server_cancel = cancel.clone();
        let server_task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = server_cancel.cancelled() => break,
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => { result.unwrap(); }
                    incoming = server_endpoint.0.accept() => {
                        let Some(incoming) = incoming else { break };
                        let owner = Arc::clone(&server_endpoint);
                        let connections = connections_tx.clone();
                        let received = received_tx.clone();
                        tasks.spawn(async move {
                            let Ok(connection) = AuthenticatedConnection::accept(
                                incoming,
                                owner,
                                SECRET.as_bytes(),
                            )
                            .await
                            else {
                                return;
                            };
                            let connection = Arc::new(connection);
                            let _ = connections.send(Arc::clone(&connection));
                            let mut streams = JoinSet::new();
                            loop {
                                tokio::select! {
                                    Some(result) = streams.join_next(), if !streams.is_empty() => {
                                        result.unwrap();
                                    }
                                    stream = connection.accept_stream() => {
                                        let Ok(mut stream) = stream else { break };
                                        let received = received.clone();
                                        streams.spawn(async move {
                                            let mut chunk = [0u8; 16384];
                                            while let Ok(n) = stream.read(&mut chunk).await {
                                                if n == 0 {
                                                    let _ = stream.shutdown().await;
                                                    break;
                                                }
                                                if n == 1 {
                                                    let _ = received.send(chunk[0]);
                                                }
                                                if !response_delay.is_zero() {
                                                    tokio::time::sleep(response_delay).await;
                                                }
                                                if stream.write_all(&chunk[..n]).await.is_err() {
                                                    break;
                                                }
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

        let (primary, primary_task) = spawn_ingress(backend_addr, cancel.clone()).await;
        let (standby, standby_task) = spawn_ingress(backend_addr, cancel.clone()).await;

        Self {
            endpoint,
            primary,
            standby,
            connections_rx,
            received_rx,
            cancel,
            server_task,
            primary_task,
            standby_task,
        }
    }

    pub async fn shutdown(self) {
        quic::shutdown_clients().await;
        self.cancel.cancel();
        self.endpoint.0.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(quic::DRAIN_TIMEOUT, self.endpoint.0.wait_idle()).await;
        self.server_task.await.unwrap();
        self.primary_task.await.unwrap();
        self.standby_task.await.unwrap();
    }
}

async fn spawn_ingress(
    backend: SocketAddr,
    cancel: CancellationToken,
) -> (Arc<IngressControl>, JoinHandle<()>) {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = front.local_addr().unwrap().port();
    let control = Arc::new(IngressControl {
        port,
        mode: AtomicU8::new(FaultMode::Pass as u8),
        blocked_client_port: AtomicU16::new(0),
        client_datagrams: AtomicU64::new(0),
    });
    let task_control = Arc::clone(&control);
    let task = tokio::spawn(async move {
        let mut routes = HashMap::<SocketAddr, Arc<UdpSocket>>::new();
        let mut replies = JoinSet::new();
        let mut buffer = [0u8; 65536];
        loop {
            let (len, client) = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                packet = front.recv_from(&mut buffer) => match packet {
                    Ok(packet) => packet,
                    Err(_) => break,
                },
            };
            task_control.client_datagrams.fetch_add(1, Ordering::SeqCst);
            if task_control.mode() == FaultMode::DropAll {
                continue;
            }
            let upstream = match routes.get(&client) {
                Some(existing) => Arc::clone(existing),
                None => {
                    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    socket.connect(backend).await.unwrap();
                    let incoming = Arc::clone(&socket);
                    let outgoing = Arc::clone(&front);
                    let reply_control = Arc::clone(&task_control);
                    replies.spawn(async move {
                        let mut reply = [0u8; 65536];
                        while let Ok(len) = incoming.recv(&mut reply).await {
                            let mode = reply_control.mode();
                            let client_blocked =
                                reply_control.blocked_client_port.load(Ordering::SeqCst)
                                    == client.port();
                            if mode == FaultMode::Pass && !client_blocked {
                                let _ = outgoing.send_to(&reply[..len], client).await;
                            }
                        }
                    });
                    routes.insert(client, Arc::clone(&socket));
                    socket
                }
            };
            let _ = upstream.send(&buffer[..len]).await;
        }
        replies.abort_all();
        while replies.join_next().await.is_some() {}
    });
    (control, task)
}
