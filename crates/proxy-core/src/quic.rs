//! TLS-verified QUIC carriers with exporter-bound application authentication.
//!
//! No application stream is accepted before authentication. No 0-RTT or TCP
//! fallback is used: once a stream is returned, its request must never be replayed.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::RwLock;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use ring::{digest, hmac};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Semaphore};

pub const ALPN: &[u8] = b"proxy-everything/1";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_STREAMS: u32 = 64;
const CANCELLED: VarInt = VarInt::from_u32(1);
const AUTH_FAILED: VarInt = VarInt::from_u32(2);

fn transport(incoming_streams: u32) -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(incoming_streams.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(VarInt::from_u32(30_000).into()))
        .stream_receive_window(VarInt::from_u32(1024 * 1024))
        .receive_window(VarInt::from_u32(8 * 1024 * 1024))
        .send_window(8 * 1024 * 1024)
        .send_fairness(true)
        .datagram_receive_buffer_size(None);
    Arc::new(config)
}

pub fn client_config(extra_ca_pem: Option<&[u8]>) -> io::Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        let certs = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC CA file contains no certificates",
            ));
        }
        for cert in certs {
            roots.add(cert).map_err(io::Error::other)?;
        }
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport(0));
    Ok(config)
}

pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<quinn::ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(io::Error::other)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(io::Error::other)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(1));
    config
        .max_incoming(MAX_CONNECTIONS)
        .incoming_buffer_size_total(4 * 1024 * 1024);
    // A server's source/association accounting remains pinned to the validated peer.
    config.migration(false);
    Ok(config)
}

/// Own the UDP driver through bounded close-frame draining, including cancellation.
pub struct EndpointOwner(pub Endpoint);
impl Drop for EndpointOwner {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"shutdown");
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let endpoint = self.0.clone();
            runtime.spawn(async move {
                let _ = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.wait_idle()).await;
            });
        }
    }
}

fn binding(connection: &Connection, role: &[u8]) -> io::Result<[u8; 32]> {
    let mut binding = [0; 32];
    connection
        .export_keying_material(&mut binding, b"EXPORTER-proxy-everything-quic-v1", role)
        .map_err(|_| io::Error::other("TLS exporter unavailable"))?;
    Ok(binding)
}

async fn authenticate(connection: &Connection, key: &[u8], server: bool) -> io::Result<()> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let (send_role, receive_role): (&[u8], &[u8]) = if server {
        (b"server", b"client")
    } else {
        (b"client", b"server")
    };
    let own_tag = hmac::sign(&key, &binding(connection, send_role)?);
    let peer_binding = binding(connection, receive_role)?;
    let (mut send, mut recv) = if server {
        connection.accept_bi().await
    } else {
        connection.open_bi().await
    }
    .map_err(io::Error::other)?;
    if !server {
        send.write_all(own_tag.as_ref())
            .await
            .map_err(io::Error::other)?;
        send.finish().map_err(io::Error::other)?;
    }
    let tag = recv.read_to_end(32).await.map_err(io::Error::other)?;
    hmac::verify(&key, &peer_binding, &tag).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "QUIC application authentication failed",
        )
    })?;
    if server {
        send.write_all(own_tag.as_ref())
            .await
            .map_err(io::Error::other)?;
        send.finish().map_err(io::Error::other)?;
        connection.set_max_concurrent_bi_streams(MAX_STREAMS.into());
    }
    Ok(())
}

/// Only authenticated connections can produce application streams.
pub struct AuthenticatedConnection {
    connection: Connection,
    owner: Arc<EndpointOwner>,
}

impl AuthenticatedConnection {
    pub async fn accept(
        incoming: quinn::Incoming,
        owner: Arc<EndpointOwner>,
        key: &[u8],
    ) -> io::Result<Self> {
        let connection = tokio::time::timeout(CONNECT_TIMEOUT, incoming)
            .await
            .map_err(timeout)?
            .map_err(io::Error::other)?;
        if let Err(error) =
            tokio::time::timeout(CONNECT_TIMEOUT, authenticate(&connection, key, true))
                .await
                .map_err(timeout)
                .and_then(|r| r)
        {
            connection.close(AUTH_FAILED, b"authentication failed");
            return Err(error);
        }
        tracing::info!(carrier = "quic", peer = %connection.remote_address(), "authenticated QUIC connection");
        Ok(Self { connection, owner })
    }

    pub async fn accept_stream(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(io::Error::other)?;
        Ok(QuicStream::new(
            send,
            recv,
            self.connection.clone(),
            self.owner.clone(),
        ))
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"shutdown");
    }
}

fn timeout(_: tokio::time::error::Elapsed) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "QUIC connection/stream deadline exceeded; TCP fallback is disabled",
    )
}

/// One QUIC stream, independently cancelled without closing sibling streams.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    owner: Arc<EndpointOwner>,
    finished: bool,
}
impl QuicStream {
    fn new(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        owner: Arc<EndpointOwner>,
    ) -> Self {
        Self {
            send,
            recv,
            connection,
            owner,
            finished: false,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.owner.0.local_addr().expect("bound QUIC endpoint")
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn connection_id(&self) -> usize {
        self.connection.stable_id()
    }

    pub fn record_diagnostics(&self, observation: &'static str) {
        if tracing::enabled!(tracing::Level::DEBUG) {
            let stats = self.connection.stats();
            tracing::debug!(
                observation, carrier = "quic", peer = %self.peer_addr(),
                connection_id = self.connection_id(),
                rtt_us = stats.path.rtt.as_micros() as u64,
                cwnd = stats.path.cwnd, mtu = stats.path.current_mtu,
                sent_packets = stats.path.sent_packets, lost_packets = stats.path.lost_packets,
                congestion_events = stats.path.congestion_events,
                tx_bytes = stats.udp_tx.bytes, rx_bytes = stats.udp_rx.bytes,
                tx_datagrams = stats.udp_tx.datagrams, tx_ios = stats.udp_tx.ios,
                rx_datagrams = stats.udp_rx.datagrams, rx_ios = stats.udp_rx.ios,
                peer_stream_blocked = stats.frame_rx.stream_data_blocked,
                peer_connection_blocked = stats.frame_rx.data_blocked,
                "QUIC cumulative connection statistics"
            );
        }
    }
}
impl Drop for QuicStream {
    fn drop(&mut self) {
        self.record_diagnostics("stream_closed");
        // An unfinished request is cancellation, not an implicit successful FIN.
        if !self.finished {
            let _ = self.send.reset(CANCELLED);
        }
        let _ = self.recv.stop(CANCELLED);
    }
}
impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.finished = true;
        }
        result
    }
}

struct PooledConnection {
    connection: Connection,
    owner: Arc<EndpointOwner>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    runtime: tokio::runtime::Id,
    host: String,
    port: u16,
    credential: Vec<u8>,
    trust_generation: u64,
    addresses: Vec<IpAddr>,
}
type PoolEntry = Arc<Mutex<Option<Arc<PooledConnection>>>>;
static POOL: LazyLock<Cache<PoolKey, PoolEntry>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(32)
        .time_to_idle(Duration::from_secs(60))
        .build()
});
static DIAL_SLOTS: Semaphore = Semaphore::const_new(16);
static CLIENT_CONFIG: LazyLock<RwLock<(u64, Option<quinn::ClientConfig>)>> =
    LazyLock::new(|| RwLock::new((0, None)));

/// Replace trust for subsequent negotiations. Established sessions retain their
/// original identity and keys; changing this never mutates an in-flight dial.
pub fn configure_trust(ca_file: Option<&Path>) -> io::Result<()> {
    let pem = ca_file.map(std::fs::read).transpose()?;
    let config = client_config(pem.as_deref())?;
    let mut current = CLIENT_CONFIG.write();
    current.0 += 1;
    current.1 = Some(config);
    Ok(())
}

/// Dial a new session, reusing only a fully authenticated connection. A failed
/// stream or payload is never retried. Reconnection is for subsequent sessions.
pub async fn connect(host: &str, port: u16) -> io::Result<QuicStream> {
    let addresses = crate::transport::resolve_host_addresses(host).await?;
    connect_addresses(host, port, &addresses).await
}

/// Dial only addresses covered by a caller's prepared route bypass. The TLS
/// name remains the original host and the pool cannot reuse an unprepared IP.
pub async fn connect_addresses(
    host: &str,
    port: u16,
    addresses: &[IpAddr],
) -> io::Result<QuicStream> {
    let secret = crate::config::runtime::with_secret_key(|key, _| key.to_vec());
    let (generation, config) = {
        let mut current = CLIENT_CONFIG.write();
        if current.1.is_none() {
            let pem = std::env::var_os("PROXY_QUIC_CA")
                .map(std::fs::read)
                .transpose()?;
            current.1 = Some(client_config(pem.as_deref())?);
        }
        (
            current.0,
            current.1.as_ref().expect("initialized QUIC trust").clone(),
        )
    };
    let pool_key = PoolKey {
        runtime: tokio::runtime::Handle::current().id(),
        host: host.into(),
        port,
        credential: digest::digest(&digest::SHA256, &secret).as_ref().to_vec(),
        trust_generation: generation,
        addresses: addresses.to_vec(),
    };
    let entry = POOL.get_with(pool_key, || Arc::new(Mutex::new(None)));
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let pooled = {
            let mut slot = entry.lock().await;
            if slot.as_ref().is_some_and(|p| p.connection.close_reason().is_some()) { *slot = None; }
            if slot.is_none() {
                let _permit = DIAL_SLOTS.acquire().await.map_err(io::Error::other)?;
                let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no QUIC address");
                // Address selection occurs before authentication or application data.
                for address in addresses.iter() {
                    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                    let mut endpoint = Endpoint::client(bind.parse().expect("literal socket address"))?;
                    endpoint.set_default_client_config(config.clone());
                    let owner = Arc::new(EndpointOwner(endpoint));
                    let connecting = owner.0.connect(SocketAddr::new(*address, port), host).map_err(io::Error::other)?;
                    match tokio::time::timeout(Duration::from_secs(4), connecting).await {
                        Ok(Ok(connection)) => {
                            if let Err(error) = authenticate(&connection, &secret, false).await {
                                connection.close(AUTH_FAILED, b"authentication failed");
                                return Err(error);
                            }
                            tracing::info!(carrier = "quic", peer = %connection.remote_address(), "opened authenticated QUIC connection");
                            *slot = Some(Arc::new(PooledConnection { connection, owner }));
                            break;
                        }
                        Ok(Err(error)) => last_error = io::Error::other(error),
                        Err(error) => last_error = timeout(error),
                    }
                }
                if slot.is_none() { return Err(last_error); }
            }
            slot.as_ref().expect("authenticated connection").clone()
        };
        let (send, recv) = pooled.connection.open_bi().await.map_err(io::Error::other)?;
        Ok(QuicStream::new(send, recv, pooled.connection.clone(), pooled.owner.clone()))
    }).await.map_err(timeout)?
}

/// Close this runtime's pooled connections and retain UDP drivers until drained.
pub async fn shutdown_clients() {
    let runtime = tokio::runtime::Handle::current().id();
    let mut endpoints = Vec::new();
    for (key, entry) in POOL.iter() {
        if key.runtime == runtime {
            if let Some(pooled) = entry.lock().await.take() {
                pooled.connection.close(0u32.into(), b"shutdown");
                endpoints.push(pooled.owner.clone());
            }
            POOL.invalidate(key.as_ref());
        }
    }
    let _ = tokio::time::timeout(
        DRAIN_TIMEOUT,
        futures::future::join_all(endpoints.iter().map(|owner| owner.0.wait_idle())),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    const CERT: &[u8] = include_bytes!("../tests/fixtures/quic-cert.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/quic-key.pem");
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn tls_identity_alpn_and_application_credentials_are_independent_requirements() {
        let endpoint = Arc::new(EndpointOwner(
            Endpoint::server(
                server_config(CERT, KEY).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap(),
        ));
        let addr = endpoint.0.local_addr().unwrap();
        for rejection in ["untrusted", "name", "alpn", "credential"] {
            let mut config = client_config((rejection != "untrusted").then_some(CERT)).unwrap();
            if rejection == "alpn" {
                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(CertificateDer::from_pem_slice(CERT).unwrap())
                    .unwrap();
                let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                tls.alpn_protocols = vec![b"unrelated/1".to_vec()];
                config = quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
                ));
            }
            let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(config);
            let client = Arc::new(EndpointOwner(client));
            let name = if rejection == "name" {
                "other.example"
            } else {
                "localhost"
            };
            let server = async {
                let incoming = endpoint.0.accept().await.unwrap();
                assert!(
                    AuthenticatedConnection::accept(incoming, endpoint.clone(), SECRET)
                        .await
                        .is_err()
                );
            };
            let consumer = async {
                let result = async {
                    let connection = client
                        .0
                        .connect(addr, name)
                        .unwrap()
                        .await
                        .map_err(io::Error::other)?;
                    authenticate(&connection, b"wrong-credential", false).await
                }
                .await;
                assert!(
                    result.is_err(),
                    "{rejection} must fail before an application stream"
                );
            };
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(server, consumer);
            })
            .await
            .unwrap();
        }
        endpoint.0.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.0.wait_idle()).await;
    }
}
