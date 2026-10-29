//! TLS-verified QUIC carriers with exporter-bound application authentication.
//!
//! No application stream is accepted before authentication. No 0-RTT or TCP
//! fallback is used: once a stream is returned, its request must never be replayed.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use moka::sync::Cache;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use ring::{digest, hmac};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Semaphore};

mod health;

pub const ALPN: &[u8] = b"proxy-everything/1";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
/// Authenticated connections a server keeps open.
pub const MAX_CONNECTIONS: usize = 128;
/// Handshakes a server runs at once. Separate from [`MAX_CONNECTIONS`], so peers
/// that never authenticate cannot displace clients that did.
pub const MAX_HANDSHAKES: usize = 64;
/// Concurrent sessions per connection. Each client pools one connection per
/// upstream, so this must cover a busy browser's socket pool, not one request.
pub const MAX_STREAMS: u32 = 1024;
const IDLE_TIMEOUT_MS: u32 = 30_000;
/// A third of the idle timeout: idle sessions and NAT bindings survive two lost pings.
const KEEP_ALIVE: Duration = Duration::from_secs(10);
/// A pooled connection with no new or open sessions for this long is closed, so
/// keep-alive never pings on behalf of an idle client.
const POOL_LINGER: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
const AUTH_FAILED: VarInt = VarInt::from_u32(2);

fn transport(
    incoming_streams: u32,
    keep_alive: Option<Duration>,
) -> io::Result<Arc<quinn::TransportConfig>> {
    // Some UDP paths accept GSO writes but silently discard their segments.
    // Keep reliable per-datagram sends by default; verified hosts may opt in.
    let gso = match std::env::var("PROXY_QUIC_GSO") {
        Ok(value) => value.parse::<bool>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXY_QUIC_GSO must be true or false",
            )
        })?,
        Err(std::env::VarError::NotPresent) => false,
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    };
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(incoming_streams.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
        .keep_alive_interval(keep_alive)
        .stream_receive_window(VarInt::from_u32(1024 * 1024))
        .receive_window(VarInt::from_u32(8 * 1024 * 1024))
        .send_window(8 * 1024 * 1024)
        .send_fairness(true)
        .enable_segmentation_offload(gso)
        .datagram_receive_buffer_size(None);
    Ok(Arc::new(config))
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
    // Only the client pings: a server cannot keep a suspended client reachable.
    config.transport_config(transport(0, Some(KEEP_ALIVE))?);
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
    config.transport_config(transport(1, None)?);
    // Migration stays enabled: quinn validates a new path before using it, and a
    // client that rebinds its NAT or changes network keeps its sessions instead of
    // routing new ones onto a connection the server silently ignores.
    config
        .max_incoming(MAX_HANDSHAKES)
        .incoming_buffer_size_total(4 * 1024 * 1024);
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

/// One authenticated connection, shared by its streams. Holding it keeps the
/// UDP driver alive; its strong count is the number of users.
struct SharedConnection {
    connection: Connection,
    owner: Arc<EndpointOwner>,
    health: Arc<health::Health>,
    /// Streams opened so far, so the pool can tell idle from short-lived use.
    opened: AtomicU64,
}

impl SharedConnection {
    fn new(connection: Connection, owner: Arc<EndpointOwner>, side: quinn::Side) -> Arc<Self> {
        let health = health::Health::start(&connection, owner.0.local_addr().ok(), side);
        Arc::new(Self {
            connection,
            owner,
            health,
            opened: AtomicU64::new(0),
        })
    }
}

impl Drop for SharedConnection {
    fn drop(&mut self) {
        // A monitor's Connection clone must not keep an abandoned server-side
        // connection alive when its shared listener endpoint remains running.
        self.health.released.cancel();
    }
}

/// Only authenticated connections can produce application streams.
pub struct AuthenticatedConnection(Arc<SharedConnection>);

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
        let shared = SharedConnection::new(connection, owner, quinn::Side::Server);
        tracing::info!(carrier = "quic", connection_id = shared.health.id,
            local_addr = ?shared.owner.0.local_addr().ok(), peer = %shared.connection.remote_address(),
            "authenticated QUIC connection");
        Ok(Self(shared))
    }

    pub async fn accept_stream(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .0
            .connection
            .accept_bi()
            .await
            .map_err(io::Error::other)?;
        Ok(QuicStream {
            send,
            recv,
            shared: Arc::clone(&self.0),
        })
    }

    pub fn close(&self) {
        self.0.connection.close(0u32.into(), b"shutdown");
    }
}

fn timeout(_: tokio::time::error::Elapsed) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "QUIC connection/stream deadline exceeded; TCP fallback is disabled",
    )
}

/// One QUIC stream, closed independently of its siblings.
///
/// Dropping it behaves like closing a TCP socket: bytes already written are
/// delivered before FIN, and unread input is stopped. Write-then-close paths,
/// such as an error status sent just before returning, therefore work the same
/// on both carriers.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    shared: Arc<SharedConnection>,
}
impl QuicStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.owner.0.local_addr()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.shared.connection.remote_address()
    }

    pub fn connection_id(&self) -> usize {
        self.shared.health.id
    }

    pub fn record_diagnostics(&self, observation: &'static str) {
        if tracing::enabled!(tracing::Level::DEBUG) {
            self.shared.health.record(
                &self.shared.connection,
                tracing::Level::DEBUG,
                observation,
                "observation",
                None,
            );
        }
    }
}
impl Drop for QuicStream {
    fn drop(&mut self) {
        // The fields' own drops finish the send half and stop the receive half.
        self.record_diagnostics("stream_closed");
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
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    runtime: tokio::runtime::Id,
    host: Box<str>,
    port: u16,
    credential: [u8; 32],
    trust_generation: u64,
    addresses: Arc<[IpAddr]>,
}
/// One pooled connection; sessions and the idle reaper take turns under its lock.
type PoolSlot = Mutex<Option<Arc<SharedConnection>>>;
type PoolEntry = Arc<PoolSlot>;
static POOL: LazyLock<Cache<PoolKey, PoolEntry>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(32)
        .time_to_idle(Duration::from_secs(60))
        .build()
});
static DIAL_SLOTS: Semaphore = Semaphore::const_new(16);

struct Trust {
    generation: u64,
    config: quinn::ClientConfig,
}
static TRUST: ArcSwapOption<Trust> = ArcSwapOption::const_empty();

/// Replace trust for subsequent negotiations. Established sessions retain their
/// original identity and keys; changing this never mutates an in-flight dial.
pub fn configure_trust(ca_file: Option<&Path>) -> io::Result<()> {
    let pem = ca_file.map(std::fs::read).transpose()?;
    let config = client_config(pem.as_deref())?;
    TRUST.rcu(|current| {
        Some(Arc::new(Trust {
            generation: current.as_ref().map_or(0, |trust| trust.generation) + 1,
            config: config.clone(),
        }))
    });
    Ok(())
}

/// The current trust snapshot, lock-free after the first call. Without an
/// explicit [`configure_trust`], it is the Mozilla roots plus `PROXY_QUIC_CA`.
fn trust() -> io::Result<Arc<Trust>> {
    if let Some(trust) = TRUST.load_full() {
        return Ok(trust);
    }
    let pem = std::env::var_os("PROXY_QUIC_CA")
        .map(std::fs::read)
        .transpose()?;
    let trust = Arc::new(Trust {
        generation: 0,
        config: client_config(pem.as_deref())?,
    });
    // An explicit configuration that raced this default wins.
    let previous = TRUST.compare_and_swap(&None::<Arc<Trust>>, Some(Arc::clone(&trust)));
    Ok(Option::clone(&previous).unwrap_or(trust))
}

fn credential() -> [u8; 32] {
    crate::config::runtime::with_secret_key(|key, _| {
        let mut credential = [0; 32];
        credential.copy_from_slice(digest::digest(&digest::SHA256, key).as_ref());
        credential
    })
}

/// Dial a new session, reusing only a fully authenticated connection. A failed
/// stream or payload is never retried; a failed dial sends no application byte,
/// so it is retried once against refreshed DNS, as TCP connections are.
pub async fn connect(host: &str, port: u16) -> io::Result<QuicStream> {
    let addresses = crate::transport::resolve_host_addresses(host).await?;
    match connect_addresses(host, port, &addresses).await {
        Err(error)
            if error.kind() != io::ErrorKind::PermissionDenied
                && host.parse::<IpAddr>().is_err() =>
        {
            let refreshed = crate::transport::refresh_host_addresses(host).await?;
            if refreshed == addresses {
                return Err(error);
            }
            connect_addresses(host, port, &refreshed).await
        }
        result => result,
    }
}

/// Dial only addresses covered by a caller's prepared route bypass. The TLS
/// name remains the original host and the pool cannot reuse an unprepared IP.
pub async fn connect_addresses(
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
) -> io::Result<QuicStream> {
    let trust = trust()?;
    let pool_key = PoolKey {
        runtime: tokio::runtime::Handle::current().id(),
        host: host.into(),
        port,
        credential: credential(),
        trust_generation: trust.generation,
        addresses: Arc::clone(addresses),
    };
    let entry = POOL.get_with(pool_key, PoolEntry::default);
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            let shared = {
                let mut slot = entry.lock().await;
                match slot.as_ref() {
                    Some(shared)
                        if !shared.health.isolated.is_cancelled()
                            && shared.connection.close_reason().is_none() =>
                    {
                        Arc::clone(shared)
                    }
                    _ => {
                        let shared = dial(host, port, addresses, &trust.config).await?;
                        tokio::spawn(close_when_idle(
                            shared.connection.clone(),
                            Arc::downgrade(&entry),
                            POOL_LINGER,
                        ));
                        *slot = Some(Arc::clone(&shared));
                        shared
                    }
                }
            };
            let (send, recv) = tokio::select! {
                biased;
                _ = shared.health.isolated.cancelled() => continue,
                stream = shared.connection.open_bi() => stream.map_err(io::Error::other)?,
            };
            if shared.health.isolated.is_cancelled() {
                // No application byte has been handed to the caller. Only stream
                // acquisition may move to another connection; payloads never do.
                continue;
            }
            shared.opened.fetch_add(1, Ordering::Relaxed);
            return Ok(QuicStream { send, recv, shared });
        }
    })
    .await
    .map_err(timeout)?
}

/// Confirm that an authenticated peer answers, without opening a session.
/// A pooled connection cannot prove this: opening a stream on it is local.
pub async fn probe(host: &str, port: u16) -> io::Result<()> {
    let addresses = crate::transport::resolve_host_addresses(host).await?;
    let trust = trust()?;
    let shared = tokio::time::timeout(CONNECT_TIMEOUT, dial(host, port, &addresses, &trust.config))
        .await
        .map_err(timeout)??;
    shared.connection.close(0u32.into(), b"probe");
    Ok(())
}

async fn dial(
    host: &str,
    port: u16,
    addresses: &[IpAddr],
    config: &quinn::ClientConfig,
) -> io::Result<Arc<SharedConnection>> {
    let _permit = DIAL_SLOTS.acquire().await.map_err(io::Error::other)?;
    let started = Instant::now();
    // TCP's staggered, family-interleaved race; no application data is sent
    // until a handshake has won.
    let (connection, owner) = crate::transport::race_addresses(addresses, port, false, |address| {
        handshake(address, host, config)
    })
    .await?;
    let secret = crate::config::runtime::with_secret_key(|key, _| key.to_vec());
    if let Err(error) = authenticate(&connection, &secret, false).await {
        connection.close(AUTH_FAILED, b"authentication failed");
        return Err(error);
    }
    let shared = SharedConnection::new(connection, owner, quinn::Side::Client);
    tracing::info!(
        carrier = "quic", connection_id = shared.health.id,
        local_addr = ?shared.owner.0.local_addr().ok(), peer = %shared.connection.remote_address(),
        handshake_us = started.elapsed().as_micros() as u64,
        "opened authenticated QUIC connection"
    );
    Ok(shared)
}

async fn handshake(
    address: SocketAddr,
    host: &str,
    config: &quinn::ClientConfig,
) -> io::Result<(Connection, Arc<EndpointOwner>)> {
    let bind = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let owner = Arc::new(EndpointOwner(Endpoint::client(bind)?));
    let connecting = owner
        .0
        .connect_with(config.clone(), address, host)
        .map_err(io::Error::other)?;
    let connection = tokio::time::timeout(ATTEMPT_TIMEOUT, connecting)
        .await
        .map_err(timeout)?
        .map_err(io::Error::other)?;
    Ok((connection, owner))
}

/// Evict a pooled connection once a full linger period passes with no session
/// open and none opened. Dropping the evicted slot's last reference closes the
/// endpoint, which ends this task.
async fn close_when_idle(connection: Connection, entry: Weak<PoolSlot>, linger: Duration) {
    let mut last_opened = None;
    loop {
        tokio::select! {
            _ = connection.closed() => return,
            _ = tokio::time::sleep(linger) => {}
        }
        // Once evicted from the cache, no new session can reach this connection.
        let Some(entry) = entry.upgrade() else { return };
        let mut slot = entry.lock().await;
        // Sessions clone the slot under this lock, so no stream can be added
        // between this check and the eviction.
        let idle = match slot.as_ref() {
            Some(shared) if shared.connection.stable_id() == connection.stable_id() => {
                let opened = shared.opened.load(Ordering::Relaxed);
                let idle = Arc::strong_count(shared) == 1 && last_opened == Some(opened);
                last_opened = Some(opened);
                idle
            }
            _ => return,
        };
        if idle {
            *slot = None;
            return;
        }
    }
}

/// Close this runtime's pooled connections and retain UDP drivers until drained.
pub async fn shutdown_clients() {
    let runtime = tokio::runtime::Handle::current().id();
    let mut endpoints = Vec::new();
    for (key, entry) in POOL.iter() {
        if key.runtime == runtime {
            if let Some(shared) = entry.lock().await.take() {
                shared.connection.close(0u32.into(), b"shutdown");
                endpoints.push(Arc::clone(&shared.owner));
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    const CERT: &[u8] = include_bytes!("../tests/fixtures/quic-cert.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/quic-key.pem");
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn server_endpoint() -> Arc<EndpointOwner> {
        Arc::new(EndpointOwner(
            Endpoint::server(
                server_config(CERT, KEY).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap(),
        ))
    }

    #[tokio::test]
    async fn tls_identity_alpn_and_application_credentials_are_independent_requirements() {
        let endpoint = server_endpoint();
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

    /// A client connection authenticated against a loopback server, with the
    /// server's side returned so it stays open.
    async fn authenticated_pair() -> (
        Arc<EndpointOwner>,
        AuthenticatedConnection,
        Arc<SharedConnection>,
    ) {
        let endpoint = server_endpoint();
        let addr = endpoint.0.local_addr().unwrap();
        let server = async {
            let incoming = endpoint.0.accept().await.unwrap();
            AuthenticatedConnection::accept(incoming, endpoint.clone(), SECRET)
                .await
                .unwrap()
        };
        let client = async {
            let config = client_config(Some(CERT)).unwrap();
            let (connection, owner) = handshake(addr, "localhost", &config).await.unwrap();
            authenticate(&connection, SECRET, false).await.unwrap();
            SharedConnection::new(connection, owner, quinn::Side::Client)
        };
        let (server, client) = tokio::join!(server, client);
        (endpoint, server, client)
    }

    fn open(shared: &Arc<SharedConnection>, (send, recv): (SendStream, RecvStream)) -> QuicStream {
        shared.opened.fetch_add(1, Ordering::Relaxed);
        QuicStream {
            send,
            recv,
            shared: Arc::clone(shared),
        }
    }

    #[tokio::test]
    async fn dropped_stream_delivers_its_last_bytes_and_spares_siblings() {
        let (endpoint, server, client) = authenticated_pair().await;
        let replies = tokio::spawn(async move {
            for status in [b"first", b"other"] {
                let mut stream = server.accept_stream().await.unwrap();
                stream.read_u8().await.unwrap();
                // An error status written right before returning, as server/udp.rs does.
                stream.write_all(status).await.unwrap();
            }
            server
        });
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = open(&client, client.connection.open_bi().await.unwrap());
            stream.write_u8(0).await.unwrap();
            streams.push(stream);
        }
        let server = replies.await.unwrap();
        for (mut stream, expected) in streams.into_iter().zip([b"first", b"other"]) {
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
        }
        server.close();
        endpoint.0.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn dropping_server_connection_releases_its_monitor_while_listener_stays_alive() {
        let (endpoint, server, client) = authenticated_pair().await;
        drop(server);
        tokio::time::timeout(Duration::from_secs(2), client.connection.closed())
            .await
            .unwrap();
        assert_eq!(Arc::strong_count(&endpoint), 1);
        endpoint.0.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn pooled_connection_is_evicted_only_after_its_streams_close() {
        let (endpoint, server, client) = authenticated_pair().await;
        let connection = client.connection.clone();
        let stream = open(&client, connection.open_bi().await.unwrap());
        let entry: PoolEntry = Arc::new(Mutex::new(Some(client)));
        let linger = Duration::from_millis(50);
        let reaper = tokio::spawn(close_when_idle(
            connection.clone(),
            Arc::downgrade(&entry),
            linger,
        ));
        tokio::time::sleep(linger * 4).await;
        assert!(
            entry.lock().await.is_some(),
            "an open stream keeps its connection pooled"
        );
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .unwrap()
            .unwrap();
        assert!(entry.lock().await.is_none());
        // Evicting the last reference closes the client endpoint and its connection.
        tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .unwrap();
        server.close();
        endpoint.0.close(0u32.into(), b"done");
    }
}
