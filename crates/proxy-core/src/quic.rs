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
use std::time::Duration;

use arc_swap::ArcSwapOption;
use moka::sync::Cache;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use ring::{digest, hmac};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

mod health;
mod selector;

pub use selector::{
    ConnectError, FailureKind, SelectorStats, StandbyRule, classify_error, configure_standby,
    connect_error, selector_stats,
};
use selector::{Ingress, PoolStatus, SelectorKey, SharedDialError};

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

fn classify_auth_write(error: quinn::WriteError) -> SharedDialError {
    match error {
        quinn::WriteError::ConnectionLost(lost) => selector::classify_connection_error(lost, true),
        quinn::WriteError::Stopped(code) if code == AUTH_FAILED => {
            SharedDialError::authentication_failed()
        }
        quinn::WriteError::Stopped(_)
        | quinn::WriteError::ClosedStream
        | quinn::WriteError::ZeroRttRejected => {
            SharedDialError::from_io(FailureKind::Unreachable, io::Error::other(error))
        }
    }
}

fn classify_auth_read(error: quinn::ReadToEndError) -> SharedDialError {
    match error {
        quinn::ReadToEndError::TooLong => SharedDialError::authentication_failed(),
        quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(lost)) => {
            selector::classify_connection_error(lost, true)
        }
        quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) if code == AUTH_FAILED => {
            SharedDialError::authentication_failed()
        }
        quinn::ReadToEndError::Read(other) => {
            SharedDialError::from_io(FailureKind::Unreachable, io::Error::other(other))
        }
    }
}

async fn authenticate_classified(
    connection: &Connection,
    key: &hmac::Key,
    server: bool,
) -> Result<(), SharedDialError> {
    let (send_role, receive_role): (&[u8], &[u8]) = if server {
        (b"server", b"client")
    } else {
        (b"client", b"server")
    };
    let own_tag = hmac::sign(
        key,
        &binding(connection, send_role)
            .map_err(|err| SharedDialError::from_io(FailureKind::Tls, err))?,
    );
    let peer_binding = binding(connection, receive_role)
        .map_err(|err| SharedDialError::from_io(FailureKind::Tls, err))?;
    let (mut send, mut recv) = if server {
        connection.accept_bi().await
    } else {
        connection.open_bi().await
    }
    .map_err(|err| selector::classify_connection_error(err, true))?;
    if !server {
        send.write_all(own_tag.as_ref())
            .await
            .map_err(classify_auth_write)?;
        send.finish()
            .map_err(|_| SharedDialError::admission_closed())?;
    }
    let tag = recv.read_to_end(32).await.map_err(classify_auth_read)?;
    hmac::verify(key, &peer_binding, &tag).map_err(|_| SharedDialError::authentication_failed())?;
    if server {
        send.write_all(own_tag.as_ref())
            .await
            .map_err(classify_auth_write)?;
        send.finish()
            .map_err(|_| SharedDialError::admission_closed())?;
        connection.set_max_concurrent_bi_streams(MAX_STREAMS.into());
    }
    Ok(())
}

async fn authenticate(connection: &Connection, key: &hmac::Key, server: bool) -> io::Result<()> {
    authenticate_classified(connection, key, server)
        .await
        .map_err(SharedDialError::into_carrier_io_error)
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

    fn is_usable(&self) -> bool {
        !self.health.isolated.is_cancelled() && self.connection.close_reason().is_none()
    }

    fn is_faulted(&self) -> bool {
        self.health.faulted.load(Ordering::Acquire)
            || self
                .connection
                .close_reason()
                .is_some_and(|reason| !health::is_normal_close(&reason))
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
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let connection = tokio::time::timeout(CONNECT_TIMEOUT, incoming)
            .await
            .map_err(timeout)?
            .map_err(io::Error::other)?;
        if let Err(error) =
            tokio::time::timeout(CONNECT_TIMEOUT, authenticate(&connection, &key, true))
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

type DialOutcome = Result<Arc<SharedConnection>, SharedDialError>;

struct InFlightDial {
    cancel: CancellationToken,
    results: watch::Receiver<Option<DialOutcome>>,
}

struct DialSlotState {
    dial: Arc<InFlightDial>,
    waiters: usize,
}

/// Physical connection pool slot for one `(host, dialed_port, identity, addresses)`.
///
/// Lock is synchronous and never held across `.await` or destructor drops.
#[derive(Default)]
struct PoolState {
    connection: Option<Arc<SharedConnection>>,
    inflight: Option<DialSlotState>,
}

impl PoolState {
    #[cfg(test)]
    fn with_connection(connection: Arc<SharedConnection>) -> Self {
        Self {
            connection: Some(connection),
            inflight: None,
        }
    }
}

type PoolSlot = Mutex<PoolState>;
type PoolEntry = Arc<PoolSlot>;
static POOL: LazyLock<Cache<PoolKey, PoolEntry>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(64)
        .time_to_idle(Duration::from_secs(60))
        .build()
});
static DIAL_SLOTS: Semaphore = Semaphore::const_new(16);

struct DialWaiter {
    entry: PoolEntry,
    dial: Arc<InFlightDial>,
    results: watch::Receiver<Option<DialOutcome>>,
    disarmed: bool,
}

impl DialWaiter {
    async fn wait(&mut self) -> DialOutcome {
        let outcome = match self.results.wait_for(Option::is_some).await {
            Ok(ready) => ready
                .as_ref()
                .expect("watch predicate matched Some")
                .clone(),
            Err(_) => Err(SharedDialError::admission_closed()),
        };
        self.disarmed = true;
        outcome
    }
}

impl Drop for DialWaiter {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        // A single waiter timing out or being cancelled must not abort other
        // active waiters sharing the dial; only the last waiter cancels it.
        let cancel = {
            let mut state = self.entry.lock();
            match state.inflight.as_mut() {
                Some(slot) if Arc::ptr_eq(&slot.dial, &self.dial) => {
                    slot.waiters = slot.waiters.saturating_sub(1);
                    if slot.waiters == 0 {
                        state
                            .inflight
                            .take()
                            .map(|removed| removed.dial.cancel.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
    }
}

enum Checkout {
    Pooled(Arc<SharedConnection>),
    Dialing(DialWaiter),
}

fn pool_status(entry: &PoolEntry) -> PoolStatus {
    let state = entry.lock();
    match state.connection.as_ref() {
        Some(shared) if shared.is_usable() => PoolStatus::Healthy,
        Some(shared) if shared.is_faulted() => PoolStatus::Faulted(shared.health.id),
        Some(_) | None => PoolStatus::Empty,
    }
}

fn has_healthy_or_inflight(entry: &PoolEntry) -> bool {
    let state = entry.lock();
    state.inflight.is_some()
        || state
            .connection
            .as_ref()
            .is_some_and(|shared| shared.is_usable())
}

fn try_checkout_pooled(entry: &PoolEntry) -> Option<Arc<SharedConnection>> {
    let state = entry.lock();
    state
        .connection
        .as_ref()
        .filter(|shared| shared.is_usable())
        .cloned()
}

fn retire_connection(entry: &PoolEntry, id: usize) {
    let evicted = {
        let mut state = entry.lock();
        if state
            .connection
            .as_ref()
            .is_some_and(|shared| shared.health.id == id)
        {
            state.connection.take()
        } else {
            None
        }
    };
    drop(evicted);
}

fn checkout_or_dial(
    ingress: Ingress,
    entry: &PoolEntry,
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
    config: &quinn::ClientConfig,
    credential: &Credential,
) -> Checkout {
    let (dial, tx, rx, stale) = {
        let mut state = entry.lock();
        if let Some(shared) = state.connection.as_ref()
            && shared.is_usable()
        {
            return Checkout::Pooled(Arc::clone(shared));
        }
        let stale = state.connection.take();
        if let Some(slot) = state.inflight.as_mut() {
            slot.waiters += 1;
            let dial = Arc::clone(&slot.dial);
            let results = slot.dial.results.clone();
            drop(state);
            drop(stale);
            return Checkout::Dialing(DialWaiter {
                entry: Arc::clone(entry),
                dial,
                results,
                disarmed: false,
            });
        }
        let (tx, rx) = watch::channel(None);
        let dial = Arc::new(InFlightDial {
            cancel: CancellationToken::new(),
            results: rx.clone(),
        });
        state.inflight = Some(DialSlotState {
            dial: Arc::clone(&dial),
            waiters: 1,
        });
        (dial, tx, rx, stale)
    };
    drop(stale);
    tokio::spawn(run_inflight_dial(
        Arc::clone(entry),
        Arc::clone(&dial),
        tx,
        DialSpec {
            ingress,
            host: host.to_owned(),
            port,
            addresses: Arc::clone(addresses),
            config: config.clone(),
            credential: credential.clone(),
        },
    ));
    Checkout::Dialing(DialWaiter {
        entry: Arc::clone(entry),
        dial,
        results: rx,
        disarmed: false,
    })
}

struct DialSpec {
    ingress: Ingress,
    host: String,
    port: u16,
    addresses: Arc<[IpAddr]>,
    config: quinn::ClientConfig,
    credential: Credential,
}

async fn run_inflight_dial(
    entry: PoolEntry,
    dial: Arc<InFlightDial>,
    tx: watch::Sender<Option<DialOutcome>>,
    spec: DialSpec,
) {
    let outcome = tokio::select! {
        biased;
        _ = dial.cancel.cancelled() => return,
        timed = tokio::time::timeout(
            CONNECT_TIMEOUT,
            dial_shared(
                spec.ingress,
                &spec.host,
                spec.port,
                &spec.addresses,
                &spec.config,
                &spec.credential,
            ),
        ) => match timed {
            Ok(result) => result,
            Err(_) => Err(SharedDialError::timeout()),
        }
    };
    let mut abort_unused = None;
    let mut replaced_old = None;
    {
        let mut state = entry.lock();
        let active = state
            .inflight
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.dial, &dial))
            && !dial.cancel.is_cancelled();
        if active {
            state.inflight = None;
            if let Ok(shared) = &outcome {
                tokio::spawn(close_when_idle(
                    shared.connection.clone(),
                    Arc::downgrade(&entry),
                    POOL_LINGER,
                ));
                replaced_old = state.connection.replace(Arc::clone(shared));
            }
        } else {
            if state
                .inflight
                .as_ref()
                .is_some_and(|slot| Arc::ptr_eq(&slot.dial, &dial))
            {
                state.inflight = None;
            }
            if let Ok(shared) = &outcome {
                abort_unused = Some(Arc::clone(shared));
            }
        }
    }
    drop(replaced_old);
    if let Some(unused) = abort_unused {
        unused.connection.close(0u32.into(), b"cancelled");
        return;
    }
    let _ = tx.send(Some(outcome));
}

enum StreamAcquireFailure {
    Stale {
        id: usize,
        faulted: bool,
        error: SharedDialError,
    },
    DeadlineExceeded,
}

async fn open_stream_on(
    entry: &PoolEntry,
    shared: Arc<SharedConnection>,
    deadline: Instant,
) -> Result<QuicStream, StreamAcquireFailure> {
    let timed = tokio::time::timeout_at(deadline, async {
        tokio::select! {
            biased;
            _ = shared.health.isolated.cancelled() => Err(SharedDialError::admission_closed()),
            stream = shared.connection.open_bi() => {
                stream.map_err(|err| selector::classify_connection_error(err, false))
            }
        }
    })
    .await;
    let Ok(acquired) = timed else {
        return Err(StreamAcquireFailure::DeadlineExceeded);
    };
    if !shared.is_usable() {
        let faulted = shared.is_faulted();
        let id = shared.health.id;
        shared.health.isolated.cancel();
        retire_connection(entry, id);
        let error = acquired
            .err()
            .unwrap_or_else(SharedDialError::admission_closed);
        return Err(StreamAcquireFailure::Stale { id, faulted, error });
    }
    match acquired {
        Ok((send, recv)) => {
            shared.opened.fetch_add(1, Ordering::Relaxed);
            Ok(QuicStream { send, recv, shared })
        }
        Err(error) => {
            let faulted = shared.is_faulted();
            let id = shared.health.id;
            shared.health.isolated.cancel();
            retire_connection(entry, id);
            Err(StreamAcquireFailure::Stale { id, faulted, error })
        }
    }
}

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

#[derive(Clone)]
struct Credential {
    digest: [u8; 32],
    key: hmac::Key,
}

impl Credential {
    fn new(secret: &[u8]) -> Self {
        let mut digest = [0; 32];
        digest.copy_from_slice(digest::digest(&digest::SHA256, secret).as_ref());
        Self {
            digest,
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        }
    }

    fn snapshot() -> Self {
        crate::config::runtime::with_secret_key(|key, _| Self::new(key))
    }
}

/// Dial a new session, reusing only a fully authenticated connection. A failed
/// stream or payload is never retried; a failed dial sends no application byte,
/// so it is retried once against refreshed DNS within the shared acquisition deadline.
pub async fn connect(host: &str, port: u16) -> io::Result<QuicStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let addresses =
        tokio::time::timeout_at(deadline, crate::transport::resolve_host_addresses(host))
            .await
            .map_err(|_| SharedDialError::timeout().into_io_error())??;
    match connect_addresses_until(host, port, &addresses, deadline).await {
        Err(error)
            if classify_error(&error).is_retryable()
                && host.parse::<IpAddr>().is_err()
                && Instant::now() < deadline =>
        {
            let Ok(refreshed) =
                tokio::time::timeout_at(deadline, crate::transport::refresh_host_addresses(host))
                    .await
            else {
                return Err(error);
            };
            let refreshed = refreshed?;
            if refreshed == addresses || Instant::now() >= deadline {
                return Err(error);
            }
            connect_addresses_until(host, port, &refreshed, deadline).await
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
    connect_addresses_until(host, port, addresses, Instant::now() + CONNECT_TIMEOUT).await
}

async fn connect_addresses_until(
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
    deadline: Instant,
) -> io::Result<QuicStream> {
    let trust = trust()?;
    let standby_table = selector::standby()?;
    // Pool identity, selector state and authentication share immutable snapshots,
    // even if configuration changes while waiting for a slot or handshake.
    let credential = Credential::snapshot();
    let runtime = tokio::runtime::Handle::current().id();
    if let Ok(normalized_host) = selector::normalize_node_host(host)
        && let Some(standby_port) = standby_table.lookup(&normalized_host, port)
    {
        return connect_dual_until(
            runtime,
            host,
            normalized_host,
            port,
            standby_port.get(),
            addresses,
            &trust,
            &credential,
            standby_table.generation,
            deadline,
        )
        .await;
    }
    let pool_key = PoolKey {
        runtime,
        host: host.into(),
        port,
        credential: credential.digest,
        trust_generation: trust.generation,
        addresses: Arc::clone(addresses),
    };
    let entry = POOL.get_with(pool_key, PoolEntry::default);
    connect_single_until(
        &entry,
        host,
        port,
        addresses,
        &trust.config,
        &credential,
        deadline,
    )
    .await
}

#[cfg(test)]
async fn connect_pooled(
    entry: &PoolEntry,
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
    config: &quinn::ClientConfig,
    credential: &Credential,
) -> io::Result<QuicStream> {
    connect_single_until(
        entry,
        host,
        port,
        addresses,
        config,
        credential,
        Instant::now() + CONNECT_TIMEOUT,
    )
    .await
}

async fn connect_single_until(
    entry: &PoolEntry,
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
    config: &quinn::ClientConfig,
    credential: &Credential,
    deadline: Instant,
) -> io::Result<QuicStream> {
    let mut replaced = false;
    loop {
        if Instant::now() >= deadline {
            return Err(SharedDialError::timeout().into_io_error());
        }
        let shared = match checkout_or_dial(
            Ingress::Primary,
            entry,
            host,
            port,
            addresses,
            config,
            credential,
        ) {
            Checkout::Pooled(shared) => shared,
            Checkout::Dialing(mut waiter) => {
                match tokio::time::timeout_at(deadline, waiter.wait()).await {
                    Ok(Ok(shared)) => shared,
                    Ok(Err(error)) => return Err(error.into_io_error()),
                    Err(_) => return Err(SharedDialError::timeout().into_io_error()),
                }
            }
        };
        match open_stream_on(entry, shared, deadline).await {
            Ok(stream) => {
                selector::record_success();
                return Ok(stream);
            }
            Err(StreamAcquireFailure::DeadlineExceeded) => {
                return Err(SharedDialError::timeout().into_io_error());
            }
            Err(StreamAcquireFailure::Stale { error, .. }) => {
                // No application bytes have reached the caller. Retry admission
                // once, regardless of whether closure or the monitor woke us.
                // A peer that immediately closes replacements cannot cause a
                // handshake loop or restart the original acquisition deadline.
                if !replaced && error.kind.is_retryable() {
                    replaced = true;
                    continue;
                }
                return Err(error.into_io_error());
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "immutable identity snapshots passed down explicitly"
)]
async fn connect_dual_until(
    runtime: tokio::runtime::Id,
    host: &str,
    normalized_host: Box<str>,
    primary_port: u16,
    standby_port: u16,
    addresses: &Arc<[IpAddr]>,
    trust: &Trust,
    credential: &Credential,
    standby_generation: u64,
    deadline: Instant,
) -> io::Result<QuicStream> {
    if Instant::now() >= deadline {
        return Err(SharedDialError::timeout().into_io_error());
    }
    let primary_entry = POOL.get_with(
        PoolKey {
            runtime,
            host: host.into(),
            port: primary_port,
            credential: credential.digest,
            trust_generation: trust.generation,
            addresses: Arc::clone(addresses),
        },
        PoolEntry::default,
    );
    let standby_entry = POOL.get_with(
        PoolKey {
            runtime,
            host: host.into(),
            port: standby_port,
            credential: credential.digest,
            trust_generation: trust.generation,
            addresses: Arc::clone(addresses),
        },
        PoolEntry::default,
    );
    let selector = selector::selector(SelectorKey {
        runtime,
        host: normalized_host,
        primary_port,
        standby_port,
        standby_generation,
        credential: credential.digest,
        trust_generation: trust.generation,
    });

    let entry_for = |ingress: Ingress| -> &PoolEntry {
        match ingress {
            Ingress::Primary => &primary_entry,
            Ingress::Standby => &standby_entry,
        }
    };
    let port_for = |ingress: Ingress| -> u16 {
        match ingress {
            Ingress::Primary => primary_port,
            Ingress::Standby => standby_port,
        }
    };

    let plan_now = || {
        let (order, retire) = selector.plan(
            Instant::now(),
            pool_status(&primary_entry),
            pool_status(&standby_entry),
        );
        if let Some((ingress, id)) = retire {
            retire_connection(entry_for(ingress), id);
        }
        order
    };

    let mut candidates = plan_now();
    if !has_healthy_or_inflight(entry_for(candidates[0]))
        && let Some(wait_until) = selector.backoff_until(Instant::now())
    {
        if wait_until >= deadline {
            tokio::time::sleep_until(deadline).await;
            return Err(SharedDialError::timeout().into_io_error());
        }
        tokio::time::sleep_until(wait_until).await;
        candidates = plan_now();
    }

    let first = candidates[0];
    let dial_order = if let Some(shared) = try_checkout_pooled(entry_for(first)) {
        match open_stream_on(entry_for(first), shared, deadline).await {
            Ok(stream) => {
                selector.note_success(
                    first,
                    port_for(first),
                    stream.connection_id(),
                    false,
                    Instant::now(),
                );
                selector::record_success();
                return Ok(stream);
            }
            Err(StreamAcquireFailure::DeadlineExceeded) => {
                return Err(SharedDialError::timeout().into_io_error());
            }
            Err(StreamAcquireFailure::Stale { id, faulted, .. }) => {
                if faulted {
                    selector.note_mid_admission_fault(first, id);
                    [first.alternate(), first]
                } else {
                    [first, first.alternate()]
                }
            }
        }
    } else {
        candidates
    };

    let [cand0, cand1] = dial_order;
    let cand0_deadline = deadline.min(Instant::now() + selector::FIRST_CANDIDATE_BUDGET);
    let cand0_started = Instant::now();
    let err0 = match dial_or_checkout_until(
        cand0,
        entry_for(cand0),
        host,
        port_for(cand0),
        addresses,
        &trust.config,
        credential,
        cand0_deadline,
        deadline,
    )
    .await
    {
        Ok((stream, fresh_dial)) => {
            selector.note_success(
                cand0,
                port_for(cand0),
                stream.connection_id(),
                fresh_dial,
                Instant::now(),
            );
            selector::record_success();
            return Ok(stream);
        }
        Err(error) => error,
    };

    if !err0.kind.is_retryable() || Instant::now() >= deadline {
        return Err(err0.into_io_error());
    }

    tracing::warn!(
        carrier = "quic",
        from_ingress = cand0.as_str(),
        from_port = port_for(cand0),
        to_ingress = cand1.as_str(),
        to_port = port_for(cand1),
        failure_kind = err0.kind.as_str(),
        elapsed_ms = cand0_started.elapsed().as_millis() as u64,
        remaining_budget_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64,
        "QUIC ingress attempt failed; trying alternate ingress"
    );

    let err1 = match dial_or_checkout_until(
        cand1,
        entry_for(cand1),
        host,
        port_for(cand1),
        addresses,
        &trust.config,
        credential,
        deadline,
        deadline,
    )
    .await
    {
        Ok((stream, fresh_dial)) => {
            selector.note_success(
                cand1,
                port_for(cand1),
                stream.connection_id(),
                fresh_dial,
                Instant::now(),
            );
            selector::record_success();
            return Ok(stream);
        }
        Err(error) => error,
    };

    if !err1.kind.is_retryable() {
        return Err(err1.into_io_error());
    }

    selector.note_all_failed(Instant::now());
    let (primary_err, standby_err, final_is_standby) = match cand0 {
        Ingress::Primary => (err0, err1, true),
        Ingress::Standby => (err1, err0, false),
    };
    Err(selector::dual_failure_error(
        primary_err,
        standby_err,
        final_is_standby,
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit candidate slice and overall deadline"
)]
async fn dial_or_checkout_until(
    ingress: Ingress,
    entry: &PoolEntry,
    host: &str,
    port: u16,
    addresses: &Arc<[IpAddr]>,
    config: &quinn::ClientConfig,
    credential: &Credential,
    dial_deadline: Instant,
    overall_deadline: Instant,
) -> Result<(QuicStream, bool), SharedDialError> {
    let mut retried_stale = false;
    loop {
        if Instant::now() >= dial_deadline {
            return Err(SharedDialError::timeout());
        }
        match checkout_or_dial(ingress, entry, host, port, addresses, config, credential) {
            Checkout::Pooled(shared) => match open_stream_on(entry, shared, overall_deadline).await
            {
                Ok(stream) => return Ok((stream, false)),
                Err(StreamAcquireFailure::DeadlineExceeded) => {
                    return Err(SharedDialError::timeout());
                }
                Err(StreamAcquireFailure::Stale { error, .. }) => {
                    if !retried_stale && error.kind.is_retryable() && Instant::now() < dial_deadline
                    {
                        retried_stale = true;
                        continue;
                    }
                    return Err(error);
                }
            },
            Checkout::Dialing(mut waiter) => {
                let shared = match tokio::time::timeout_at(dial_deadline, waiter.wait()).await {
                    Ok(Ok(shared)) => shared,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(SharedDialError::timeout()),
                };
                return match open_stream_on(entry, shared, overall_deadline).await {
                    Ok(stream) => Ok((stream, true)),
                    Err(StreamAcquireFailure::DeadlineExceeded) => Err(SharedDialError::timeout()),
                    Err(StreamAcquireFailure::Stale { error, .. }) => Err(error),
                };
            }
        }
    }
}

/// Confirm that an authenticated peer answers, without opening a session.
/// A pooled connection cannot prove this: opening a stream on it is local.
pub async fn probe(host: &str, port: u16) -> io::Result<()> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let addresses =
        tokio::time::timeout_at(deadline, crate::transport::resolve_host_addresses(host))
            .await
            .map_err(|_| SharedDialError::timeout().into_io_error())??;
    let trust = trust()?;
    let standby_table = selector::standby()?;
    let credential = Credential::snapshot();
    if let Ok(normalized_host) = selector::normalize_node_host(host)
        && let Some(standby_port) = standby_table.lookup(&normalized_host, port)
    {
        let runtime = tokio::runtime::Handle::current().id();
        let selector = selector::selector(SelectorKey {
            runtime,
            host: normalized_host,
            primary_port: port,
            standby_port: standby_port.get(),
            standby_generation: standby_table.generation,
            credential: credential.digest,
            trust_generation: trust.generation,
        });
        let (order, _) = selector.plan(Instant::now(), PoolStatus::Empty, PoolStatus::Empty);
        let port_for = |ingress: Ingress| match ingress {
            Ingress::Primary => port,
            Ingress::Standby => standby_port.get(),
        };
        let [cand0, cand1] = order;
        let cand0_deadline = deadline.min(Instant::now() + selector::FIRST_CANDIDATE_BUDGET);
        let err0 = match tokio::time::timeout_at(
            cand0_deadline,
            dial_shared(
                cand0,
                host,
                port_for(cand0),
                &addresses,
                &trust.config,
                &credential,
            ),
        )
        .await
        {
            Ok(Ok(shared)) => {
                shared.connection.close(0u32.into(), b"probe");
                return Ok(());
            }
            Ok(Err(error)) => error,
            Err(_) => SharedDialError::timeout(),
        };
        if !err0.kind.is_retryable() || Instant::now() >= deadline {
            return Err(err0.into_io_error());
        }
        return match tokio::time::timeout_at(
            deadline,
            dial_shared(
                cand1,
                host,
                port_for(cand1),
                &addresses,
                &trust.config,
                &credential,
            ),
        )
        .await
        {
            Ok(Ok(shared)) => {
                shared.connection.close(0u32.into(), b"probe");
                Ok(())
            }
            Ok(Err(err1)) if !err1.kind.is_retryable() => Err(err1.into_io_error()),
            Ok(Err(err1)) => {
                let (p_err, s_err, final_is_standby) = match cand0 {
                    Ingress::Primary => (err0, err1, true),
                    Ingress::Standby => (err1, err0, false),
                };
                Err(selector::dual_failure_error(p_err, s_err, final_is_standby))
            }
            Err(_) => {
                let timeout = SharedDialError::timeout();
                let (p_err, s_err, final_is_standby) = match cand0 {
                    Ingress::Primary => (err0, timeout, true),
                    Ingress::Standby => (timeout, err0, false),
                };
                Err(selector::dual_failure_error(p_err, s_err, final_is_standby))
            }
        };
    }

    let shared = tokio::time::timeout_at(
        deadline,
        dial_shared(
            Ingress::Primary,
            host,
            port,
            &addresses,
            &trust.config,
            &credential,
        ),
    )
    .await
    .map_err(|_| SharedDialError::timeout().into_io_error())?
    .map_err(SharedDialError::into_io_error)?;
    shared.connection.close(0u32.into(), b"probe");
    Ok(())
}

async fn dial_shared(
    ingress: Ingress,
    host: &str,
    port: u16,
    addresses: &[IpAddr],
    config: &quinn::ClientConfig,
    credential: &Credential,
) -> Result<Arc<SharedConnection>, SharedDialError> {
    let _permit = DIAL_SLOTS
        .acquire()
        .await
        .map_err(|err| SharedDialError::from_io(FailureKind::Unreachable, io::Error::other(err)))?;
    selector::record_dial(ingress);
    let started = Instant::now();
    // TCP's staggered, family-interleaved race; no application data is sent
    // until a handshake has won. A terminal TLS/config rejection aborts sibling
    // address attempts immediately so dual-stack stalls cannot mask TLS errors.
    let terminal_abort = CancellationToken::new();
    let terminal_error: std::sync::Mutex<Option<SharedDialError>> = std::sync::Mutex::new(None);
    let raced = tokio::select! {
        biased;
        _ = terminal_abort.cancelled() => Err(io::Error::other("terminal QUIC dial rejection")),
        result = crate::transport::race_addresses(addresses, port, false, |address| {
            let terminal_abort = terminal_abort.clone();
            let terminal_error = &terminal_error;
            async move {
                match handshake_classified(address, host, config).await {
                    Ok(pair) => Ok(pair),
                    Err(error) => {
                        if !error.kind.is_retryable() {
                            let mut slot = terminal_error.lock().unwrap_or_else(|p| p.into_inner());
                            if slot.is_none() {
                                *slot = Some(error.clone());
                            }
                            terminal_abort.cancel();
                        }
                        Err(error.into_carrier_io_error())
                    }
                }
            }
        }) => result,
    };
    let (connection, owner) = match raced {
        Ok(pair) => pair,
        Err(last_io) => {
            if let Some(terminal) = terminal_error
                .into_inner()
                .unwrap_or_else(|p| p.into_inner())
            {
                return Err(terminal);
            }
            return Err(SharedDialError::from_io(classify_error(&last_io), last_io));
        }
    };
    if let Err(error) = authenticate_classified(&connection, &credential.key, false).await {
        connection.close(AUTH_FAILED, b"authentication failed");
        return Err(error);
    }
    let shared = SharedConnection::new(connection, owner, quinn::Side::Client);
    tracing::info!(
        carrier = "quic",
        ingress = ingress.as_str(),
        connection_id = shared.health.id,
        local_addr = ?shared.owner.0.local_addr().ok(),
        peer = %shared.connection.remote_address(),
        handshake_us = started.elapsed().as_micros() as u64,
        "opened authenticated QUIC connection"
    );
    Ok(shared)
}

async fn handshake_classified(
    address: SocketAddr,
    host: &str,
    config: &quinn::ClientConfig,
) -> Result<(Connection, Arc<EndpointOwner>), SharedDialError> {
    let bind = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let endpoint = Endpoint::client(bind)
        .map_err(|err| SharedDialError::from_io(FailureKind::Unreachable, err))?;
    let owner = Arc::new(EndpointOwner(endpoint));
    let connecting = owner
        .0
        .connect_with(config.clone(), address, host)
        .map_err(selector::classify_connect_error)?;
    let connection = tokio::time::timeout(ATTEMPT_TIMEOUT, connecting)
        .await
        .map_err(|_| SharedDialError::timeout())?
        .map_err(|err| selector::classify_connection_error(err, false))?;
    Ok((connection, owner))
}

#[cfg(test)]
async fn handshake(
    address: SocketAddr,
    host: &str,
    config: &quinn::ClientConfig,
) -> io::Result<(Connection, Arc<EndpointOwner>)> {
    handshake_classified(address, host, config)
        .await
        .map_err(SharedDialError::into_carrier_io_error)
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
        let evicted = {
            let mut state = entry.lock();
            // Sessions clone the slot under this lock, so no stream can be added
            // between this check and the eviction.
            let idle = match state.connection.as_ref() {
                Some(shared) if shared.connection.stable_id() == connection.stable_id() => {
                    let opened = shared.opened.load(Ordering::Relaxed);
                    let idle = Arc::strong_count(shared) == 1 && last_opened == Some(opened);
                    last_opened = Some(opened);
                    idle
                }
                _ => return,
            };
            if idle { state.connection.take() } else { None }
        };
        if let Some(evicted) = evicted {
            drop(evicted);
            return;
        }
    }
}

/// Close this runtime's pooled connections and retain UDP drivers until drained.
pub async fn shutdown_clients() {
    let runtime = tokio::runtime::Handle::current().id();
    selector::invalidate_runtime(runtime);
    let mut endpoints = Vec::new();
    for (key, entry) in POOL.iter() {
        if key.runtime == runtime {
            let (shared, inflight) = {
                let mut state = entry.lock();
                (state.connection.take(), state.inflight.take())
            };
            if let Some(slot) = inflight {
                slot.dial.cancel.cancel();
            }
            if let Some(shared) = shared {
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
                    let connection =
                        client.0.connect(addr, name).unwrap().await.map_err(|err| {
                            selector::classify_connection_error(err, false).into_carrier_io_error()
                        })?;
                    authenticate(
                        &connection,
                        &hmac::Key::new(hmac::HMAC_SHA256, b"wrong-credential"),
                        false,
                    )
                    .await
                }
                .await;
                let error = result.expect_err("rejection must fail before an application stream");
                let expected = if rejection == "credential" {
                    FailureKind::Authentication
                } else {
                    FailureKind::Tls
                };
                assert_eq!(
                    classify_error(&error),
                    expected,
                    "{rejection} must preserve its non-retryable classification"
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
            authenticate(
                &connection,
                &hmac::Key::new(hmac::HMAC_SHA256, SECRET),
                false,
            )
            .await
            .unwrap();
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
    async fn waiting_stream_reconnects_when_the_pooled_connection_closes_before_monitor_runs() {
        let (endpoint, server, client) = authenticated_pair().await;
        client.health.released.cancel();
        tokio::task::yield_now().await;
        let mut held = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(20), client.connection.open_bi()).await
            {
                Ok(pair) => held.push(pair.unwrap()),
                Err(_) => break,
            }
            assert!(held.len() <= MAX_STREAMS as usize);
        }
        let entry: PoolEntry = Arc::new(Mutex::new(PoolState::with_connection(client.clone())));
        let address = endpoint.0.local_addr().unwrap();
        let addresses: Arc<[IpAddr]> = Arc::from([address.ip()]);
        let config = client_config(Some(CERT)).unwrap();
        let credential = Credential::new(SECRET);
        let pending = connect_pooled(
            &entry,
            "localhost",
            address.port(),
            &addresses,
            &config,
            &credential,
        );
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
        client.connection.close(0u32.into(), b"path closed");
        let accept = async {
            AuthenticatedConnection::accept(
                endpoint.0.accept().await.unwrap(),
                endpoint.clone(),
                SECRET,
            )
            .await
            .unwrap()
        };
        let (replacement, peer) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(pending, accept)
        })
        .await
        .unwrap();
        assert_ne!(replacement.unwrap().connection_id(), client.health.id);
        peer.close();
        server.close();
        drop(held);
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
        let entry: PoolEntry = Arc::new(Mutex::new(PoolState::with_connection(client)));
        let linger = Duration::from_millis(50);
        let reaper = tokio::spawn(close_when_idle(
            connection.clone(),
            Arc::downgrade(&entry),
            linger,
        ));
        tokio::time::sleep(linger * 4).await;
        assert!(
            entry.lock().connection.is_some(),
            "an open stream keeps its connection pooled"
        );
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .unwrap()
            .unwrap();
        assert!(entry.lock().connection.is_none());
        // Evicting the last reference closes the client endpoint and its connection.
        tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .unwrap();
        server.close();
        endpoint.0.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn cancelling_one_coalesced_waiter_keeps_inflight_dial_alive_for_remaining_waiters() {
        let endpoint = server_endpoint();
        let address = endpoint.0.local_addr().unwrap();
        let addresses: Arc<[IpAddr]> = Arc::from([address.ip()]);
        let config = client_config(Some(CERT)).unwrap();
        let credential = Credential::new(SECRET);
        let entry = PoolEntry::default();

        // Hold server acceptance briefly so two callers coalesce onto one dial,
        // then cancel the impatient caller before TLS completes.
        let server_owner = endpoint.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server_owner.0.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(120)).await;
            let accepted = AuthenticatedConnection::accept(incoming, server_owner.clone(), SECRET)
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(80), server_owner.0.accept())
                    .await
                    .is_err(),
                "coalesced callers must not trigger a second handshake"
            );
            accepted
        });

        let impatient = connect_single_until(
            &entry,
            "localhost",
            address.port(),
            &addresses,
            &config,
            &credential,
            Instant::now() + Duration::from_millis(30),
        );
        let patient = connect_single_until(
            &entry,
            "localhost",
            address.port(),
            &addresses,
            &config,
            &credential,
            Instant::now() + Duration::from_secs(3),
        );
        let (impatient_res, patient_res) = tokio::join!(impatient, patient);
        assert_eq!(impatient_res.err().unwrap().kind(), io::ErrorKind::TimedOut);
        let stream = patient_res.unwrap();
        let server_conn = server_task.await.unwrap();
        drop(stream);
        server_conn.close();
        endpoint.0.close(0u32.into(), b"done");
    }
}
