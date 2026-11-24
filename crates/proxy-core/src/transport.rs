//! Transport utilities for establishing proxy connections.
//!
//! This module provides low-level TCP connection utilities that are shared
//! between the client and control modules, avoiding circular dependencies.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use base64::Engine;
use futures::future::BoxFuture;
use moka::sync::Cache;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;
use tokio_socks::tcp::Socks5Stream;

const DNS_CACHE_CAPACITY: u64 = 4096;
const DNS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// Budget for an endpoint policy's network resolvers. A listed policy's
/// system fallback gets [`DNS_TIMEOUT`] on top; `auto` runs the system
/// resolver alongside them, inside this budget.
const ENDPOINT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of its budget an `auto` lookup leaves unused, so that it reports
/// why it failed before the budget's own timer cuts it off.
const AUTO_DNS_MARGIN: Duration = Duration::from_millis(250);
/// Lower bound on reusing a network resolver's endpoint answer, so a zero TTL
/// does not cost a lookup per connection. [`DNS_CACHE_TTL`] is the upper one.
const ENDPOINT_TTL_FLOOR: Duration = Duration::from_secs(30);
const NEGATIVE_TTL_FLOOR: Duration = Duration::from_secs(5);
const NEGATIVE_TTL_CEILING: Duration = Duration::from_secs(60);
const DNS_REFRESH_FLOOR: Duration = Duration::from_secs(2);
const EXTERNAL_PROXY_TIMEOUT: Duration = Duration::from_secs(15);
const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
static DNS_SLOTS: Semaphore = Semaphore::const_new(8);
/// Endpoint lookups through network resolvers, separate from [`DNS_SLOTS`]
/// so stalled OS lookups cannot hold them.
static ENDPOINT_DNS_SLOTS: Semaphore = Semaphore::const_new(8);

/// Which resolver policy a lookup follows. The two never share cache
/// entries: a system answer for a destination must not satisfy an endpoint
/// lookup whose policy demands an encrypted one.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Purpose {
    /// A host the client connects to itself, such as a direct-route site.
    Destination,
    /// A proxy node, relay target or external proxy; see [`crate::dns`].
    Endpoint,
}

type DnsKey = (Purpose, String);

struct DnsEntry {
    /// Empty for a negative answer.
    addresses: Arc<[IpAddr]>,
    refreshed: Instant,
    expires: Instant,
    /// Generation of the endpoint policy that produced the entry; zero for
    /// destinations.
    generation: u64,
}

impl DnsEntry {
    fn new(addresses: Vec<IpAddr>, ttl: Duration, generation: u64) -> Self {
        let refreshed = Instant::now();
        Self {
            addresses: addresses.into(),
            refreshed,
            expires: refreshed + ttl,
            generation,
        }
    }

    fn serves(&self, generation: u64, refresh: bool) -> bool {
        self.generation == generation
            && Instant::now() < self.expires
            && (!refresh || self.refreshed.elapsed() < DNS_REFRESH_FLOOR)
    }

    fn addresses(&self) -> std::io::Result<Arc<[IpAddr]>> {
        if self.addresses.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no A or AAAA record",
            ))
        } else {
            Ok(Arc::clone(&self.addresses))
        }
    }
}

static DNS_LOOKUPS: LazyLock<Cache<DnsKey, Arc<Mutex<()>>>> =
    LazyLock::new(|| Cache::builder().max_capacity(DNS_CACHE_CAPACITY).build());

/// Bounded, expiring cache for DNS results.
///
/// Proxy endpoints can move during failover and users can change networks while
/// the process remains alive. A permanent single-address cache made both cases
/// fail until restart and allowed arbitrary destination names to grow memory
/// without a limit. Entries also expire individually, by record TTL for
/// endpoint answers from network resolvers.
static DNS_CACHE: LazyLock<Cache<DnsKey, Arc<DnsEntry>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(DNS_CACHE_CAPACITY)
        .time_to_live(DNS_CACHE_TTL)
        .build()
});

/// The endpoint DNS policy in effect. The generation tells its cache entries
/// apart from those an earlier policy produced.
struct ActiveEndpointDns {
    generation: u64,
    policy: std::result::Result<EndpointDnsPolicy, ParsePolicyError>,
}

impl ActiveEndpointDns {
    fn new(policy: std::result::Result<EndpointDnsPolicy, ParsePolicyError>) -> Self {
        static GENERATION: AtomicU64 = AtomicU64::new(1);
        Self {
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
            policy,
        }
    }
}

/// The policy from [`set_endpoint_dns`]. Until one is set, lookups use the
/// `ENDPOINT_DNS` environment variable, read once on first use.
static ENDPOINT_DNS: ArcSwapOption<ActiveEndpointDns> = ArcSwapOption::const_empty();

fn active_endpoint_dns() -> Arc<ActiveEndpointDns> {
    static FROM_ENV: LazyLock<Arc<ActiveEndpointDns>> = LazyLock::new(|| {
        let policy = match endpoint_dns_from_env() {
            Ok(Some(policy)) => {
                announce_endpoint_dns(&policy, "ENDPOINT_DNS");
                Ok(policy)
            }
            Ok(None) => {
                let policy = EndpointDnsPolicy::default();
                announce_endpoint_dns(&policy, "default");
                Ok(policy)
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "ENDPOINT_DNS is invalid; endpoint lookups fail until a valid policy is set"
                );
                Err(error)
            }
        };
        Arc::new(ActiveEndpointDns::new(policy))
    });
    ENDPOINT_DNS
        .load_full()
        .unwrap_or_else(|| Arc::clone(&FROM_ENV))
}

/// The policy `ENDPOINT_DNS` names; `None` when it is unset or blank.
fn endpoint_dns_from_env() -> std::result::Result<Option<EndpointDnsPolicy>, ParsePolicyError> {
    match std::env::var("ENDPOINT_DNS") {
        Ok(spec) if !spec.trim().is_empty() => spec.parse().map(Some),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ParsePolicyError::UnknownEntry {
            entry: "<non-UTF-8 ENDPOINT_DNS>".to_owned(),
        }),
    }
}

/// What endpoint lookups consult besides the policy. Fixed for the life of
/// the process; tests substitute loopback resolvers and their own hosts file.
struct EndpointSources {
    automatic: dns::Automatic,
    hosts: std::path::PathBuf,
}

static ENDPOINT_SOURCES: LazyLock<EndpointSources> = LazyLock::new(|| EndpointSources {
    automatic: dns::Automatic::builtin(|host| Box::pin(async move { system_lookup(&host).await })),
    hosts: dns::hosts_path(),
});

fn announce_endpoint_dns(policy: &EndpointDnsPolicy, source: &'static str) {
    if policy.has_experimental_queries() {
        tracing::warn!(
            %policy,
            source,
            "endpoint DNS uses the experimental two-question query shape; it is non-standard, \
             easy to fingerprint and answered by few resolvers"
        );
    } else {
        tracing::info!(%policy, source, "endpoint DNS policy in effect");
    }
}

/// Sets how remote proxy endpoints are resolved from now on; see
/// [`crate::dns`]. Answers cached under a different policy are not reused.
pub fn set_endpoint_dns(policy: EndpointDnsPolicy) {
    // A caller that sets its policy on every start keeps the cache while the
    // policy stays the same.
    let unchanged = ENDPOINT_DNS
        .load()
        .as_ref()
        .is_some_and(|active| matches!(&active.policy, Ok(current) if *current == policy));
    if unchanged {
        return;
    }
    announce_endpoint_dns(&policy, "configuration");
    ENDPOINT_DNS.store(Some(Arc::new(ActiveEndpointDns::new(Ok(policy)))));
}

/// Applies the policy a configuration carries. Without one, lookups go back
/// to the `ENDPOINT_DNS` environment variable, else to
/// [`EndpointDnsPolicy::default`]. A spec that does not parse changes nothing.
pub fn apply_endpoint_dns(
    spec: Option<&EndpointDnsSpec>,
) -> std::result::Result<(), ParsePolicyError> {
    match spec {
        Some(spec) => set_endpoint_dns(spec.parse()?),
        None => ENDPOINT_DNS.store(None),
    }
    Ok(())
}

/// The endpoint DNS policy in effect: the last [`set_endpoint_dns`], else the
/// `ENDPOINT_DNS` environment variable, else [`EndpointDnsPolicy::default`].
/// An invalid `ENDPOINT_DNS` is returned as the error, and endpoint lookups
/// fail rather than fall back to another policy until a valid one is set.
pub fn endpoint_dns() -> std::result::Result<EndpointDnsPolicy, ParsePolicyError> {
    active_endpoint_dns().policy.clone()
}

use crate::config::runtime;
use crate::dns::{self, EndpointDnsPolicy, EndpointDnsSpec, ParsePolicyError};
use crate::relay::{ExternalProxyKind, ExternalProxyTarget};
use crate::secure_transport::{ProxyStream, WireProtocol, connect_v3};
use crate::{Aes256GcmCryption, ProxyHeader, ProxyTransport};

#[derive(Debug, Snafu)]
pub enum TransportError {
    #[snafu(display("URI(`{uri:?}`), IO error: {detail}"))]
    Io {
        uri: Option<String>,
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("URI(`{uri}`) Encryption error: {detail}"))]
    Encryption { uri: String, detail: String },
    #[snafu(display("URI(`{uri}`) Send header error"))]
    SendHeader {
        uri: String,
        source: crate::ProxyError,
    },
    #[snafu(display("URI(`{uri}`) Serde json failed"))]
    SerdeJson {
        uri: String,
        source: serde_json::Error,
    },
    #[snafu(display("Empty DNS record"))]
    EmptyDNSRecord,
    #[snafu(display("External proxy `{proxy}` error: {detail}"))]
    ExternalProxy { proxy: String, detail: String },
    #[snafu(display("SOCKS5 upstream `{proxy}` handshake failed"))]
    SocksProxy {
        proxy: String,
        source: tokio_socks::Error,
    },
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[inline]
fn get_uri(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

fn dns_cache_key(host: &str) -> String {
    let host = host.trim_end_matches('.');
    // Most hosts arrive already lowercase and without a trailing root.
    if !host.is_empty() && host.bytes().all(|byte| !byte.is_ascii_uppercase()) {
        host.to_owned()
    } else {
        host.to_ascii_lowercase()
    }
}

/// Resolve all addresses for a host through the bounded process cache.
pub async fn resolve_host_addresses(host: &str) -> std::io::Result<Arc<[IpAddr]>> {
    resolve_addresses(host, false, Purpose::Destination).await
}

/// Resolve a remote proxy endpoint, such as a node, relay target or external
/// proxy, under the endpoint DNS policy and through the same bounded cache.
pub async fn resolve_endpoint_addresses(host: &str) -> std::io::Result<Arc<[IpAddr]>> {
    resolve_addresses(host, false, Purpose::Endpoint).await
}

/// Re-resolve an endpoint after every cached address failed, bypassing the
/// cache unless it was refreshed moments ago.
pub(crate) async fn refresh_endpoint_addresses(host: &str) -> std::io::Result<Arc<[IpAddr]>> {
    resolve_addresses(host, true, Purpose::Endpoint).await
}

async fn resolve_addresses(
    host: &str,
    refresh: bool,
    purpose: Purpose,
) -> std::io::Result<Arc<[IpAddr]>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Arc::from([ip]));
    }

    let cache_key = dns_cache_key(host);
    if cache_key.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS host is empty",
        ));
    }
    match purpose {
        Purpose::Destination => {
            let key = (purpose, cache_key);
            cached_lookup(key, 0, refresh, DNS_TIMEOUT, host, |_| {
                Box::pin(async { Ok(DnsEntry::new(system_lookup(host).await?, DNS_CACHE_TTL, 0)) })
            })
            .await
        }
        Purpose::Endpoint => {
            let active = active_endpoint_dns();
            resolve_endpoint(&active, &ENDPOINT_SOURCES, host, cache_key, refresh).await
        }
    }
}

async fn resolve_endpoint(
    active: &ActiveEndpointDns,
    sources: &EndpointSources,
    host: &str,
    cache_key: String,
    refresh: bool,
) -> std::io::Result<Arc<[IpAddr]>> {
    let policy = active.policy.as_ref().map_err(|error| {
        error
            .clone()
            .into_io(std::io::ErrorKind::InvalidInput, "invalid ENDPOINT_DNS")
    })?;
    let budget = if policy.is_system_only() {
        DNS_TIMEOUT
    } else if policy.has_system_fallback() && !policy.is_automatic() {
        ENDPOINT_DNS_TIMEOUT + DNS_TIMEOUT
    } else {
        ENDPOINT_DNS_TIMEOUT
    };
    let key = (Purpose::Endpoint, cache_key);
    let generation = active.generation;
    cached_lookup(key, generation, refresh, budget, host, |deadline| {
        Box::pin(endpoint_entry(
            policy, sources, generation, host, refresh, deadline,
        ))
    })
    .await
}

/// Serves `key` from the cache, or runs `lookup` once for every concurrent
/// caller and caches what it returns. The whole call is bounded by `budget`.
///
/// `lookup` is type-erased because connection futures embed this call:
/// proving them `Send` through the resolver stack beneath it would exceed the
/// compiler's auto-trait recursion limit.
async fn cached_lookup<'a>(
    key: DnsKey,
    generation: u64,
    refresh: bool,
    budget: Duration,
    host: &str,
    lookup: impl FnOnce(Instant) -> BoxFuture<'a, std::io::Result<DnsEntry>>,
) -> std::io::Result<Arc<[IpAddr]>> {
    let deadline = Instant::now() + budget;
    let work = async {
        let gate = DNS_LOOKUPS.get_with(key.clone(), || Arc::new(Mutex::new(())));
        let _guard = gate.lock().await;
        if let Some(cached) = DNS_CACHE.get(&key)
            && cached.serves(generation, refresh)
        {
            return cached.addresses();
        }
        let entry = Arc::new(lookup(deadline).await?);
        tracing::debug!(host, purpose = ?key.0, addresses = ?entry.addresses, "DNS resolved and cached");
        DNS_CACHE.insert(key, Arc::clone(&entry));
        entry.addresses()
    };
    tokio::time::timeout_at(deadline, work).await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup budget exhausted")
    })?
}

/// Resolves an endpoint under `policy`. Listed network resolvers fail closed
/// unless the policy ends in `system`; `auto` decides for itself when the
/// system resolver's answer can be used. Every answer drops addresses no
/// remote host can have, which sinkholes and some injectors use.
async fn endpoint_entry(
    policy: &EndpointDnsPolicy,
    sources: &EndpointSources,
    generation: u64,
    host: &str,
    refresh: bool,
    deadline: Instant,
) -> std::io::Result<DnsEntry> {
    if policy.is_system_only() {
        return system_entry(host, generation).await;
    }
    // A hosts entry is the user's own answer. It outranks the policy's
    // resolvers as it outranks the platform's, and no network can forge it.
    if let Some(addresses) = dns::hosts_addresses(&sources.hosts, &dns_cache_key(host)).await {
        tracing::debug!(host, ?addresses, "endpoint pinned by the hosts file");
        return Ok(DnsEntry::new(addresses, ENDPOINT_TTL_FLOOR, generation));
    }
    if policy.is_automatic() {
        let _permit = ENDPOINT_DNS_SLOTS
            .acquire()
            .await
            .map_err(std::io::Error::other)?;
        let deadline = deadline.checked_sub(AUTO_DNS_MARGIN).unwrap_or(deadline);
        return match sources.automatic.resolve(host, refresh, deadline).await {
            Ok((addresses, ttl)) => {
                let ttl = ttl.map_or(DNS_CACHE_TTL, |ttl| {
                    ttl.clamp(ENDPOINT_TTL_FLOOR, DNS_CACHE_TTL)
                });
                Ok(DnsEntry::new(addresses, ttl, generation))
            }
            // Every caller that queued behind this lookup would only repeat
            // it, against resolvers that are not this project's to load.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DnsEntry::new(Vec::new(), NEGATIVE_TTL_FLOOR, generation))
            }
            Err(error) => Err(error),
        };
    }
    let network_deadline = if policy.has_system_fallback() {
        deadline.checked_sub(DNS_TIMEOUT).unwrap_or(deadline)
    } else {
        deadline
    };
    let resolved = {
        let _permit = ENDPOINT_DNS_SLOTS
            .acquire()
            .await
            .map_err(std::io::Error::other)?;
        dns::resolve(policy, host, network_deadline).await
    };
    let error = match resolved {
        Ok(dns::Resolution::Addresses { addresses, ttl }) => {
            let ttl = ttl.clamp(ENDPOINT_TTL_FLOOR, DNS_CACHE_TTL);
            return Ok(DnsEntry::new(addresses, ttl, generation));
        }
        Ok(dns::Resolution::Missing { ttl }) if !policy.has_system_fallback() => {
            let ttl = ttl
                .unwrap_or(NEGATIVE_TTL_CEILING)
                .clamp(NEGATIVE_TTL_FLOOR, NEGATIVE_TTL_CEILING);
            return Ok(DnsEntry::new(Vec::new(), ttl, generation));
        }
        Ok(dns::Resolution::Missing { .. }) => {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no A or AAAA record")
        }
        Err(error) => error.into(),
    };
    if !policy.has_system_fallback() {
        return Err(error);
    }
    tracing::warn!(
        host,
        %error,
        "endpoint DNS resolvers failed; using the system resolver as the policy allows"
    );
    system_entry(host, generation).await
}

async fn system_entry(host: &str, generation: u64) -> std::io::Result<DnsEntry> {
    let mut addresses = system_lookup(host).await?;
    addresses.retain(|address| dns::is_routable_endpoint(*address));
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "the system resolver returned only addresses no remote endpoint can have",
        ));
    }
    Ok(DnsEntry::new(addresses, DNS_CACHE_TTL, generation))
}

/// The platform resolver, then the secondary resolvers when it fails.
async fn system_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
    // The permit stays with the OS call even if the async waiter times out.
    // Cancelling lookup_host itself otherwise leaves an unbounded blocking job.
    let permit = DNS_SLOTS.acquire().await.map_err(std::io::Error::other)?;
    let owned_host = host.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        (owned_host.as_str(), 0)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(std::io::Error::other)?;
    let mut addresses = match result {
        Ok(addresses) => addresses.into_iter().map(|address| address.ip()).collect(),
        Err(error) => {
            tracing::warn!(host, %error, "system DNS failed, falling back to secondary resolvers");
            Vec::new()
        }
    };
    if addresses.is_empty() {
        addresses = uni_stream::addr::get_ip_addrs(host).await?;
    }
    let mut seen = HashSet::with_capacity(addresses.len());
    addresses.retain(|address| seen.insert(*address));
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Empty DNS record",
        ));
    }
    Ok(addresses)
}

/// Resolves a hostname to the first currently preferred IP address.
#[inline]
pub async fn resolve_host(host: &str) -> std::io::Result<IpAddr> {
    resolve_host_addresses(host)
        .await?
        .first()
        .copied()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Empty DNS record"))
}

/// Connect using the OS TCP retry policy, refreshing DNS once if all addresses
/// fail. Dropping this future cancels all outstanding sockets. A caller's
/// protocol handshake deadline must not truncate TCP's SYN retransmissions.
pub async fn connect_tcp_host(host: &str, port: u16) -> std::io::Result<TcpStream> {
    connect_tcp_resolved(host, port, Purpose::Destination).await
}

/// [`connect_tcp_host`] for a remote proxy endpoint, whose name is resolved
/// under the endpoint DNS policy.
pub async fn connect_tcp_endpoint(host: &str, port: u16) -> std::io::Result<TcpStream> {
    connect_tcp_resolved(host, port, Purpose::Endpoint).await
}

async fn connect_tcp_resolved(
    host: &str,
    port: u16,
    purpose: Purpose,
) -> std::io::Result<TcpStream> {
    crate::diagnostics::phase("resolve");
    let addresses = resolve_addresses(host, false, purpose).await?;
    crate::diagnostics::phase("tcp_connect");
    match connect_tcp_addresses(&addresses, port).await {
        Ok(stream) => Ok(stream),
        Err(error) if host.parse::<IpAddr>().is_err() => {
            crate::diagnostics::phase("resolve_refresh");
            let refreshed = resolve_addresses(host, true, purpose).await?;
            if refreshed == addresses {
                return Err(error);
            }
            crate::diagnostics::phase("tcp_connect");
            connect_tcp_addresses(&refreshed, port).await
        }
        Err(error) => Err(error),
    }
}

/// Connect only to addresses whose route policy the caller has already prepared.
/// Uses the normal family staggering and TCP diagnostics without resolving a
/// different address behind the caller's installed bypass routes.
pub async fn connect_tcp_addresses(addresses: &[IpAddr], port: u16) -> std::io::Result<TcpStream> {
    race_addresses(addresses, port, cfg!(target_os = "ios"), connect_socket).await
}

async fn connect_socket(address: SocketAddr) -> std::io::Result<TcpStream> {
    let started = Instant::now();
    let result = TcpStream::connect(address).await;
    crate::diagnostics::tcp_connect_finished(address, started.elapsed(), &result);
    let stream = result?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

// At most two sockets are in flight. A blackholed preferred address must not
// delay the other family until the operating system's SYN retries expire.
// QUIC handshakes race through the same policy.
pub(crate) async fn race_addresses<T, F, Fut>(
    addresses: &[IpAddr],
    port: u16,
    retry_stalled_single: bool,
    connect: F,
) -> std::io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;
    let mut ordered = addresses.to_vec();
    if let Some(first) = ordered.first()
        && let Some(other) = ordered
            .iter()
            .position(|ip| ip.is_ipv4() != first.is_ipv4())
    {
        let other = ordered.remove(other);
        ordered.insert(1, other);
    }
    // On iOS a lost initial SYN otherwise adds a full kernel retransmission
    // interval even when the next attempt would connect immediately. Give a
    // single-address endpoint the same bounded fallback as a dual-stack one.
    // Only a still-pending handshake gets one backup; immediate errors are
    // returned, and no protocol bytes are sent until the winning socket returns.
    let mut backup = if retry_stalled_single && ordered.len() == 1 {
        ordered.first().copied()
    } else {
        None
    };
    let mut remaining = ordered.into_iter();
    let mut pending = FuturesUnordered::new();
    let mut next_start = Instant::now();
    let mut last_error = std::io::Error::new(std::io::ErrorKind::NotFound, "Empty DNS record");
    loop {
        if pending.is_empty() || (pending.len() < 2 && Instant::now() >= next_start) {
            if let Some(ip) = remaining.next() {
                pending.push(connect(SocketAddr::new(ip, port)));
                next_start = Instant::now() + ADDRESS_STAGGER;
            } else if pending.is_empty() {
                return Err(last_error);
            } else if let Some(ip) = backup.take() {
                pending.push(connect(SocketAddr::new(ip, port)));
            }
        }
        tokio::select! {
            result = pending.next(), if !pending.is_empty() => {
                match result {
                    Some(Ok(stream)) => return Ok(stream),
                    Some(Err(error)) => last_error = error,
                    None => {}
                }
                next_start = Instant::now();
            }
            _ = tokio::time::sleep_until(next_start), if pending.len() < 2 && (remaining.len() > 0 || backup.is_some()) => {}
        }
    }
}

/// Establishes a TCP connection to the given host and port.
///
/// If the host is an IP address, connects directly.
/// If the host is a domain name, performs DNS resolution first.
#[inline]
pub async fn get_tcp_stream(host: &str, port: u16, detail: &'static str) -> Result<TcpStream> {
    connect_tcp_host(host, port)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(format!("TcpStream({}:{})", host, port)),
            detail,
        })
}

/// [`get_tcp_stream`] for a remote proxy endpoint, such as an external
/// upstream proxy, whose name is resolved under the endpoint DNS policy.
pub async fn get_tcp_endpoint_stream(
    host: &str,
    port: u16,
    detail: &'static str,
) -> Result<TcpStream> {
    connect_tcp_endpoint(host, port)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(format!("TcpStream({}:{})", host, port)),
            detail,
        })
}

/// Establishes a TCP connection through the proxy server.
///
/// This function:
/// 1. Connects to the proxy server
/// 2. Sends an encrypted ProxyHeader with the target host/port
/// 3. Returns the connected stream ready for bidirectional forwarding
pub async fn get_tcp_proxy_stream(
    host: &str,
    port: u16,
    proxy_server: &str,
    proxy_server_port: u16,
    msg_key: Option<Cow<'static, str>>,
    detail: &'static str,
) -> Result<ProxyStream> {
    let protocol = WireProtocol::configured().context(IoSnafu {
        uri: None,
        detail: "select wire protocol",
    })?;
    get_tcp_proxy_stream_with_protocol(
        host,
        port,
        proxy_server,
        proxy_server_port,
        msg_key,
        detail,
        protocol,
    )
    .await
}

/// Connect with explicit protocol selection without changing process configuration.
pub async fn get_tcp_proxy_stream_with_protocol(
    host: &str,
    port: u16,
    proxy_server: &str,
    proxy_server_port: u16,
    msg_key: Option<Cow<'static, str>>,
    detail: &'static str,
    protocol: WireProtocol,
) -> Result<ProxyStream> {
    let proxy_header = ProxyHeader {
        host: host.into(),
        port,
        key: msg_key,
        transport: ProxyTransport::Tcp,
    };
    get_proxy_stream(
        &proxy_header,
        proxy_server,
        proxy_server_port,
        detail,
        &get_uri(host, port),
        protocol,
    )
    .await
}

pub(crate) async fn get_proxy_stream(
    proxy_header: &ProxyHeader,
    proxy_server: &str,
    proxy_server_port: u16,
    detail: &'static str,
    uri: &str,
    protocol: WireProtocol,
) -> Result<ProxyStream> {
    let stream = get_upstream_stream(proxy_server, proxy_server_port, detail).await?;
    setup_proxy_stream(proxy_header, stream, uri, protocol).await
}

pub(crate) async fn setup_proxy_stream(
    proxy_header: &ProxyHeader,
    mut proxy_server_stream: crate::upstream::CarrierStream,
    uri: &str,
    protocol: WireProtocol,
) -> Result<ProxyStream> {
    // Do not log the session key or the encrypted header. The transport and
    // boolean encryption flag are enough to diagnose protocol negotiation
    // without leaking credentials into debug output.
    tracing::debug!(
        peer = ?proxy_server_stream.peer_addr().ok(),
        target = uri,
        transport = ?proxy_header.transport,
        wire_protocol = ?protocol,
        session_encrypted = protocol == WireProtocol::V3 || proxy_header.key.is_some(),
        "opening proxy transport connection"
    );
    crate::diagnostics::phase("proxy_header_prepare");
    // One snapshot binds header encryption and framing to the same credential.
    let (key, checksum_key) =
        runtime::with_secret_key(|key, hash| <[u8; 32]>::try_from(key).map(|key| (key, hash)))
            .map_err(|error| TransportError::Encryption {
                uri: uri.to_string(),
                detail: error.to_string(),
            })?;
    let mut header = vec![0; 8];
    serde_json::to_writer(&mut header, &proxy_header).with_context(|_| SerdeJsonSnafu {
        uri: uri.to_string(),
    })?;
    if protocol == WireProtocol::Legacy {
        let mut cryption =
            Aes256GcmCryption::try_new(&key).map_err(|e| TransportError::Encryption {
                uri: uri.to_string(),
                detail: e.to_string(),
            })?;
        let tag = cryption
            .encrypt(&mut header[8..])
            .map_err(|e| TransportError::Encryption {
                uri: uri.to_string(),
                detail: e.to_string(),
            })?;
        header.extend_from_slice(tag.as_ref());
    }
    let len = (header.len() - 8) as u32;
    header[..4].copy_from_slice(&(len ^ checksum_key).to_be_bytes());
    header[4..8].copy_from_slice(&len.to_be_bytes());
    if protocol == WireProtocol::V3 {
        let control = crate::control::is_control_target(&proxy_header.host, proxy_header.port);
        let setup = async {
            let mut stream = connect_v3(proxy_server_stream, &key, control)?;
            crate::diagnostics::phase("proxy_header_write");
            stream.write_all(&header).await?;
            stream.flush().await?;
            crate::diagnostics::phase("proxy_header_written");
            Ok::<_, std::io::Error>(ProxyStream::Secure(Box::new(stream)))
        };
        return tokio::time::timeout(Duration::from_secs(10), setup)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "v3 header write timed out")
            })
            .and_then(|result| result)
            .context(IoSnafu {
                uri: None,
                detail: "v3 setup",
            });
    }
    crate::diagnostics::phase("proxy_header_write");
    let written = tokio::time::timeout(
        Duration::from_secs(10),
        proxy_server_stream.write_all(&header),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "legacy header write timed out",
        )
    })
    .and_then(|result| result);
    if written.is_err() {
        proxy_server_stream.record_diagnostics("proxy_header_write_failed");
    }
    written.with_context(|_| IoSnafu {
        uri: Some(uri.to_string()),
        detail: "send proxy header",
    })?;
    crate::diagnostics::phase("proxy_header_written");
    tracing::debug!(
        peer = ?proxy_server_stream.peer_addr().ok(),
        target = uri,
        transport = ?proxy_header.transport,
        encrypted_header_bytes = len,
        "sent encrypted proxy connection header"
    );
    Ok(proxy_server_stream.into())
}

/// Establish a TCP tunnel to a destination through an external SOCKS5 or HTTP proxy.
pub async fn get_tcp_external_proxy_stream(
    proxy: &ExternalProxyTarget,
    host: &str,
    port: u16,
    detail: &'static str,
) -> Result<TcpStream> {
    let stream = get_tcp_endpoint_stream(proxy.host.as_str(), proxy.port, detail).await?;
    tokio::time::timeout(
        EXTERNAL_PROXY_TIMEOUT,
        negotiate_external_proxy(stream, proxy, host, port, detail),
    )
    .await
    .map_err(|_| TransportError::ExternalProxy {
        proxy: proxy.display_url(),
        detail: format!(
            "external proxy handshake exceeded {} seconds",
            EXTERNAL_PROXY_TIMEOUT.as_secs()
        ),
    })?
}

async fn negotiate_external_proxy(
    mut stream: TcpStream,
    proxy: &ExternalProxyTarget,
    host: &str,
    port: u16,
    detail: &'static str,
) -> Result<TcpStream> {
    match proxy.kind {
        ExternalProxyKind::Socks5 => {
            let target_host = if proxy.remote_dns {
                host.to_string()
            } else {
                resolve_host(host)
                    .await
                    .context(IoSnafu {
                        uri: Some(host.to_string()),
                        detail,
                    })?
                    .to_string()
            };
            let socks_stream = match (&proxy.username, &proxy.password) {
                (Some(username), Some(password)) => Socks5Stream::connect_with_password_and_socket(
                    stream,
                    (target_host.as_str(), port),
                    username,
                    password,
                )
                .await
                .map_err(|source| TransportError::SocksProxy {
                    proxy: proxy.display_url(),
                    source,
                })?,
                _ => Socks5Stream::connect_with_socket(stream, (target_host.as_str(), port))
                    .await
                    .map_err(|source| TransportError::SocksProxy {
                        proxy: proxy.display_url(),
                        source,
                    })?,
            };
            Ok(socks_stream.into_inner())
        }
        ExternalProxyKind::Http => {
            let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let mut request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: \
                 Keep-Alive\r\n"
            );
            if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
            }
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(proxy.display_url()),
                    detail: "write http proxy connect request",
                })?;

            let mut response = Vec::new();
            read_http_header(&mut stream, &mut response, 16 * 1024)
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(proxy.display_url()),
                    detail: "read http proxy connect response",
                })?;

            let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                return Err(TransportError::ExternalProxy {
                    proxy: proxy.display_url(),
                    detail: "Malformed HTTP proxy response".to_string(),
                });
            };
            let header_text = String::from_utf8_lossy(&response[..headers_end + 4]);
            let status_line = header_text.lines().next().unwrap_or_default();
            let status_ok = status_line
                .split_whitespace()
                .nth(1)
                .is_some_and(|code| code == "200");
            if !status_ok {
                return Err(TransportError::ExternalProxy {
                    proxy: proxy.display_url(),
                    detail: format!("HTTP CONNECT failed: {status_line}"),
                });
            }
            Ok(stream)
        }
    }
}

/// Append one HTTP header through its terminating CRLF pair, leaving payload
/// bytes on the socket. `header` may contain an already-read protocol prefix.
/// The caller owns the setup deadline and the maximum header size.
pub async fn read_http_header(
    stream: &mut TcpStream,
    header: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<()> {
    let mut chunk = [0; 4096];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy header exceeds its size limit",
            ));
        }
        let capacity = chunk.len().min(limit - header.len());
        let n = stream.peek(&mut chunk[..capacity]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP proxy header",
            ));
        }
        // A header can share a packet with a request body or a tunnel greeting.
        // Inspect the previous three bytes too, in case CRLF straddles reads.
        let prefix = header.len().min(3);
        let mut boundary = [0; 4099];
        boundary[..prefix].copy_from_slice(&header[header.len() - prefix..]);
        boundary[prefix..prefix + n].copy_from_slice(&chunk[..n]);
        let consume = boundary[..prefix + n]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map_or(n, |end| end + 4 - prefix);
        stream.read_exact(&mut chunk[..consume]).await?;
        header.extend_from_slice(&chunk[..consume]);
    }
    Ok(())
}

/// Open a native upstream using the carrier selected for this negotiation.
pub async fn get_upstream_stream(
    host: &str,
    port: u16,
    detail: &'static str,
) -> Result<crate::upstream::CarrierStream> {
    crate::upstream::connect_host(host, port)
        .await
        .context(IoSnafu { uri: None, detail })
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use hickory_proto::op::{Message, ResponseCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;
    use crate::dns::testing::{
        Scope, addresses_reply_to, fake_https_resolver, fake_udp_resolver, loopback_automatic,
        response_to_request,
    };
    use crate::relay::ExternalProxyTarget;

    #[test]
    fn dns_cache_keys_are_case_and_root_dot_insensitive() {
        assert_eq!(dns_cache_key("Example.COM."), "example.com");
    }

    fn ip(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    fn no_platform_answer(_host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async { Err(std::io::ErrorKind::NotFound.into()) })
    }

    /// A platform resolver that places every name inside the mainland.
    fn domestic_platform_answer(_host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async { Ok(vec![IpAddr::from([119, 29, 29, 29])]) })
    }

    /// A hosts file that is removed when the test ends, however it ends.
    struct HostsFile(std::path::PathBuf);

    impl HostsFile {
        fn with(test: &str, content: &str) -> Self {
            let name = format!("proxy-core-{}-{test}.hosts", std::process::id());
            let path = std::env::temp_dir().join(name);
            std::fs::write(&path, content).unwrap();
            Self(path)
        }

        fn missing() -> std::path::PathBuf {
            std::env::temp_dir().join("proxy-core-tests-have-no-such-hosts-file")
        }
    }

    impl Drop for HostsFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The `auto` policy over the given loopback resolvers and platform
    /// resolver, with no witnesses and no hosts file.
    fn automatic_sources(
        resolvers: &[(SocketAddr, Scope)],
        system: dns::SystemResolver,
    ) -> EndpointSources {
        EndpointSources {
            automatic: loopback_automatic(resolvers, &[], system),
            hosts: HostsFile::missing(),
        }
    }

    fn automatic() -> ActiveEndpointDns {
        ActiveEndpointDns::new(Ok(EndpointDnsPolicy::auto()))
    }

    /// How long the cached endpoint entry for `host` is good for.
    fn cached_for(host: &str) -> Duration {
        let entry = DNS_CACHE
            .get(&(Purpose::Endpoint, dns_cache_key(host)))
            .unwrap();
        entry.expires - entry.refreshed
    }

    /// A policy of one loopback resolver, held locally so tests never change
    /// the process-wide policy.
    fn udp_policy(server: SocketAddr, system_fallback: bool) -> ActiveEndpointDns {
        let mut entries = vec![format!("udp://{server}")];
        if system_fallback {
            entries.push("system".to_owned());
        }
        ActiveEndpointDns::new(Ok(EndpointDnsPolicy::from_entries(entries).unwrap()))
    }

    /// A loopback resolver answering every query with `reply`, and the number
    /// of queries it has received.
    async fn counting_resolver(
        reply: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        let server = fake_udp_resolver(move |_, request| {
            counter.fetch_add(1, Ordering::SeqCst);
            vec![reply(request)]
        })
        .await;
        (server, queries)
    }

    fn rcode_reply(code: ResponseCode) -> impl Fn(&[u8]) -> Vec<u8> {
        move |request| {
            response_to_request(request, code, Vec::new())
                .to_vec()
                .unwrap()
        }
    }

    async fn resolve_from(
        active: &ActiveEndpointDns,
        sources: &EndpointSources,
        host: &str,
    ) -> std::io::Result<Arc<[IpAddr]>> {
        resolve_endpoint(active, sources, host, dns_cache_key(host), false).await
    }

    /// Resolves under a policy that names its own resolvers, with nothing
    /// else to consult.
    async fn resolve_under(
        active: &ActiveEndpointDns,
        host: &str,
    ) -> std::io::Result<Arc<[IpAddr]>> {
        let sources = automatic_sources(&[], no_platform_answer);
        resolve_from(active, &sources, host).await
    }

    #[tokio::test]
    async fn the_automatic_policy_caches_an_authenticated_answer_for_its_record_ttl() {
        const HOST: &str = "automatic.endpoint-dns.example.net";
        let address = ip("203.0.113.51");
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        let resolver = fake_https_resolver(move |request| {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut reply = Message::from_vec(&addresses_reply_to(request, &[address])).unwrap();
            for record in &mut reply.answers {
                record.ttl = 90;
            }
            reply.to_vec().unwrap()
        })
        .await;
        let sources = automatic_sources(&[(resolver, Scope::Global)], no_platform_answer);
        let active = automatic();

        assert_eq!(
            *resolve_from(&active, &sources, HOST).await.unwrap(),
            [address]
        );
        assert_eq!(cached_for(HOST), Duration::from_secs(90));
        assert_eq!(
            *resolve_from(&active, &sources, HOST).await.unwrap(),
            [address]
        );
        // One A and one AAAA query; the cache served the second lookup.
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_automatic_policy_falls_back_to_the_platform_resolver_without_a_record_ttl() {
        const HOST: &str = "fallback.endpoint-dns.example.net";
        let resolver = fake_https_resolver(rcode_reply(ResponseCode::ServFail)).await;
        let sources = automatic_sources(&[(resolver, Scope::Global)], domestic_platform_answer);
        assert_eq!(
            *resolve_from(&automatic(), &sources, HOST).await.unwrap(),
            [ip("119.29.29.29")]
        );
        assert_eq!(cached_for(HOST), DNS_CACHE_TTL);
    }

    #[tokio::test]
    async fn the_automatic_policy_remembers_briefly_that_a_name_has_no_address() {
        const HOST: &str = "absent.endpoint-dns.example.net";
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        let nxdomain = rcode_reply(ResponseCode::NXDomain);
        let resolver = fake_https_resolver(move |request| {
            counter.fetch_add(1, Ordering::SeqCst);
            nxdomain(request)
        })
        .await;
        let sources = automatic_sources(&[(resolver, Scope::Global)], no_platform_answer);
        let active = automatic();

        for _ in 0..2 {
            let error = resolve_from(&active, &sources, HOST).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(cached_for(HOST), NEGATIVE_TTL_FLOOR);
    }

    #[tokio::test]
    async fn a_hosts_entry_outranks_the_resolvers_of_every_policy_but_system() {
        const HOST: &str = "Pinned.Endpoint-DNS.example.net.";
        let pinned = ip("203.0.113.60");
        let hosts = HostsFile::with(
            "pinned",
            "# the node\n203.0.113.60 pinned.endpoint-dns.example.net node\n",
        );
        let elsewhere = ip("203.0.113.61");
        let (udp, udp_queries) =
            counting_resolver(move |request| addresses_reply_to(request, &[elsewhere])).await;
        let https_requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&https_requests);
        let https = fake_https_resolver(move |request| {
            counter.fetch_add(1, Ordering::SeqCst);
            addresses_reply_to(request, &[elsewhere])
        })
        .await;
        let sources = EndpointSources {
            automatic: loopback_automatic(&[(https, Scope::Global)], &[], no_platform_answer),
            hosts: hosts.0.clone(),
        };

        for active in [automatic(), udp_policy(udp, false), udp_policy(udp, true)] {
            assert_eq!(
                *resolve_from(&active, &sources, HOST).await.unwrap(),
                [pinned]
            );
            assert_eq!(cached_for(HOST), ENDPOINT_TTL_FLOOR);
        }
        assert_eq!(udp_queries.load(Ordering::SeqCst), 0);
        assert_eq!(https_requests.load(Ordering::SeqCst), 0);

        // A name the file does not pin is resolved as the policy says.
        assert_eq!(
            *resolve_from(&automatic(), &sources, "other.endpoint-dns.example.net")
                .await
                .unwrap(),
            [elsewhere]
        );
    }

    #[tokio::test]
    async fn endpoint_answers_are_cached_per_policy_generation() {
        const HOST: &str = "generation.endpoint-dns.test";
        let (first_address, second_address) = (ip("203.0.113.41"), ip("203.0.113.42"));
        let (first, first_queries) =
            counting_resolver(move |request| addresses_reply_to(request, &[first_address])).await;
        let (second, _) =
            counting_resolver(move |request| addresses_reply_to(request, &[second_address])).await;
        let (first, second) = (udp_policy(first, false), udp_policy(second, false));

        assert_eq!(*resolve_under(&first, HOST).await.unwrap(), [first_address]);
        let asked = first_queries.load(Ordering::SeqCst);
        assert_eq!(*resolve_under(&first, HOST).await.unwrap(), [first_address]);
        assert_eq!(first_queries.load(Ordering::SeqCst), asked);
        assert_eq!(
            *resolve_under(&second, HOST).await.unwrap(),
            [second_address]
        );
    }

    #[tokio::test]
    async fn concurrent_endpoint_lookups_share_one_resolution() {
        const HOST: &str = "concurrent.endpoint-dns.test";
        let address = ip("203.0.113.44");
        let (server, queries) =
            counting_resolver(move |request| addresses_reply_to(request, &[address])).await;
        let active = udp_policy(server, false);
        let lookups = futures::future::join_all((0..4).map(|_| resolve_under(&active, HOST))).await;
        for addresses in lookups {
            assert_eq!(*addresses.unwrap(), [address]);
        }
        // One A and one AAAA query, however many callers waited.
        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn endpoint_resolvers_fail_closed_unless_the_policy_ends_in_system() {
        let (servfail, _) = counting_resolver(rcode_reply(ResponseCode::ServFail)).await;

        let error = resolve_under(&udp_policy(servfail, false), "localhost")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(
            error.to_string().contains(&format!("udp://{servfail}")),
            "{error}"
        );

        let addresses = resolve_under(&udp_policy(servfail, true), "localhost")
            .await
            .unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(IpAddr::is_loopback), "{addresses:?}");
    }

    #[tokio::test]
    async fn missing_endpoints_are_cached_briefly_without_a_fallback() {
        const HOST: &str = "missing.endpoint-dns.test";
        let (server, queries) = counting_resolver(rcode_reply(ResponseCode::NXDomain)).await;
        let active = udp_policy(server, false);

        let error = resolve_under(&active, HOST).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        let asked = queries.load(Ordering::SeqCst);
        let error = resolve_under(&active, HOST).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(queries.load(Ordering::SeqCst), asked);
    }

    #[tokio::test]
    async fn sinkhole_only_endpoint_answers_fail_closed() {
        let (server, _) = counting_resolver(|request| {
            addresses_reply_to(request, &[IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)])
        })
        .await;
        let error = resolve_under(&udp_policy(server, false), "sinkhole.endpoint-dns.test")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only addresses no remote endpoint can have"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn destination_lookups_never_serve_endpoint_answers() {
        let system = resolve_host_addresses("localhost").await.unwrap();
        let address = ip("203.0.113.43");
        let (server, _) =
            counting_resolver(move |request| addresses_reply_to(request, &[address])).await;

        let endpoint = resolve_under(&udp_policy(server, false), "localhost")
            .await
            .unwrap();
        assert_eq!(*endpoint, [address]);
        assert_eq!(resolve_host_addresses("localhost").await.unwrap(), system);
    }

    #[tokio::test]
    async fn an_invalid_policy_fails_endpoint_lookups_instead_of_using_the_system_resolver() {
        let active = ActiveEndpointDns::new(Err(ParsePolicyError::Empty));
        let error = resolve_under(&active, "localhost").await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "invalid ENDPOINT_DNS");
        assert!(
            error
                .get_ref()
                .and_then(std::error::Error::source)
                .is_some_and(|source| source.is::<ParsePolicyError>()),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn silent_external_proxies_release_the_connection_at_the_setup_deadline() {
        for scheme in ["http", "socks5h"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = ExternalProxyTarget::parse(&format!(
                "{scheme}://{}",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let client = tokio::spawn(async move {
                get_tcp_external_proxy_stream(&proxy, "example.test", 443, "deadline test").await
            });
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(peer.read(&mut request).await.unwrap() > 0);
            // Real socket readiness must arrive before virtual time can skip
            // ahead; otherwise an idle runtime can expire the handshake first.
            tokio::time::pause();
            tokio::time::advance(EXTERNAL_PROXY_TIMEOUT).await;
            let error = client.await.unwrap().unwrap_err();
            tokio::time::resume();
            assert!(error.to_string().contains("handshake exceeded 15 seconds"));
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
        }
    }

    #[tokio::test]
    async fn http_connect_preserves_coalesced_payload_and_formats_ipv6_authorities() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            ExternalProxyTarget::parse(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT [::1]:443 HTTP/1.1\r\n"));
            // Split the delimiter across reads, then coalesce its end with data.
            peer.write_all(b"HTTP/1.1 200 OK\r\n\r").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            peer.write_all(b"\nserver greeting").await.unwrap();
        });
        let mut stream = get_tcp_external_proxy_stream(&proxy, "::1", 443, "payload test")
            .await
            .unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"server greeting");
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_blackholed_preferred_address_does_not_delay_the_other_family() {
        let started = Instant::now();
        let ips = [
            "::1".parse().unwrap(),
            "::2".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ];
        let connected = race_addresses(&ips, 80, false, |address| async move {
            if address.is_ipv6() {
                std::future::pending::<()>().await;
            }
            Ok(address)
        })
        .await
        .unwrap();
        assert!(connected.is_ipv4());
        assert_eq!(started.elapsed(), ADDRESS_STAGGER);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_candidates_advance_without_the_stagger_delay() {
        let started = Instant::now();
        let ips = ["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
        let connected = race_addresses(&ips, 80, false, |address| async move {
            if address.ip() == "127.0.0.1".parse::<IpAddr>().unwrap() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            Ok(address)
        })
        .await
        .unwrap();
        assert_eq!(connected.ip(), ips[1]);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_stalled_dial_drops_every_candidate_and_bounds_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ips = (1..=20)
            .map(|n| IpAddr::from([127, 0, 0, n]))
            .collect::<Vec<_>>();
        for addresses in [&ips[..1], &ips[..]] {
            peak.store(0, Ordering::SeqCst);
            let attempt = race_addresses(addresses, 80, true, |_| {
                let active = Active(Arc::clone(&count));
                peak.fetch_max(count.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                async move {
                    let _active = active;
                    std::future::pending::<std::io::Result<()>>().await
                }
            });
            assert!(
                tokio::time::timeout(Duration::from_secs(30), attempt)
                    .await
                    .is_err()
            );
            assert_eq!(peak.load(Ordering::SeqCst), 2);
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn single_address_backup_recovers_a_lost_syn_and_cancels_the_loser() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct Pending(Arc<AtomicBool>);
        impl Drop for Pending {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicBool::new(false));
        let attempts = AtomicUsize::new(0);
        let started = Instant::now();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let connected = race_addresses(&[ip], 80, true, |address| {
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let active = Arc::clone(&active);
            async move {
                if first {
                    active.store(true, Ordering::SeqCst);
                    let _guard = Pending(active);
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(Duration::from_millis(60)).await;
                Ok(address)
            }
        })
        .await
        .unwrap();
        assert_eq!(connected, SocketAddr::new(ip, 80));
        assert_eq!(
            started.elapsed(),
            ADDRESS_STAGGER + Duration::from_millis(60)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(!active.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn completed_single_address_handshakes_do_not_start_a_backup() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for refused in [false, true] {
            let attempts = AtomicUsize::new(0);
            let started = Instant::now();
            let result = race_addresses(&[IpAddr::from([127, 0, 0, 1])], 80, true, |_| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    if refused {
                        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                    } else {
                        Ok(())
                    }
                }
            })
            .await;
            assert_eq!(result.is_err(), refused);
            assert_eq!(started.elapsed(), Duration::from_millis(60));
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_ip_can_connect_after_the_former_nested_deadlines() {
        let ip = "127.0.0.1".parse().unwrap();
        let connected = race_addresses(&[ip], 80, false, |address| async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            Ok(address)
        })
        .await
        .unwrap();
        assert_eq!(connected, SocketAddr::new(ip, 80));
    }

    async fn start_echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });
        addr.to_string()
    }

    async fn start_http_proxy(expected_auth: Option<String>) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_log = Arc::new(Mutex::new(String::new()));
        let request_log_clone = request_log.clone();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = inbound.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request_str = String::from_utf8_lossy(&request).into_owned();
            *request_log_clone.lock().await = request_str.clone();
            if let Some(auth) = expected_auth {
                assert!(request_str.contains(&format!("Proxy-Authorization: Basic {auth}\r\n")));
            }
            let connect_line = request_str.lines().next().unwrap();
            let target = connect_line
                .strip_prefix("CONNECT ")
                .and_then(|v| v.split_whitespace().next())
                .unwrap();
            let mut target_parts = target.rsplitn(2, ':');
            let port: u16 = target_parts.next().unwrap().parse().unwrap();
            let host = target_parts.next().unwrap();
            let mut outbound = TcpStream::connect((host, port)).await.unwrap();
            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        (addr.to_string(), request_log)
    }

    async fn start_socks5_proxy(
        username: Option<&'static str>,
        password: Option<&'static str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();

            let ver = inbound.read_u8().await.unwrap();
            assert_eq!(ver, 0x05);
            let methods_len = inbound.read_u8().await.unwrap() as usize;
            let mut methods = vec![0u8; methods_len];
            inbound.read_exact(&mut methods).await.unwrap();
            let method = if username.is_some() { 0x02 } else { 0x00 };
            assert!(methods.contains(&method));
            inbound.write_all(&[0x05, method]).await.unwrap();

            if let (Some(username), Some(password)) = (username, password) {
                assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
                let username_len = inbound.read_u8().await.unwrap() as usize;
                let mut username_buf = vec![0u8; username_len];
                inbound.read_exact(&mut username_buf).await.unwrap();
                let password_len = inbound.read_u8().await.unwrap() as usize;
                let mut password_buf = vec![0u8; password_len];
                inbound.read_exact(&mut password_buf).await.unwrap();
                assert_eq!(String::from_utf8(username_buf).unwrap(), username);
                assert_eq!(String::from_utf8(password_buf).unwrap(), password);
                inbound.write_all(&[0x01, 0x00]).await.unwrap();
            }

            assert_eq!(inbound.read_u8().await.unwrap(), 0x05);
            assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
            assert_eq!(inbound.read_u8().await.unwrap(), 0x00);
            let atyp = inbound.read_u8().await.unwrap();
            let host = match atyp {
                0x01 => {
                    let mut buf = [0u8; 4];
                    inbound.read_exact(&mut buf).await.unwrap();
                    std::net::Ipv4Addr::from(buf).to_string()
                }
                0x03 => {
                    let len = inbound.read_u8().await.unwrap() as usize;
                    let mut buf = vec![0u8; len];
                    inbound.read_exact(&mut buf).await.unwrap();
                    String::from_utf8(buf).unwrap()
                }
                other => panic!("unexpected atyp: {other:#x}"),
            };
            let port = inbound.read_u16().await.unwrap();
            let mut outbound = TcpStream::connect((host.as_str(), port)).await.unwrap();
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn test_connect_via_http_proxy_with_basic_auth() {
        let target_addr = start_echo_server().await;
        let (target_host, target_port) = target_addr.split_once(':').unwrap();
        let target_port: u16 = target_port.parse().unwrap();

        let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
        let (proxy_addr, request_log) = start_http_proxy(Some(expected_auth)).await;
        let proxy =
            ExternalProxyTarget::parse(&format!("http://user:secret@{proxy_addr}")).unwrap();

        let mut stream =
            get_tcp_external_proxy_stream(&proxy, target_host, target_port, "http proxy auth test")
                .await
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(request_log.lock().await.starts_with("CONNECT "));
    }

    #[tokio::test]
    async fn test_connect_via_socks5_proxy_with_password_auth() {
        let target_addr = start_echo_server().await;
        let (target_host, target_port) = target_addr.split_once(':').unwrap();
        let target_port: u16 = target_port.parse().unwrap();

        let proxy_addr = start_socks5_proxy(Some("user"), Some("secret")).await;
        let proxy =
            ExternalProxyTarget::parse(&format!("socks5://user:secret@{proxy_addr}")).unwrap();

        let mut stream = get_tcp_external_proxy_stream(
            &proxy,
            target_host,
            target_port,
            "socks5 proxy auth test",
        )
        .await
        .unwrap();
        stream.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }
}
