//! Local listener and protocol dispatch. Route decisions, forwarding,
//! and errors live in their owning modules; native sessions are always encrypted.

#[cfg(feature = "auto-proxy")]
pub mod auto_proxy;
mod connection;
use connection::connect_native;
pub use connection::*;
mod forward;
pub use forward::*;
pub mod http;
mod icmp;
#[cfg(target_os = "macos")]
pub mod macos_dns_restore;
#[cfg(target_os = "macos")]
pub mod macos_tun;
#[cfg(feature = "network-extension")]
pub mod packet_tunnel;
pub mod socks;
pub mod tun;
mod udp;
#[cfg(target_os = "windows")]
mod windows_apps;
#[cfg(target_os = "windows")]
mod windows_icon;

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "auto-proxy")]
use auto_proxy::{SenderChan, run_auto_proxy_by_country};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::util::{GracefulShutdownManager, GracefulShutdownManagerImpl, error_report};
use snafu::ResultExt;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use self::http::HttpProxierProvider;
use self::socks::SocksProxierProvider;

mod error;
pub use error::ClientError;
use error::*;

pub type Result<T> = std::result::Result<T, ClientError>;

/// Runtime configuration for client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub enable_auto_proxy: bool,
    /// Accept RFC 1928 UDP ASSOCIATE requests on the local SOCKS5 listener.
    pub enable_udp: bool,
    pub cache_dir: Option<PathBuf>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            // Preserve the previous explicit-config default while keeping UDP
            // enabled for callers that have not learned about this option yet.
            enable_auto_proxy: false,
            enable_udp: true,
            cache_dir: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientRuntimeConfig {
    pub client: ClientConfig,
    pub upstream_proxy: Option<ExternalProxyTarget>,
    /// Optional device-wide TUN capture routed through the local SOCKS5 listener.
    pub tun: Option<tun::TunConfig>,
    /// Runtime override used when an independently managed TUN session is
    /// enabled after the local listener has started. While set, every accepted
    /// connection uses the remote proxy so client-owned direct sockets cannot
    /// be captured and fed back into the listener.
    pub force_proxy: Option<Arc<AtomicBool>>,
}

impl From<ClientConfig> for ClientRuntimeConfig {
    fn from(client: ClientConfig) -> Self {
        Self {
            client,
            upstream_proxy: None,
            tun: None,
            force_proxy: None,
        }
    }
}

pub trait Forwarder {
    fn forward(self) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderContext<'a> {
    header: &'a [u8],
}

pub struct ProxyContext<'a> {
    /// Limit untrusted client input, not the outbound TCP connection.
    handshake_deadline: tokio::time::Instant,
    /// header buffer for response [only http proxy use]
    buffer: &'a [u8],
    #[cfg(feature = "auto-proxy")]
    sender: Option<&'a SenderChan>,
    /// Force all connections to go through proxy, bypassing auto-proxy rules.
    force_proxy: bool,
    /// Optional external upstream proxy used instead of the encrypted proxy server.
    upstream_proxy: Option<&'a ExternalProxyTarget>,
    /// Honour [`proxy_core::config::FORCED_DIRECT_HOSTS`]. Disabled only while a
    /// TUN session owns the routes, where a direct socket from this process
    /// would be captured back into the local listener.
    honor_forced_direct: bool,
    /// Whether the local listener accepts SOCKS5 UDP ASSOCIATE requests.
    enable_udp: bool,
    /// TODO: let this stream abstract
    stream: TcpStream,
}

pub trait ForwarderProvider {
    type Item: Forwarder;

    fn try_new(header_context: HeaderContext<'_>) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn try_build_forwarder(
        self,
        proxy_context: ProxyContext<'_>,
    ) -> impl std::future::Future<Output = Result<Self::Item>> + Send;
}

pub struct ClientProxyContext {
    stream: TcpStream,
    #[cfg(feature = "auto-proxy")]
    sender: Option<SenderChan>,
    force_proxy: bool,
    upstream_proxy: Option<ExternalProxyTarget>,
    honor_forced_direct: bool,
    enable_udp: bool,
}

async fn handle_proxy(
    proxy_context: ProxyContext<'_>,
    provider: impl ForwarderProvider,
    permit: tokio::sync::SemaphorePermit<'_>,
) -> Result<()> {
    let proxier = provider.try_build_forwarder(proxy_context).await?;
    drop(permit);
    proxier.forward().await
}

const CLIENT_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
static CLIENT_SETUP_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(256);

fn setup_timeout() -> ClientError {
    ClientError::Io {
        uri: None,
        detail: "local proxy handshake timed out",
        source: std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "proxy setup deadline exceeded",
        ),
    }
}

async fn read_initial_header(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let first = stream.read_u8().await?;
    let mut header = vec![first];
    if first == 5 {
        let methods = stream.read_u8().await?;
        header.push(methods);
        header.resize(2 + usize::from(methods), 0);
        stream.read_exact(&mut header[2..]).await?;
        return Ok(header);
    }
    proxy_core::transport::read_http_header(stream, &mut header, MAX_HTTP_HEADER_BYTES).await?;
    Ok(header)
}

#[tracing::instrument(skip_all)]
pub async fn handle_client(mut context: ClientProxyContext) -> Result<()> {
    let permit = CLIENT_SETUP_SLOTS
        .try_acquire()
        .map_err(|_| ClientError::Io {
            uri: None,
            detail: "local proxy setup capacity exhausted",
            source: std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "too many pending handshakes",
            ),
        })?;
    let deadline = tokio::time::Instant::now() + CLIENT_SETUP_TIMEOUT;
    let header_buf = tokio::time::timeout_at(deadline, read_initial_header(&mut context.stream))
        .await
        .map_err(|_| setup_timeout())?
        .context(IoSnafu {
            uri: None,
            detail: "Read First Header Error",
        })?;
    let header = header_buf.as_slice();
    let header_context = HeaderContext { header };
    let proxy_context = ProxyContext {
        handshake_deadline: deadline,
        buffer: header,
        #[cfg(feature = "auto-proxy")]
        sender: context.sender.as_ref(),
        force_proxy: context.force_proxy,
        upstream_proxy: context.upstream_proxy.as_ref(),
        honor_forced_direct: context.honor_forced_direct,
        enable_udp: context.enable_udp,
        stream: context.stream,
    };

    if header.first() == Some(&5) {
        handle_proxy(
            proxy_context,
            SocksProxierProvider::try_new(header_context)?,
            permit,
        )
        .await
    } else {
        handle_proxy(
            proxy_context,
            HttpProxierProvider::try_new(header_context)?,
            permit,
        )
        .await
    }
}

#[cfg(feature = "auto-proxy")]
const DEFAULT_CHAN_CAP: usize = 1024;

static NEXT_CONNECTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[tracing::instrument(skip_all, fields(
    connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
    peer = ?context.stream.peer_addr().ok(),
))]
async fn client_proxy_background_task(context: ClientProxyContext) {
    if let Err(error) = handle_client(context).await {
        tracing::error!(error = %error_report(&error), "proxy connection failed");
    }
}

/// Run client with a pre-bound listener and cancellation token.
///
/// This is the core client loop. Use `start_client` for production with
/// graceful shutdown, or call this directly for testing/custom setups.
pub async fn run_client_with_listener(
    listener: TcpListener,
    cancel_token: CancellationToken,
    tracker: Option<TaskTracker>,
    config: Option<ClientConfig>,
) {
    run_client_with_listener_runtime_config(listener, cancel_token, tracker, config.map(Into::into))
        .await
}

/// Whether per-host auto-proxy decisions apply to this listener.
///
/// TUN mode deliberately does *not* appear here. A direct socket opened by this
/// process is captured by the tunnel, recognised as belonging to a bypassed
/// process — the current executable is always in the bypass list — and relayed
/// out through the physical interface rather than back into this listener. The
/// same relay maps the fake virtual-DNS destination back to the real address, so
/// a direct decision can actually connect. TUN mode used to force everything
/// through the proxy because neither of those existed yet.
///
/// An upstream proxy does rule auto-proxy out: every connection is forwarded to a
/// third party, so there is no direct decision left to make.
fn auto_proxy_applies(enable_auto_proxy: bool, has_upstream_proxy: bool) -> bool {
    cfg!(feature = "auto-proxy") && enable_auto_proxy && !has_upstream_proxy
}

pub async fn run_client_with_listener_runtime_config(
    listener: TcpListener,
    cancel_token: CancellationToken,
    tracker: Option<TaskTracker>,
    config: Option<ClientRuntimeConfig>,
) {
    let enable_auto_proxy = config
        .as_ref()
        .map(|c| c.client.enable_auto_proxy)
        .unwrap_or(true);
    let upstream_proxy = config.as_ref().and_then(|c| c.upstream_proxy.clone());
    let tun_config = config.as_ref().and_then(|c| c.tun.clone());
    let force_proxy_controller = config.as_ref().and_then(|c| c.force_proxy.clone());
    let enable_udp = config.as_ref().map(|c| c.client.enable_udp).unwrap_or(true);
    let tun_active = tun_config.is_some();
    let enable_auto_proxy = auto_proxy_applies(enable_auto_proxy, upstream_proxy.is_some());
    let force_proxy = !enable_auto_proxy;
    #[cfg(feature = "auto-proxy")]
    let cache_dir = config.as_ref().and_then(|c| c.client.cache_dir.clone());
    let upstream_proxy_display = upstream_proxy.as_ref().map(|proxy| proxy.display_url());
    tracing::info!(
        local_addr = ?listener.local_addr().ok(),
        enable_auto_proxy,
        enable_udp,
        force_proxy,
        dynamic_force_proxy = force_proxy_controller.is_some(),
        tun_enabled = tun_config.is_some(),
        upstream_proxy = ?upstream_proxy_display,
        "client listener configured"
    );

    let tun_task = tun_config.map(|tun_config| {
        let token = cancel_token.clone();
        let local_port = listener.local_addr().map(|address| address.port());
        async move {
            let local_port = match local_port {
                Ok(port) => port,
                Err(error) => {
                    tracing::error!(%error, "cannot determine local listener port for TUN mode");
                    return;
                }
            };
            match tun::run(local_port, tun_config, token.clone()).await {
                Ok(sessions) => {
                    tracing::info!(remaining_sessions = sessions, "TUN traffic capture stopped");
                }
                Err(error) => {
                    tracing::error!(%error, "TUN traffic capture failed");
                    // Do not leave the application claiming to proxy device
                    // traffic after TUN setup or its relay loop has failed.
                    token.cancel();
                }
            }
        }
    });
    if let Some(task) = tun_task {
        if let Some(ref tracker) = tracker {
            tracker.spawn(task);
        } else {
            tokio::spawn(task);
        }
    }

    #[cfg(feature = "auto-proxy")]
    let sender: Option<SenderChan> = if enable_auto_proxy {
        let (tx, rx) = kanal::bounded_async(DEFAULT_CHAN_CAP);
        let token = cancel_token.clone();
        let cache_dir = cache_dir.clone();
        let task = async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = run_auto_proxy_by_country(rx, cache_dir) => {}
            }
        };
        if let Some(ref t) = tracker {
            t.spawn(task);
        } else {
            tokio::spawn(task);
        }
        Some(tx)
    } else {
        None
    };

    loop {
        tokio::select! {
            ret = listener.accept() => {
                let Ok((stream, _)) = ret else {
                    continue;
                };
                let token = cancel_token.clone();
                #[cfg(feature = "auto-proxy")]
                let sender = if force_proxy_controller
                    .as_ref()
                    .is_some_and(|controller| controller.load(Ordering::Acquire))
                {
                    None
                } else {
                    sender.clone()
                };
                let tun_owns_routes = tun_active
                    || force_proxy_controller
                        .as_ref()
                        .is_some_and(|controller| controller.load(Ordering::Acquire));
                // `force_proxy` now comes from the auto-proxy setting and the
                // dynamic controller alone. TUN owning the routes no longer
                // implies it: process bypass keeps this listener's own direct
                // sockets out of the tunnel.
                let force_proxy = force_proxy
                    || force_proxy_controller
                        .as_ref()
                        .is_some_and(|controller| controller.load(Ordering::Acquire));
                let task = client_proxy_background_task(ClientProxyContext {
                    stream,
                    #[cfg(feature = "auto-proxy")]
                    sender,
                    force_proxy,
                    upstream_proxy: upstream_proxy.clone(),
                    // Left as-is under TUN. This path calls the same
                    // `get_tcp_stream` as auto-proxy's direct decision, so the
                    // bypass relay would repair its destination too and enabling
                    // it should work — but that is a separate behaviour change to
                    // a compiled-in list, so it stays off until asked for.
                    // See `proxy_core::config::FORCED_DIRECT_HOSTS`.
                    honor_forced_direct: !tun_owns_routes,
                    enable_udp,
                });
                let wrapped_task = async move {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        _ = task => {}
                    }
                };
                if let Some(ref t) = tracker {
                    t.spawn(wrapped_task);
                } else {
                    tokio::spawn(wrapped_task);
                }
            }
            _ = cancel_token.cancelled() => {
                break;
            }
        }
    }
}

/// Start client with optional runtime configuration.
///
/// This is useful when callers want to explicitly toggle auto-proxy behavior
/// without relying on environment variables.
#[tracing::instrument]
pub async fn start_client_with_config(
    host: impl AsRef<str> + Debug,
    port: u16,
    config: Option<ClientConfig>,
) -> Result<()> {
    start_client_with_runtime_config(host, port, config.map(Into::into)).await
}

#[tracing::instrument(skip(config))]
pub async fn start_client_with_runtime_config(
    host: impl AsRef<str> + Debug,
    port: u16,
    config: Option<ClientRuntimeConfig>,
) -> Result<()> {
    let listener = TcpListener::bind((host.as_ref(), port))
        .await
        .context(IoSnafu {
            uri: None,
            detail: "Client listener error",
        })?;
    let mut manager = GracefulShutdownManagerImpl::new();
    if !manager.spawn_graceful_signals() {
        RegisterSignalSnafu {}.fail()?
    }
    let cancel_token = manager.cancellation_token();
    let tracker = manager.tracker().clone();

    run_client_with_listener_runtime_config(listener, cancel_token, Some(tracker), config).await;

    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
    Ok(())
}

#[tracing::instrument]
pub async fn start_client(host: impl AsRef<str> + Debug, port: u16) -> Result<()> {
    start_client_with_config(host, port, None).await
}

#[cfg(test)]
mod tests;
