//! Client-side proxy implementation.
//!
//! This module provides the client-side proxy functionality, supporting both
//! HTTP/HTTPS and SOCKS5 protocols. The client listens on a local port and
//! forwards traffic to the remote proxy server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Client Architecture                              │
//! │                                                                         │
//! │  Browser/App ──► Local Proxy (1080) ──► Protocol Handler ──► Server    │
//! │                         │                     │                         │
//! │                         ▼                     ▼                         │
//! │                  ┌─────────────┐      ┌─────────────┐                  │
//! │                  │ HTTP/HTTPS  │      │   SOCKS5    │                  │
//! │                  │   Handler   │      │   Handler   │                  │
//! │                  └─────────────┘      └─────────────┘                  │
//! │                         │                     │                         │
//! │                         └──────────┬─────────┘                         │
//! │                                    ▼                                    │
//! │                           ┌─────────────────┐                          │
//! │                           │  Auto-Proxy     │                          │
//! │                           │  Decision       │                          │
//! │                           └─────────────────┘                          │
//! │                                    │                                    │
//! │                         ┌──────────┴──────────┐                        │
//! │                         ▼                     ▼                         │
//! │                   Direct Connect        Proxy Server                   │
//! │                   (CN traffic)          (Foreign)                      │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Protocol Support
//!
//! - **HTTP**: Plain HTTP requests are forwarded directly or through proxy
//! - **HTTPS**: CONNECT method establishes encrypted tunnel
//! - **SOCKS5**: TCP CONNECT and UDP ASSOCIATE with IPv4/IPv6/domain support
//!
//! # Auto-Proxy Feature
//!
//! When the `auto-proxy` feature is enabled, the client automatically decides
//! whether to use the proxy based on the destination's geographic location:
//!
//! - **Direct**: CN (China) traffic
//! - **Proxy**: US, SG, TW, HK, JP, IN traffic

#[cfg(feature = "auto-proxy")]
pub mod auto_proxy;
pub mod http;
#[cfg(target_os = "macos")]
pub mod macos_dns_restore;
#[cfg(target_os = "macos")]
pub mod macos_tun;
pub mod socks;
pub mod tun;
mod udp;
#[cfg(target_os = "windows")]
mod windows_apps;
#[cfg(target_os = "windows")]
mod windows_icon;

use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "auto-proxy")]
use auto_proxy::{SenderChan, run_auto_proxy_by_country};
use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::config::{gen_random_key, runtime};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::util::{GracefulShutdownManager, GracefulShutdownManagerImpl, error_report};
use proxy_core::{client_proxy_with_cryptor_codec, proxy_with_norlmal_codec};
use snafu::{Report, ResultExt, Snafu};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use self::http::{HttpProxierProvider, HttpProxyError};
use self::socks::{SocksError, SocksProxierProvider};

#[derive(Debug, Snafu)]
pub enum ClientError {
    #[snafu(display("URI(`{uri}`) Serde json failed"))]
    SerdeJson {
        uri: String,
        source: serde_json::Error,
    },
    #[snafu(display("URI(`{uri:?}`),Io error occur: {detail}"))]
    Io {
        uri: Option<String>,
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("URI(`{uri}`) Encryption error occur,detail:{detail}"))]
    Encryption { uri: String, detail: String },
    #[snafu(display("URI(`{uri}`) Send header error"))]
    SendHeader {
        uri: String,
        source: proxy_core::ProxyError,
    },
    #[snafu(display("URI(`{uri}`) Proxy error happen"))]
    Proxy {
        uri: String,
        source: proxy_core::ProxyError,
    },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("URI(`{uri}`) Send item for auto proxy error"))]
    SendAutoProxy { uri: String },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("URI(`{uri}`) Recv item form auto proxy error"))]
    ReciveAutoProxy { uri: String },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Can't proxy localhost!!! Host(`127.0.0.1:{port}`)"))]
    LocalHost { port: u16 },
    #[snafu(display("Http proxy error"))]
    HttpProxy { source: HttpProxyError },
    #[snafu(display("Socks proxy error"))]
    SocksProxy { source: SocksError },
    #[snafu(display("External proxy error"))]
    ExternalProxy {
        source: proxy_core::transport::TransportError,
    },
    #[snafu(display("UDP proxy error"))]
    Datagram { source: proxy_core::ProxyError },
    #[snafu(display("Signals register error"))]
    RegisterSignal,
    #[snafu(display("Empty dns record"))]
    EmptyDNSRecord,
}

#[inline]
pub fn get_msg_key_from_codec_ip(ip: impl AsRef<str>) -> Option<String> {
    let codec_ips = runtime::need_codec_ips();
    codec_ips
        .iter()
        .find(|codec_ip| codec_ip.as_str() == ip.as_ref())
        .map(|_| gen_random_key())
}

/// Change `msg_key` when it is none
#[inline]
pub fn change_msg_key(
    ip: impl AsRef<str>,
    msg_key: Option<Cow<'static, str>>,
) -> Option<Cow<'static, str>> {
    if msg_key.is_none() {
        get_msg_key_from_codec_ip(ip).map(Cow::Owned)
    } else {
        msg_key
    }
}

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
    msg_key: Option<&'a str>,
}

pub struct ProxyContext<'a> {
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

pub trait ProxierProviderType {
    type Provider: ForwarderProvider;
    const PROXY_TYPE: &'static str;
}

macro_rules! make_provider_type {
    ($name:ident, $proxy_type:expr, $provider_name:ty) => {
        pub struct $name {}

        impl ProxierProviderType for $name {
            type Provider = $provider_name;

            const PROXY_TYPE: &'static str = $proxy_type;
        }
    };
}

make_provider_type!(HttpProxierProviderType, "HTTP/HTTPS", HttpProxierProvider);
make_provider_type!(SocksProxierProviderType, "SOCKS5", SocksProxierProvider);

pub type TcpAsyncReader<T = OwnedReadHalf> = AsyncReader<T>;
pub type TcpAsyncWriter<T = OwnedWriteHalf> = AsyncWriter<T>;

#[derive(Debug)]
pub struct ForwardContext {
    host: String,
    port: u16,
    need_proxy: bool,
    msg_key: Option<Cow<'static, str>>,
}

impl Display for ForwardContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "addr:({}:{}) need_proxy({})",
            self.host, self.port, self.need_proxy
        )
    }
}

pub struct TcpForwardImpl {
    context: ForwardContext,
    client_reader: TcpAsyncReader,
    client_writer: TcpAsyncWriter,
    server_reader: TcpAsyncReader,
    server_writer: TcpAsyncWriter,
}

// ============================================================================
// Common Helper Functions
// ============================================================================

/// Splits a TcpStream into async reader and writer.
///
/// This is a convenience function that wraps the stream splitting
/// and adapter creation into a single call.
#[inline]
pub fn split_and_wrap(stream: TcpStream) -> (TcpAsyncReader, TcpAsyncWriter) {
    let (r, w) = stream.into_split();
    (AsyncReader::new(r), AsyncWriter::new(w))
}

/// Result of server connection resolution.
///
/// Encapsulates the connection state after proxy decision,
/// including the established stream and routing information.
pub struct ServerConnection {
    /// The established TCP connection to the server (direct or proxy).
    pub stream: TcpStream,
    /// Whether the connection goes through the proxy server.
    pub need_proxy: bool,
    /// Optional session encryption key.
    pub msg_key: Option<Cow<'static, str>>,
}

/// Resolves server connection based on proxy rules.
///
/// This function unifies the connection establishment logic for both
/// HTTP and SOCKS5 protocols. It handles:
///
/// 1. Auto-proxy decision (if enabled)
/// 2. Direct connection for non-proxy hosts
/// 3. Proxy connection through configured server
///
/// # Arguments
///
/// * `host` - Target hostname or IP
/// * `port` - Target port
/// * `sender` - Channel for auto-proxy queries (None = always proxy)
/// * `msg_key` - Optional pre-configured session key
///
/// # Returns
///
/// A `ServerConnection` containing the established stream and routing info.
#[cfg(feature = "auto-proxy")]
pub async fn resolve_server_connection(
    host: &str,
    port: u16,
    sender: Option<&SenderChan>,
    msg_key: Option<Cow<'static, str>>,
    upstream_proxy: Option<&ExternalProxyTarget>,
    honor_forced_direct: bool,
) -> Result<ServerConnection> {
    use proxy_core::config::runtime;

    // Ahead of the upstream proxy and of every keyword or geo rule: these hosts
    // are compiled in as direct, so no configuration can route them elsewhere.
    if honor_forced_direct && proxy_core::config::is_forced_direct_host(host) {
        return Ok(ServerConnection {
            stream: get_tcp_stream(host, port, "[NOPROXY-FORCED] compiled-in direct host").await?,
            need_proxy: false,
            msg_key,
        });
    }

    if let Some(upstream_proxy) = upstream_proxy {
        tracing::debug!(
            host,
            port,
            upstream_proxy = %upstream_proxy.display_url(),
            "connecting target through upstream proxy"
        );
        let stream = proxy_core::transport::get_tcp_external_proxy_stream(
            upstream_proxy,
            host,
            port,
            "[UPSTREAM-PROXY] connect through external proxy",
        )
        .await
        .context(ExternalProxySnafu)?;
        return Ok(ServerConnection {
            stream,
            need_proxy: true,
            msg_key: None,
        });
    }

    // One connection must observe one complete upstream generation. The FFI
    // may replace this snapshot while TUN remains enabled.
    let server_endpoint = runtime::server_endpoint();

    // If sender is None (auto-proxy disabled), always use proxy
    if let Some(sender) = sender {
        match need_proxy(host, port, sender).await? {
            ProxyStatus::NorlmalProxy => {}
            ProxyStatus::NoProxy(detail) => {
                return Ok(ServerConnection {
                    stream: get_tcp_stream(host, port, detail).await?,
                    need_proxy: false,
                    msg_key,
                });
            }
            ProxyStatus::NeedSpecialProxy(proxy_server) => {
                let msg_key = change_msg_key(proxy_server.as_str(), msg_key);
                return Ok(ServerConnection {
                    stream: get_tcp_proxy_stream(
                        host,
                        port,
                        &proxy_server,
                        server_endpoint.port,
                        msg_key.clone(),
                        "[PROXY] special proxy",
                    )
                    .await?,
                    need_proxy: true,
                    msg_key,
                });
            }
        }
    }

    // Default: use normal proxy
    let msg_key = change_msg_key(server_endpoint.host.as_str(), msg_key);
    Ok(ServerConnection {
        stream: get_tcp_proxy_stream(
            host,
            port,
            &server_endpoint.host,
            server_endpoint.port,
            msg_key.clone(),
            "[PROXY] default proxy",
        )
        .await?,
        need_proxy: true,
        msg_key,
    })
}

// ============================================================================
// URI and Proxy Status
// ============================================================================

#[inline]
pub fn get_uri(host: impl AsRef<str>, port: u16) -> String {
    format!("{}:{}", host.as_ref(), port)
}

pub enum ProxyStatus {
    NorlmalProxy,
    NoProxy(&'static str),
    NeedSpecialProxy(String),
}

/// How long a connection waits for a first-time geo decision before proceeding
/// through the proxy.
///
/// Sized from measured ip-api round-trips (170-680ms from the development
/// machine), so a healthy lookup still answers within it and keeps its accurate
/// decision. A shorter bound would discard good answers in the common case; a
/// longer one would be felt as a stall. Expiring is safe and self-correcting: the
/// connection uses the proxy, and the lookup finishes in the background and
/// records the answer for the next connection to that host.
///
/// The geo HTTP client has its own 2s timeout, so this is what actually bounds the
/// front end.
#[cfg(feature = "auto-proxy")]
const AUTO_PROXY_DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(800);

/// we will not proxy if option is some
#[cfg(feature = "auto-proxy")]
pub async fn need_proxy(
    host: impl AsRef<str>,
    port: u16,
    sender: &SenderChan,
) -> Result<ProxyStatus> {
    use proxy_core::config::runtime;

    if host.as_ref() == "127.0.0.1" {
        LocalHostSnafu { port }.fail()?;
    }
    // prehandle when host contain `NONPROXY_KEYWORS` or `PROXY_KEYWORDS`
    let nonproxy_keywords = runtime::nonproxy_keywords();
    let proxy_keywords = runtime::proxy_keywords();
    let has_nonproxy_list = nonproxy_keywords.iter().any(|v| host.as_ref().contains(v));
    let has_proxy_status = proxy_keywords
        .iter()
        .find(|v| host.as_ref().contains(&v.name_server))
        .map(|v| match v.proxy_server.as_ref() {
            Some(proxy_server) => ProxyStatus::NeedSpecialProxy(proxy_server.clone()),
            None => ProxyStatus::NorlmalProxy,
        });
    if has_nonproxy_list && has_proxy_status.is_none() {
        return Ok(ProxyStatus::NoProxy(
            "[NOPROXY-RULES] we will start connect server directly",
        ));
    }
    match has_proxy_status {
        None => {
            // Fast-path: check global cache before sending to channel
            // This bypasses channel overhead for cache hits (O(1) lookup)
            if let Some(need_proxy) = auto_proxy::PROXY_CACHE.get(host.as_ref()) {
                let need_proxy = *need_proxy;
                tracing::debug!(host = host.as_ref(), need_proxy, "cache hit (fast-path)");
                return if need_proxy {
                    Ok(ProxyStatus::NorlmalProxy)
                } else {
                    Ok(ProxyStatus::NoProxy(
                        "[NOPROXY-AUTO] we will start connect server by proxy",
                    ))
                };
            }

            // Cache miss: send to background task for geo query
            let (tx, rx) = kanal::bounded_async(1);
            sender
                .send((host.as_ref().to_string(), tx))
                .await
                .map_err(|_| ClientError::SendAutoProxy {
                    uri: get_uri(host.as_ref(), port),
                })?;
            // Bounded so a slow or throttled lookup cannot hold up the
            // connection. Giving up does not waste the query: it finishes in the
            // background and records the answer, so the next connection to this
            // host is decided immediately and accurately.
            let received = match tokio::time::timeout(AUTO_PROXY_DECISION_TIMEOUT, rx.recv()).await
            {
                Ok(result) => result.map_err(|_| ClientError::ReciveAutoProxy {
                    uri: get_uri(host.as_ref(), port),
                }),
                Err(_) => {
                    tracing::debug!(
                        host = host.as_ref(),
                        port,
                        timeout = ?AUTO_PROXY_DECISION_TIMEOUT,
                        "geo lookup did not answer in time; using the proxy for this connection"
                    );
                    // Same direction as a failed lookup: never leak a connection
                    // that should have been proxied.
                    return Ok(ProxyStatus::NorlmalProxy);
                }
            };
            match received {
                Ok(v) => {
                    if v {
                        Ok(ProxyStatus::NorlmalProxy)
                    } else {
                        Ok(ProxyStatus::NoProxy(
                            "[NOPROXY-AUTO] we will start connect server by proxy",
                        ))
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "{}:{} check ip error: {},we will use normal proxy by default",
                        host.as_ref(),
                        port,
                        error_report(&e)
                    );
                    Ok(ProxyStatus::NorlmalProxy)
                }
            }
        }
        Some(proxy_status) => Ok(proxy_status),
    }
}

#[inline]
pub async fn get_tcp_stream(host: &str, port: u16, detail: &'static str) -> Result<TcpStream> {
    proxy_core::transport::connect_tcp_host(host, port)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(format!("TcpStream({}:{})", host, port)),
            detail,
        })
}

pub async fn get_tcp_proxy_stream(
    host: &str,
    port: u16,
    proxy_server: &str,
    proxy_server_port: u16,
    msg_key: Option<Cow<'static, str>>,
    detail: &'static str,
) -> Result<TcpStream> {
    proxy_core::transport::get_tcp_proxy_stream(
        host,
        port,
        proxy_server,
        proxy_server_port,
        msg_key,
        detail,
    )
    .await
    .context(ExternalProxySnafu)
}

impl Forwarder for TcpForwardImpl {
    #[tracing::instrument(skip_all, fields(context))]
    async fn forward(self) -> Result<()> {
        let TcpForwardImpl {
            context,
            client_reader,
            client_writer,
            server_reader,
            server_writer,
        } = self;
        let ForwardContext {
            need_proxy,
            host,
            port,
            msg_key,
        } = context;

        tracing::debug!(host, port, need_proxy, ?msg_key);

        // start to forward
        match (need_proxy, msg_key) {
            (true, Some(key)) => {
                tracing::debug!(?key, info = "start with codec forward");
                client_proxy_with_cryptor_codec(
                    &host,
                    &key,
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await
                .with_context(|_| ProxySnafu {
                    uri: get_uri(host.as_str(), port),
                })
            }
            _ => {
                tracing::debug!(info = "start norlmal forward");
                proxy_with_norlmal_codec(
                    &host,
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await
                .with_context(|_| ProxySnafu {
                    uri: get_uri(host.as_str(), port),
                })
            }
        }
    }
}

pub struct ClientProxyContext {
    stream: TcpStream,
    msg_key: Option<String>,
    #[cfg(feature = "auto-proxy")]
    sender: Option<SenderChan>,
    force_proxy: bool,
    upstream_proxy: Option<ExternalProxyTarget>,
    honor_forced_direct: bool,
    enable_udp: bool,
}

#[inline]
fn get_provider<T: ProxierProviderType>(header: HeaderContext<'_>) -> Option<T::Provider> {
    let result = T::Provider::try_new(header);
    match result {
        Ok(o) => {
            tracing::debug!(protocol = T::PROXY_TYPE, "protocol matched");
            Some(o)
        }
        Err(e) => {
            tracing::debug!(protocol = T::PROXY_TYPE, "protocol mismatch: {}", e);
            None
        }
    }
}

async fn handle_proxy(
    proxy_context: ProxyContext<'_>,
    provider: impl ForwarderProvider,
) -> Result<()> {
    let proxier = provider.try_build_forwarder(proxy_context).await?;
    proxier.forward().await
}

#[tracing::instrument(skip_all, fields(msg_key))]
pub async fn handle_client(mut context: ClientProxyContext) -> Result<()> {
    // FIXME Turn header read to every structure
    let mut header_buf = [0; 1024 * 4];
    let n = context
        .stream
        .read(&mut header_buf)
        .await
        .context(IoSnafu {
            uri: None,
            detail: "Read First Header Error",
        })?;
    let header = &header_buf[..n];
    let header_context = HeaderContext {
        header,
        msg_key: context.msg_key.as_deref(),
    };
    let proxy_context = ProxyContext {
        buffer: header,
        #[cfg(feature = "auto-proxy")]
        sender: context.sender.as_ref(),
        force_proxy: context.force_proxy,
        upstream_proxy: context.upstream_proxy.as_ref(),
        honor_forced_direct: context.honor_forced_direct,
        enable_udp: context.enable_udp,
        stream: context.stream,
    };

    macro_rules! start_proxy_with_provider {
        ($header_context:expr,$proxy_context:expr,$provider_type:ty) => {
            if let Some(p) = get_provider::<$provider_type>($header_context) {
                return handle_proxy($proxy_context, p).await;
            }
        };

        ($header_context:expr,$proxy_context:expr, $($provider_type:ty),*) => {
            $(start_proxy_with_provider!($header_context, $proxy_context, $provider_type);)*
        };
    }
    // This equal to:
    // if let Some(p) = get_provider::<HttpProxierProviderType>(header_context) {
    //     return handle_proxy(proxy_context, p).await;
    // }
    // if let Some(p) = get_provider::<SocksProviderType>(header_context) {
    //     return handle_proxy(proxy_context, p).await;
    // }
    start_proxy_with_provider!(
        header_context,
        proxy_context,
        HttpProxierProviderType,
        SocksProxierProviderType
    );
    Ok(())
}

#[cfg(feature = "auto-proxy")]
const DEFAULT_CHAN_CAP: usize = 1024;

async fn client_proxy_background_task<const NEED_CODEC: bool>(context: ClientProxyContext) {
    if NEED_CODEC {
        let random_key = context
            .msg_key
            .clone()
            .expect("must be Some when it `NEED_CODEC` is true");
        if let Err(e) = handle_client(context).await {
            let report = Report::from_error(e).to_string();
            tracing::error!(random_key, proxy_with_randomkey_handle_error = report);
        }
    } else if let Err(e) = handle_client(context).await {
        let report = Report::from_error(e).to_string();
        tracing::error!(proxy_handle_error = report);
    }
}

/// Run client with a pre-bound listener and cancellation token.
///
/// This is the core client loop. Use `start_client` for production with
/// graceful shutdown, or call this directly for testing/custom setups.
pub async fn run_client_with_listener<const NEED_CODEC: bool>(
    listener: TcpListener,
    cancel_token: CancellationToken,
    tracker: Option<TaskTracker>,
    config: Option<ClientConfig>,
) {
    run_client_with_listener_runtime_config::<NEED_CODEC>(
        listener,
        cancel_token,
        tracker,
        config.map(Into::into),
    )
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
    enable_auto_proxy && !has_upstream_proxy
}

pub async fn run_client_with_listener_runtime_config<const NEED_CODEC: bool>(
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
                let task = client_proxy_background_task::<NEED_CODEC>(ClientProxyContext {
                    stream,
                    msg_key: if NEED_CODEC { Some(gen_random_key()) } else { None },
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
pub async fn start_client_with_config<const NEED_CODEC: bool>(
    host: impl AsRef<str> + Debug,
    port: u16,
    config: Option<ClientConfig>,
) -> Result<()> {
    start_client_with_runtime_config::<NEED_CODEC>(host, port, config.map(Into::into)).await
}

#[tracing::instrument]
pub async fn start_client_with_runtime_config<const NEED_CODEC: bool>(
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

    run_client_with_listener_runtime_config::<NEED_CODEC>(
        listener,
        cancel_token,
        Some(tracker),
        config,
    )
    .await;

    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
    Ok(())
}

#[tracing::instrument]
pub async fn start_client<const NEED_CODEC: bool>(
    host: impl AsRef<str> + Debug,
    port: u16,
) -> Result<()> {
    start_client_with_config::<NEED_CODEC>(host, port, None).await
}

#[cfg(test)]
mod tests {
    use proxy_core::relay::ExternalProxyTarget;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// A geo lookup must not hold up the connection. When the background task is
    /// slow, the decision falls back to the proxy rather than waiting.
    #[tokio::test]
    async fn a_slow_geo_lookup_does_not_block_the_connection() {
        let host = format!("slow-{}.example", std::process::id());
        let (sender, receiver) = kanal::bounded_async::<auto_proxy::SendItem>(1);

        // A responder that answers far too late to be useful.
        let stub = tokio::spawn(async move {
            let (_host, notifier) = receiver.recv().await.unwrap();
            tokio::time::sleep(AUTO_PROXY_DECISION_TIMEOUT * 4).await;
            // The waiter is gone by now; the send failing is the expected path.
            let _ = notifier.send(false).await;
        });

        let started = std::time::Instant::now();
        let status = need_proxy(&host, 443, &sender).await.unwrap();
        let waited = started.elapsed();

        assert!(
            matches!(status, ProxyStatus::NorlmalProxy),
            "an undecided host must use the proxy, never a direct connection"
        );
        assert!(
            waited < AUTO_PROXY_DECISION_TIMEOUT * 2,
            "waited {waited:?}, which means the deadline did not apply"
        );
        stub.await.unwrap();
    }

    /// A lookup that answers promptly keeps its accurate decision, so the deadline
    /// does not cost correctness in the common case.
    #[tokio::test]
    async fn a_prompt_geo_lookup_still_decides_the_connection() {
        let host = format!("prompt-{}.example", std::process::id());
        let (sender, receiver) = kanal::bounded_async::<auto_proxy::SendItem>(1);

        let stub = tokio::spawn(async move {
            let (_host, notifier) = receiver.recv().await.unwrap();
            // `false` = no proxy needed, i.e. a CN host in normal mode.
            notifier.send(false).await.unwrap();
        });

        let status = need_proxy(&host, 443, &sender).await.unwrap();
        assert!(
            matches!(status, ProxyStatus::NoProxy(_)),
            "a resolved direct decision must be honoured"
        );
        stub.await.unwrap();
    }

    /// TUN must no longer be a reason to disable auto-proxy, and the user's own
    /// setting must remain the switch.
    #[test]
    fn auto_proxy_follows_the_user_setting_not_tun() {
        assert!(auto_proxy_applies(true, false));
        assert!(!auto_proxy_applies(false, false));
        // An upstream proxy leaves no direct decision to make.
        assert!(!auto_proxy_applies(true, true));
        assert!(!auto_proxy_applies(false, true));
    }

    async fn start_client_for_test(
        upstream_proxy: ExternalProxyTarget,
    ) -> (String, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let token = CancellationToken::new();
        tokio::spawn(run_client_with_listener_runtime_config::<false>(
            listener,
            token.clone(),
            None,
            Some(ClientRuntimeConfig {
                client: ClientConfig {
                    enable_auto_proxy: false,
                    enable_udp: true,
                    cache_dir: None,
                },
                upstream_proxy: Some(upstream_proxy),
                tun: None,
                force_proxy: None,
            }),
        ));
        (addr, token)
    }

    async fn start_echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
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
        addr
    }

    async fn start_auth_http_connect_proxy(expected_auth: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = inbound.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
            let connect_target = request
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("CONNECT "))
                .and_then(|line| line.split_whitespace().next())
                .unwrap();
            let (host, port) = connect_target.rsplit_once(':').unwrap();
            let mut outbound = TcpStream::connect((host, port.parse::<u16>().unwrap()))
                .await
                .unwrap();
            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        addr
    }

    async fn start_plain_http_proxy(expected_auth: String) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = inbound.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
            let _ = tx.send(request);
            inbound
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
        });
        (addr, rx)
    }

    async fn start_auth_socks5_proxy(username: &'static str, password: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            assert_eq!(inbound.read_u8().await.unwrap(), 0x05);
            let methods_len = inbound.read_u8().await.unwrap() as usize;
            let mut methods = vec![0u8; methods_len];
            inbound.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0x02));
            inbound.write_all(&[0x05, 0x02]).await.unwrap();

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
                other => panic!("unexpected ATYP: {other:#x}"),
            };
            let port = inbound.read_u16().await.unwrap();
            let mut outbound = TcpStream::connect((host.as_str(), port)).await.unwrap();
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        addr
    }

    async fn read_until_headers_end(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut response = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            response.extend_from_slice(&buf[..n]);
            if let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let body_start = headers_end + 4;
                return (
                    String::from_utf8_lossy(&response[..body_start]).into_owned(),
                    response[body_start..].to_vec(),
                );
            }
        }
    }

    #[tokio::test]
    async fn local_socks5_forwards_through_authenticated_socks5_upstream() {
        let target_addr = start_echo_server().await;
        let (_, target_port) = target_addr.rsplit_once(':').unwrap();
        let target_port = target_port.parse::<u16>().unwrap();
        let upstream_addr = start_auth_socks5_proxy("user", "secret").await;
        let upstream_proxy =
            ExternalProxyTarget::parse(&format!("socks5://user:secret@{upstream_addr}")).unwrap();
        let (client_addr, token) = start_client_for_test(upstream_proxy).await;

        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut handshake = [0u8; 2];
        stream.read_exact(&mut handshake).await.unwrap();
        assert_eq!(handshake, [0x05, 0x00]);
        stream
            .write_all(&[
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (target_port >> 8) as u8,
                target_port as u8,
            ])
            .await
            .unwrap();
        let mut response = [0u8; 10];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0..2], [0x05, 0x00]);

        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        token.cancel();
    }

    #[tokio::test]
    async fn local_http_connect_forwards_through_authenticated_http_upstream() {
        let target_addr = start_echo_server().await;
        let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
        let upstream_addr = start_auth_http_connect_proxy(expected_auth).await;
        let upstream_proxy =
            ExternalProxyTarget::parse(&format!("http://user:secret@{upstream_addr}")).unwrap();
        let (client_addr, token) = start_client_for_test(upstream_proxy).await;

        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream
            .write_all(
                format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let (response, _) = read_until_headers_end(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));

        stream.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        token.cancel();
    }

    #[tokio::test]
    async fn local_plain_http_replaces_proxy_authorization_for_http_upstream() {
        let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
        let (upstream_addr, request_rx) = start_plain_http_proxy(expected_auth.clone()).await;
        let upstream_proxy =
            ExternalProxyTarget::parse(&format!("http://user:secret@{upstream_addr}")).unwrap();
        let (client_addr, token) = start_client_for_test(upstream_proxy).await;

        let mut stream = TcpStream::connect(client_addr).await.unwrap();
        stream
            .write_all(
                b"GET http://example.test/path HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic d3Jvbmc=\r\n\r\n",
            )
            .await
            .unwrap();
        let (response, mut body) = read_until_headers_end(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        while body.len() < 2 {
            let mut buf = [0u8; 2];
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            body.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&body[..2], b"OK");

        let request = request_rx.await.unwrap();
        assert!(request.contains(&format!("Proxy-Authorization: Basic {expected_auth}\r\n")));
        assert!(!request.contains("Proxy-Authorization: Basic d3Jvbmc="));
        token.cancel();
    }
}
