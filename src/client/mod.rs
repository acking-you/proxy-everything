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
//! - **SOCKS5**: Full SOCKS5 protocol with IPv4/IPv6/domain support
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
pub mod socks;

use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::path::PathBuf;

#[cfg(feature = "auto-proxy")]
use auto_proxy::{SenderChan, run_auto_proxy_by_country};
use snafu::{OptionExt, Report, ResultExt, Snafu};
use tokio::io::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use self::http::{HttpProxierProvider, HttpProxyError};
use self::socks::{SocksError, SocksProxierProvider};
use crate::codec::{AsyncReader, AsyncReaderWriterRef, AsyncWriter};
use crate::config::{gen_random_key, runtime};
use crate::util::{GracefulShutdownManager, GracefulShutdownManagerImpl};
use crate::{
    Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader, client_proxy_with_cryptor_codec,
    proxy_with_norlmal_codec, set_data_size,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

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
        source: crate::ProxyError,
    },
    #[snafu(display("URI(`{uri}`) Proxy error happen"))]
    Proxy {
        uri: String,
        source: crate::ProxyError,
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
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub enable_auto_proxy: bool,
    pub cache_dir: Option<PathBuf>,
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
) -> Result<ServerConnection> {
    use crate::config::runtime;

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
                        runtime::server_port(),
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
    let server_host = runtime::server_host();
    let msg_key = change_msg_key(server_host.as_str(), msg_key);
    Ok(ServerConnection {
        stream: get_tcp_proxy_stream(
            host,
            port,
            &server_host,
            runtime::server_port(),
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

/// we will not proxy if option is some
#[cfg(feature = "auto-proxy")]
pub async fn need_proxy(
    host: impl AsRef<str>,
    port: u16,
    sender: &SenderChan,
) -> Result<ProxyStatus> {
    use crate::config::runtime;

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
            match rx.recv().await.map_err(|_| ClientError::ReciveAutoProxy {
                uri: get_uri(host.as_ref(), port),
            }) {
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
                        "{}:{} check ip error:{},we will use normal proxy by default",
                        host.as_ref(),
                        port,
                        e
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
    // The input might be an IP address represented as a string, in which case DNS resolution is not
    // required
    let ipaddr = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Domain name, need DNS resolution
            uni_stream::addr::get_ip_addrs(host)
                .await
                .context(IoSnafu {
                    uri: Some(host.into()),
                    detail,
                })?
                .into_iter()
                .next()
                .context(EmptyDNSRecordSnafu)?
        }
    };

    TcpStream::connect((ipaddr, port))
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
    // 1. get proxy server stream
    let mut proxy_server_stream = get_tcp_stream(proxy_server, proxy_server_port, detail).await?;

    // 2. prepare proxy header
    let proxy_header = ProxyHeader {
        host: host.into(),
        port,
        key: msg_key,
    };
    let mut header_json =
        serde_json::to_string(&proxy_header).with_context(|_| SerdeJsonSnafu {
            uri: get_uri(host, port),
        })?;
    let mut cryption =
        Aes256GcmCryption::try_new_with_default_key().map_err(|e| ClientError::Encryption {
            uri: get_uri(host, port),
            detail: e.to_string(),
        })?;

    // SAFETY: We use `as_bytes_mut()` to encrypt the JSON string in-place.
    // After encryption, the bytes are no longer valid UTF-8, but we only use
    // `addr` as a byte slice for network transmission (write_all), never as
    // a String again. The String is dropped after this scope.
    let (addr, tag, len) = unsafe {
        let addr = header_json.as_bytes_mut();
        let tag = cryption
            .encrypt(addr)
            .map_err(|e| ClientError::Encryption {
                uri: get_uri(host, port),
                detail: e.to_string(),
            })?;
        let len = addr.len() + tag.as_ref().len();
        (addr, tag, len as u32)
    };

    let mut proxy_server_stream_ref = AsyncReaderWriterRef::new(&mut proxy_server_stream);

    // 3. send proxy header
    set_data_size(&mut proxy_server_stream_ref, len)
        .await
        .with_context(|_| SendHeaderSnafu {
            uri: get_uri(host, port),
        })?;
    proxy_server_stream_ref
        .write_all(addr)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(get_uri(host, port)),
            detail: "Send Header(host,ip)",
        })?;
    proxy_server_stream_ref
        .write_all(tag.as_ref())
        .await
        .with_context(|_| IoSnafu {
            uri: Some(get_uri(host, port)),
            detail: "Send Header(tag)",
        })?;
    Ok(proxy_server_stream)
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

        tracing::info!(host, port, need_proxy, ?msg_key);

        // start to forward
        match (need_proxy, msg_key) {
            (true, Some(key)) => {
                tracing::info!(?key, info = "start with codec forward");
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
                tracing::info!(info = "start norlmal forward");
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
}

#[inline]
fn get_provider<T: ProxierProviderType>(header: HeaderContext<'_>) -> Option<T::Provider> {
    let result = T::Provider::try_new(header);
    match result {
        Ok(o) => {
            tracing::info!(protocol = T::PROXY_TYPE, "protocol matched");
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
    let enable_auto_proxy = config.as_ref().map(|c| c.enable_auto_proxy).unwrap_or(true);
    let cache_dir = config.as_ref().and_then(|c| c.cache_dir.clone());

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
                let sender = sender.clone();
                let task = client_proxy_background_task::<NEED_CODEC>(ClientProxyContext {
                    stream,
                    msg_key: if NEED_CODEC { Some(gen_random_key()) } else { None },
                    #[cfg(feature = "auto-proxy")]
                    sender,
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

#[tracing::instrument]
pub async fn start_client<const NEED_CODEC: bool>(
    host: impl AsRef<str> + Debug,
    port: u16,
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

    run_client_with_listener::<NEED_CODEC>(listener, cancel_token, Some(tracker), None).await;

    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
    Ok(())
}
