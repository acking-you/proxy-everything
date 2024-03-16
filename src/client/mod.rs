#[cfg(feature = "auto-proxy")]
pub mod auto_proxy;
pub mod http;
pub mod socks;
use std::borrow::Cow;
use std::fmt::{Debug, Display};

#[cfg(feature = "auto-proxy")]
use auto_proxy::{run_auto_proxy_by_country, SendItem, SenderChan};
#[cfg(feature = "monoio")]
use monoio::io::Splitable;
#[cfg(feature = "monoio")]
use monoio::net::TcpStream;
use once_cell::sync::Lazy;
use snafu::{Report, ResultExt, Snafu};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

use self::http::{HttpProxierProvider, HttpProxyError};
use self::socks::{SocksError, SocksProxierProvider};
use crate::codec::{AsyncReader, AsyncReaderWriterRef, AsyncWriter};
use crate::util::{
    GracefulShutdownManager, GracefulShutdownManagerImpl, ProxyTaskId, TaskIdGenerator,
};
use crate::{
    client_proxy_with_cryptor_codec, gen_random_key, proxy_with_norlmal_codec, set_data_size,
    Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader,
};

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
    SendHeader { uri: String, source: crate::Error },
    #[snafu(display("URI(`{uri}`) Proxy error happen"))]
    Proxy { uri: String, source: crate::Error },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("URI(`{uri}`) Send item for auto proxy error"))]
    SendAutoProxy {
        uri: String,
        source: flume::SendError<SendItem>,
    },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("URI(`{uri}`) Recv item form auto proxy error"))]
    ReciveAutoProxy {
        uri: String,
        source: flume::RecvError,
    },
    #[cfg(feature = "auto-proxy")]
    #[snafu(display("Can't proxy localhost!!! Host(`127.0.0.1:{port}`)"))]
    LocalHost { port: u16 },
    #[snafu(display("Http proxy error"))]
    HttpProxy { source: HttpProxyError },
    #[snafu(display("Socks proxy error"))]
    SocksProxy { source: SocksError },
}

#[derive(Debug)]
pub struct ParsedProxyKeyWord {
    pub name_server: String,
    pub proxy_server: Option<String>,
}

fn parse_keywords(keywords: Vec<String>) -> Vec<ParsedProxyKeyWord> {
    keywords
        .into_iter()
        .map(|v| match v.find(':') {
            Some(i) => ParsedProxyKeyWord {
                name_server: v[..i].trim().to_string(),
                proxy_server: Some(v[i + 1..].trim().to_string()),
            },
            None => ParsedProxyKeyWord {
                name_server: v,
                proxy_server: None,
            },
        })
        .collect()
}

const DEFAULT_WORD: &str = "%DEFAULT%";

#[cfg(feature = "auto-proxy")]
pub static NONPROXY_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    let mut default_keywords = vec![
        "chaoxing".to_string(),
        "bilibili".to_string(),
        "bili".to_string(),
        "xigua".to_string(),
        "byte".to_string(),
        "douyin".to_string(),
        "cnblogs".to_string(),
        "qq.com".to_string(),
        "jd.com".to_string(),
        "retiehe".to_string(),
        "meituan".to_string(),
        "jianguoyun".to_string(),
        "taobao.com".to_string(),
        "csdn".to_string(),
        "juejin".to_string(),
        "baidu".to_string(),
        "zhihu".to_string(),
        "ximalaya".to_string(),
        "cn".to_string(),
    ];
    match std::env::var("NONPROXY_KEYWORDS") {
        Ok(k) => {
            let mut keywords = k.trim().split(',').map(|s| s.to_string());
            let is_insert_default = if let Some(keyword) = keywords.next() {
                keyword == DEFAULT_WORD
            } else {
                false
            };
            let mut keywords = keywords.collect::<Vec<_>>();
            if is_insert_default {
                keywords.append(&mut default_keywords);
            }
            tracing::info!("`NONPROXY_KEYWORDS` is `{keywords:?}`");
            keywords
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`NONPROXY_KEYWORDS` provided,we use default keywords:{default_keywords:?}"
            );
            default_keywords
        }
    }
});

#[cfg(feature = "auto-proxy")]
pub static PROXY_KEYWORDS: Lazy<Vec<ParsedProxyKeyWord>> = Lazy::new(|| {
    let mut default_keywords = vec![
        "tiktok".to_string(),
        "youtube".to_string(),
        "scholar.google:64.23.159.180".to_string(),
        // for reddit
        "reddit:64.23.159.180".to_string(),
        "google".to_string(),
        "chatgpt".to_string(),
        "twitter".to_string(),
        "facebook".to_string(),
        "bilibili.tv".to_string(),
        "github".to_string(),
        "docker".to_string(),
    ];
    match std::env::var("PROXY_KEYWORDS") {
        Ok(k) => {
            let mut keywords = k.trim().split(',').map(|s| s.to_string());
            let insert_default = if let Some(keyword) = keywords.next() {
                keyword == DEFAULT_WORD
            } else {
                false
            };
            let mut keywords = keywords.collect::<Vec<_>>();
            if insert_default {
                keywords.append(&mut default_keywords);
            }
            tracing::info!("`PROXY_KEYWORDS` is `{keywords:?}`");
            parse_keywords(keywords)
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`PROXY_KEYWORDS` provided,we use default keywords:{default_keywords:?}"
            );
            parse_keywords(default_keywords)
        }
    }
});

pub static NEED_CODEC_IP: Lazy<Vec<String>> = Lazy::new(|| {
    let mut default_codec_ip = vec![
        // US node
        "64.23.159.180".to_string(),
    ];
    match std::env::var("NEED_CODEC_IP") {
        Ok(v) => {
            let mut codec_ip = v.trim().split(',').map(|s| s.to_string());
            let need_default = if let Some(key) = codec_ip.next() {
                key == DEFAULT_WORD
            } else {
                false
            };
            let mut res = codec_ip.collect::<Vec<_>>();
            if need_default {
                res.append(&mut default_codec_ip);
            }
            tracing::info!("`NEED_CODEC_IP` is `{res:?}`");
            res
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`NEED_CODEC_IP` provided,we use default need codec ip:{default_codec_ip:?}"
            );
            default_codec_ip
        }
    }
});

#[inline]
pub fn get_msg_key_from_codec_ip(ip: impl AsRef<str>) -> Option<String> {
    NEED_CODEC_IP
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
    sender: &'a SenderChan,
    /// TODO: let this stream abstract
    stream: TcpStream,
}

pub trait ForwarderProvider {
    type Item: Forwarder;

    fn try_new_from_header_context(header_context: HeaderContext<'_>) -> Result<Self>
    where
        Self: std::marker::Sized;

    fn try_build_from_proxy_context(
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
    if host.as_ref() == "127.0.0.1" {
        LocalHostSnafu { port }.fail()?;
    }
    // prehandle when host contain `NONPROXY_KEYWORS` or `PROXY_KEYWORDS`
    let has_nonproxy_list = NONPROXY_KEYWORDS.iter().any(|v| host.as_ref().contains(v));
    let has_proxy_status = PROXY_KEYWORDS
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
            // start check by ip-api.com
            let (tx, rx) = flume::bounded(1);
            sender
                .send_async((host.as_ref().to_string(), tx))
                .await
                .with_context(|_| SendAutoProxySnafu {
                    uri: get_uri(host.as_ref(), port),
                })?;
            match rx
                .recv_async()
                .await
                .with_context(|_| ReciveAutoProxySnafu {
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
    TcpStream::connect((host, port))
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
        if need_proxy && msg_key.is_some() {
            let key = msg_key.as_ref().expect(
                "the `msg_key` has been checked earlier with `is_some`, getting it will never fail",
            );
            tracing::info!(?key, info = "start with codec forward");
            client_proxy_with_cryptor_codec(
                &host,
                key,
                client_reader,
                server_reader,
                client_writer,
                server_writer,
            )
            .await
            .with_context(|_| ProxySnafu {
                uri: get_uri(host.as_str(), port),
            })
        } else {
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

pub struct ClientProxyContext {
    stream: TcpStream,
    msg_key: Option<String>,
    #[cfg(feature = "auto-proxy")]
    sender: SenderChan,
}

#[inline]
fn get_provider<T: ProxierProviderType>(header: HeaderContext<'_>) -> Option<T::Provider> {
    let result = T::Provider::try_new_from_header_context(header);
    match result {
        Ok(o) => Some(o),
        Err(e) => {
            tracing::warn!(fails = T::PROXY_TYPE,get_proxy_provider_error = ?Report::from_error(e));
            None
        }
    }
}

async fn handle_proxy(
    proxy_context: ProxyContext<'_>,
    provider: impl ForwarderProvider,
) -> Result<()> {
    let proxier = provider.try_build_from_proxy_context(proxy_context).await?;
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
        sender: &context.sender,
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

#[tracing::instrument]
pub async fn start_client<const NEED_CODEC: bool>(host: impl AsRef<str> + Debug, port: u16) {
    let listener = TcpListener::bind((host.as_ref(), port)).await.unwrap();
    let mut manager = GracefulShutdownManagerImpl::new();
    let mut proxy_id = ProxyTaskId::new();
    // Register SIGINT & SIGTERM & SIGQUIT
    if !manager.spawn_graceful_signals() {
        return;
    }
    #[cfg(feature = "auto-proxy")]
    let sender = {
        let (tx, rx) = flume::bounded(DEFAULT_CHAN_CAP);
        manager.spawn(proxy_id.gen(), async move {
            run_auto_proxy_by_country(rx).await
        });
        tx
    };

    while !manager.is_cancelled() {
        let (stream, _) = listener.accept().await.unwrap();
        #[cfg(feature = "auto-proxy")]
        let sender = sender.clone();
        let background_task = client_proxy_background_task::<NEED_CODEC>(ClientProxyContext {
            stream,
            msg_key: if NEED_CODEC {
                Some(gen_random_key())
            } else {
                None
            },
            #[cfg(feature = "auto-proxy")]
            sender,
        });
        manager.spawn(proxy_id.gen(), background_task);
    }
    manager.wait().await;
}
