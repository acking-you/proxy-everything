#[cfg(feature = "auto-proxy")]
pub mod auto_proxy;
pub mod http;
pub mod socks;
use crate::codec::{AsyncReader, AsyncWriter};
use crate::util::{
    GracefulShutdownManager, GracefulShutdownManagerImpl, ProxyTaskId, TaskIdGenerator,
};
use crate::{
    client_proxy_with_cryptor_codec, gen_random_key, proxy_with_norlmal_codec, set_data_size,
    Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader,
};
use async_trait::async_trait;
#[cfg(feature = "auto-proxy")]
use auto_proxy::{run_auto_proxy_by_country, SendItem, SenderChan};

#[cfg(feature = "monoio")]
use monoio::io::Splitable;
use once_cell::sync::Lazy;
use snafu::{Report, ResultExt, Snafu};
use std::fmt::{Debug, Display};
use std::str::FromStr;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(feature = "monoio")]
use monoio::net::TcpStream;

use self::http::{HttpProxierProvider, HttpProxyError};
use self::socks::{SocksError, SocksProxierProvider};

#[derive(Debug, Snafu)]
pub enum ClientError {
    #[snafu(display("URI(`{uri}`) Parse host from http request fails"))]
    Host { uri: String },
    #[snafu(display("URI(`{uri}`) Parse port from http request fails"))]
    Port { uri: String },
    #[snafu(display("URI(`{uri}`) Parse port from string fails"))]
    StrPort {
        uri: String,
        source: <u16 as FromStr>::Err,
    },
    #[snafu(display("URI(`{uri}`) Parse method from http request fails"))]
    Method { uri: String },
    #[snafu(display("Parse uri from http request fails"))]
    Uri,
    #[snafu(display("URI(`{uri}`) Parse http version from request fails"))]
    Version { uri: String },
    #[snafu(display("URI(`{uri}`) Not supported method:{method}"))]
    NotSupported { uri: String, method: String },
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

#[cfg(feature = "auto-proxy")]
pub static NONPROXY_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    let mut default_keywords = vec![
        "bilibili".to_string(),
        "bili".to_string(),
        "xigua".to_string(),
        "byte".to_string(),
        "douyin".to_string(),
        "cnblogs".to_string(),
        "qq.com".to_string(),
        "jd.com".to_string(),
        "meituan".to_string(),
        "jianguoyun".to_string(),
        "taobao.com".to_string(),
        "csdn".to_string(),
        "juejin".to_string(),
        "baidu".to_string(),
        "zhihu".to_string(),
        "bytedance".to_string(),
        "ximalaya".to_string(),
        "cn".to_string(),
    ];
    match std::env::var("NONPROXY_KEYWORDS") {
        Ok(k) => {
            let mut keywords = k.trim().split(',').map(|s| s.to_string());
            let is_insert_default = if let Some(keyword) = keywords.next() {
                keyword == "%DEFAULT%"
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
pub static PROXY_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    let mut default_keywords = vec![
        "tiktok".to_string(),
        "youtube".to_string(),
        "google".to_string(),
        "chatgpt".to_string(),
        "twitter".to_string(),
        "facebook".to_string(),
        "github".to_string(),
        "docker".to_string(),
    ];
    match std::env::var("PROXY_KEYWORDS") {
        Ok(k) => {
            let mut keywords = k.trim().split(',').map(|s| s.to_string());
            let insert_default = if let Some(keyword) = keywords.next() {
                keyword == "%DEFAULT%"
            } else {
                false
            };
            let mut keywords = keywords.collect::<Vec<_>>();
            if insert_default {
                keywords.append(&mut default_keywords);
            }
            tracing::info!("`PROXY_KEYWORDS` is `{keywords:?}`");
            keywords
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`PROXY_KEYWORDS` provided,we use default keywords:{default_keywords:?}"
            );
            default_keywords
        }
    }
});

pub type Result<T> = std::result::Result<T, ClientError>;

pub static SERVER_HOST: Lazy<String> = Lazy::new(|| match std::env::var("SERVER_HOST") {
    Ok(s) => s,
    Err(_) => {
        tracing::error!("You are not set `ENV:SERVER_HOST`. we will use `localhost` as default!");
        "127.0.0.1".to_string()
    }
});

#[async_trait]
pub trait Proxier {
    async fn proxy(self) -> Result<()>;
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
    stream: TcpStream,
}

#[async_trait]
pub trait ProxierProvider {
    type Item: Proxier;

    fn try_new_from_header_context(header_context: HeaderContext<'_>) -> Result<Self>
    where
        Self: std::marker::Sized;

    async fn try_build_from_proxy_context(
        self,
        proxy_context: ProxyContext<'_>,
    ) -> Result<Self::Item>;
}

pub trait ProxierProviderType {
    type Provider: ProxierProvider;
    const PROXY_TYPE: &'static str;
}

macro_rules! make_provider_type {
    ($name:ident,$proxy_type:expr,$provider_name:ty) => {
        pub struct $name {}

        impl ProxierProviderType for $name {
            type Provider = $provider_name;
            const PROXY_TYPE: &'static str = $proxy_type;
        }
    };
}

make_provider_type!(HttpProxierProviderType, "HTTP/HTTPS", HttpProxierProvider);
make_provider_type!(SocksProxierProviderType, "SOCKS5", SocksProxierProvider);

pub const SERVER_PORT: u16 = 1081;
pub const CLIENT_PORT: u16 = 1080;

pub type TcpAsyncReader<T = OwnedReadHalf> = AsyncReader<T>;
pub type TcpAsyncWriter<T = OwnedWriteHalf> = AsyncWriter<T>;

#[derive(Debug)]
pub struct ForwardContext {
    host: String,
    port: u16,
    need_proxy: bool,
    msg_key: Option<String>,
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

pub struct ProxierImpl {
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

/// we will not proxy if option is some
#[cfg(feature = "auto-proxy")]
pub async fn need_proxy(
    host: impl AsRef<str>,
    port: u16,
    sender: &SenderChan,
) -> Result<Option<&'static str>> {
    if host.as_ref() == "127.0.0.1" {
        LocalHostSnafu { port }.fail()?;
    }
    // prehandle when host contain `NONPROXY_KEYWORS` or `PROXY_KEYWORDS`
    let has_nonproxy_list = NONPROXY_KEYWORDS.iter().any(|v| host.as_ref().contains(v));
    let has_proxy_list = PROXY_KEYWORDS.iter().any(|v| host.as_ref().contains(v));
    if has_nonproxy_list && !has_proxy_list {
        return Ok(Some(
            "[NOPROXY-RULES] we will start connect server directly",
        ));
    }
    if !has_proxy_list {
        // start check by ip-api.com
        let (tx, rx) = flume::bounded(1);
        sender
            .send_async((host.as_ref().to_string(), tx))
            .await
            .with_context(|_| SendAutoProxySnafu {
                uri: get_uri(host.as_ref(), port),
            })?;
        let need_proxy = match rx
            .recv_async()
            .await
            .with_context(|_| ReciveAutoProxySnafu {
                uri: get_uri(host.as_ref(), port),
            }) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(received_auto_proxy_error=?e);
                true
            }
        };
        if !need_proxy {
            return Ok(Some("[NOPROXY-AUTO] we will start connect server by proxy"));
        }
    }
    Ok(None)
}

#[async_trait]
impl Proxier for ProxierImpl {
    #[tracing::instrument(skip_all, fields(context))]
    async fn proxy(self) -> Result<()> {
        let ProxierImpl {
            context,
            client_reader,
            client_writer,
            server_reader,
            mut server_writer,
        } = self;
        let ForwardContext {
            need_proxy,
            host,
            port,
            msg_key,
        } = context;

        // Start no proxy
        if !need_proxy {
            tracing::info!(host, port, "start no proxy");
            return proxy_with_norlmal_codec(
                &host,
                client_reader,
                server_reader,
                client_writer,
                server_writer,
            )
            .await
            .with_context(|_| ProxySnafu {
                uri: get_uri(host.as_str(), port),
            });
        }

        // Start to proxy
        let proxy_header = ProxyHeader {
            host: host.clone(),
            port,
            key: msg_key,
        };
        tracing::info!(host, port, info = "start proxy",);
        let mut header_json =
            serde_json::to_string(&proxy_header).with_context(|_| SerdeJsonSnafu {
                uri: get_uri(host.as_str(), port),
            })?;
        let mut cryption =
            Aes256GcmCryption::try_new_with_default_key().map_err(|e| ClientError::Encryption {
                uri: get_uri(host.as_str(), port),
                detail: e.to_string(),
            })?;

        let (addr, tag, len) = unsafe {
            let addr = header_json.as_bytes_mut();
            let tag = cryption
                .encrypt(addr)
                .map_err(|e| ClientError::Encryption {
                    uri: get_uri(host.as_str(), port),
                    detail: e.to_string(),
                })?;
            let len = addr.len() + tag.as_ref().len();
            (addr, tag, len as u32)
        };

        // send msg header
        set_data_size(&mut server_writer, len)
            .await
            .with_context(|_| SendHeaderSnafu {
                uri: get_uri(host.as_str(), port),
            })?;
        server_writer
            .write_all(addr)
            .await
            .with_context(|_| IoSnafu {
                uri: Some(get_uri(host.as_str(), port)),
                detail: "Send Header(host,ip)",
            })?;
        server_writer
            .write_all(tag.as_ref())
            .await
            .with_context(|_| IoSnafu {
                uri: Some(get_uri(host.as_str(), port)),
                detail: "Send Header(tag)",
            })?;

        // start to forward
        if let Some(key) = proxy_header.key.as_ref() {
            tracing::info!(key, info = "start with codec forward");
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
    provider: impl ProxierProvider,
) -> Result<()> {
    let proxier = provider.try_build_from_proxy_context(proxy_context).await?;
    proxier.proxy().await
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
