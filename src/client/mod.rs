#[cfg(feature = "auto-proxy")]
pub mod auto_proxy;
use crate::codec::{AsyncReader, AsyncWriter};
use crate::util::{
    GracefulShutdownManager, GracefulShutdownManagerImpl, ProxyTaskId, TaskIdGenerator,
};
use crate::{
    client_proxy_with_cryptor_codec, gen_random_key, proxy_with_norlmal_codec, set_data_size,
    Aes256GcmCryption, MyAsyncReadExt, MyAsyncWriteExt, ProxyHeader,
};
#[cfg(feature = "auto-proxy")]
use auto_proxy::{run_auto_proxy_by_country, SendItem, SenderChan};

#[cfg(feature = "monoio")]
use monoio::io::Splitable;
use once_cell::sync::Lazy;
use snafu::{OptionExt, Report, ResultExt, Snafu};
use std::fmt::Debug;
use std::str::FromStr;
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(feature = "monoio")]
use monoio::net::TcpStream;

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

type Result<T> = std::result::Result<T, ClientError>;

pub static SERVER_HOST: Lazy<String> = Lazy::new(|| match std::env::var("SERVER_HOST") {
    Ok(s) => s,
    Err(_) => {
        tracing::error!("You are not set `ENV:SERVER_HOST`. we will use `localhost` as default!");
        "127.0.0.1".to_string()
    }
});

pub const SERVER_PORT: u16 = 1081;
pub const CLIENT_PORT: u16 = 1080;

pub struct ClientProxyContext {
    msg_key: Option<String>,
    #[cfg(feature = "auto-proxy")]
    sender: SenderChan,
}

#[tracing::instrument(skip_all, fields(msg_key))]
pub async fn handle_client(client_socket: TcpStream, context: ClientProxyContext) -> Result<()> {
    let (r, w) = client_socket.into_split();
    let (mut client_reader, mut client_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let mut buffer = [0; 4096];
    client_reader.read(&mut buffer).await.context(IoSnafu {
        uri: None,
        detail: "Read Http Header",
    })?;

    // Parse http `CONNECT` request
    let request = String::from_utf8_lossy(&buffer[..]);
    let mut lines = request.lines();
    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        let method = parts.next().context(MethodSnafu {
            uri: first_line.to_string(),
        })?;
        let uri = parts.next().context(UriSnafu)?;
        let _version = parts.next().context(VersionSnafu { uri })?;
        let method = method.to_ascii_lowercase();
        if method != "connect" {
            NotSupportedSnafu { uri, method }.fail()?
        }

        let mut parts = uri.split(':');
        let host = parts.next().context(HostSnafu { uri })?;
        let port: u16 = parts
            .next()
            .context(PortSnafu { uri })?
            .parse()
            .context(StrPortSnafu { uri })?;

        // response to 200
        client_writer
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .await
            .with_context(|_| IoSnafu {
                uri: Some(uri.to_string()),
                detail: "Write Http Connection Ok",
            })?;

        // check auto proxy to prevent proxy to remote server
        #[cfg(feature = "auto-proxy")]
        {
            async fn handle_no_proxy(
                host: &str,
                port: u16,
                client_reader: AsyncReader<tokio::net::tcp::OwnedReadHalf>,
                client_writer: AsyncWriter<tokio::net::tcp::OwnedWriteHalf>,
            ) -> Result<()> {
                tracing::info!(host, port, info = "start no proxy");
                let stream = TcpStream::connect((host, port))
                    .await
                    .with_context(|_| IoSnafu {
                        uri: Some(format!("{host}:{port}")),
                        detail: "error in start connect to no proxy",
                    })?;
                let (server_reader, server_writer) = stream.into_split();
                proxy_with_norlmal_codec(
                    host,
                    client_reader,
                    AsyncReader::new(server_reader),
                    client_writer,
                    AsyncWriter::new(server_writer),
                )
                .await
                .with_context(|_| ProxySnafu {
                    uri: format!("{host}:{port}"),
                })
            }
            if host == "127.0.0.1" {
                LocalHostSnafu { port }.fail()?;
            }
            // prehandle when host contain `NONPROXY_KEYWORS` or `PROXY_KEYWORDS`
            let has_nonproxy_list = NONPROXY_KEYWORDS.iter().any(|v| host.contains(v));
            let has_proxy_list = PROXY_KEYWORDS.iter().any(|v| host.contains(v));
            if has_nonproxy_list && !has_proxy_list {
                return handle_no_proxy(host, port, client_reader, client_writer).await;
            }
            if !has_proxy_list {
                // start check by ip-api.com
                let sender = &context.sender;

                let (tx, rx) = flume::bounded(1);
                sender
                    .send_async((host.to_string(), tx))
                    .await
                    .with_context(|_| SendAutoProxySnafu { uri })?;
                let need_proxy = match rx
                    .recv_async()
                    .await
                    .with_context(|_| ReciveAutoProxySnafu { uri })
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(received_auto_proxy_error=?e);
                        true
                    }
                };
                // No need to proxy
                if !need_proxy {
                    return handle_no_proxy(host, port, client_reader, client_writer).await;
                }
            }
        }
        // Start to proxy
        let proxy_header = ProxyHeader {
            host: host.into(),
            port,
            key: context.msg_key.clone(),
        };
        tracing::info!(host, port, info = "start proxy",);
        let mut header_json =
            serde_json::to_string(&proxy_header).with_context(|_| SerdeJsonSnafu { uri })?;
        let mut cryption =
            Aes256GcmCryption::try_new_with_default_key().map_err(|e| ClientError::Encryption {
                uri: uri.to_string(),
                detail: e.to_string(),
            })?;

        let (addr, tag, len) = unsafe {
            let addr = header_json.as_bytes_mut();
            let tag = cryption
                .encrypt(addr)
                .map_err(|e| ClientError::Encryption {
                    uri: uri.to_string(),
                    detail: e.to_string(),
                })?;
            let len = addr.len() + tag.as_ref().len();
            (addr, tag, len as u32)
        };
        let server_socket = TcpStream::connect((SERVER_HOST.as_ref(), SERVER_PORT))
            .await
            .with_context(|_| IoSnafu {
                uri: Some(uri.to_string()),
                detail: "Connect to proxy server",
            })?;
        let (r, w) = server_socket.into_split();
        let (server_reader, mut server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));

        // send msg header
        set_data_size(&mut server_writer, len)
            .await
            .with_context(|_| SendHeaderSnafu { uri })?;
        server_writer
            .write_all(addr)
            .await
            .with_context(|_| IoSnafu {
                uri: Some(uri.to_string()),
                detail: "Send Header(host,ip)",
            })?;
        server_writer
            .write_all(tag.as_ref())
            .await
            .with_context(|_| IoSnafu {
                uri: Some(uri.to_string()),
                detail: "Send Header(tag)",
            })?;

        // start to forward
        tracing::info!(?proxy_header, info = "start to forward");
        if let Some(key) = proxy_header.key.as_ref() {
            client_proxy_with_cryptor_codec(
                host,
                key,
                client_reader,
                server_reader,
                client_writer,
                server_writer,
            )
            .await
            .with_context(|_| ProxySnafu { uri })?;
        } else {
            proxy_with_norlmal_codec(
                host,
                client_reader,
                server_reader,
                client_writer,
                server_writer,
            )
            .await
            .with_context(|_| ProxySnafu { uri })?;
        }
    }

    Ok(())
}

#[cfg(feature = "auto-proxy")]
const DEFAULT_CHAN_CAP: usize = 1024;

async fn client_proxy_background_task<const NEED_CODEC: bool>(
    client_socket: TcpStream,
    context: ClientProxyContext,
) {
    if NEED_CODEC {
        let random_key = context
            .msg_key
            .clone()
            .expect("must be Some when it `NEED_CODEC` is true");
        if let Err(e) = handle_client(client_socket, context).await {
            let report = Report::from_error(e).to_string();
            tracing::error!(random_key, proxy_with_randomkey_handle_error = report);
        }
    } else if let Err(e) = handle_client(client_socket, context).await {
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
        let (client_socket, _) = listener.accept().await.unwrap();
        #[cfg(feature = "auto-proxy")]
        let sender = sender.clone();
        let background_task = client_proxy_background_task::<NEED_CODEC>(
            client_socket,
            ClientProxyContext {
                msg_key: if NEED_CODEC {
                    Some(gen_random_key())
                } else {
                    None
                },
                #[cfg(feature = "auto-proxy")]
                sender,
            },
        );
        manager.spawn(proxy_id.gen(), background_task);
    }
    manager.wait().await;
}
