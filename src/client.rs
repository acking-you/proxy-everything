use crate::runtime_codec::{AsyncReader, AsyncWriter};
use crate::{
    client_proxy_with_cryptor_codec, gen_random_key, proxy_with_norlmal_codec, set_data_size,
    Aes256GcmCryption, MyAsyncReadExt, MyAsyncWriteExt, ProxyHeader,
};

#[cfg(feature = "monoio")]
use monoio::io::Splitable;
use once_cell::sync::Lazy;
use snafu::{OptionExt, Report, ResultExt, Snafu};
use std::str::FromStr;
#[cfg(feature = "tokio")]
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(feature = "monoio")]
use monoio::net::TcpStream;

#[derive(Debug, Snafu)]
pub enum ClientError {
    #[snafu(display("Parse host from http request fails"))]
    Host,
    #[snafu(display("Parse port from http request fails"))]
    Port,
    #[snafu(display("Parse port from string fails"))]
    StrPort { source: <u16 as FromStr>::Err },
    #[snafu(display("Parse method from http request fails"))]
    Method,
    #[snafu(display("Parse uri from http request fails"))]
    Uri,
    #[snafu(display("Parse http version from request fails"))]
    Version,
    #[snafu(display("Not supported operate:{detail}"))]
    NotSupported { detail: String },
    #[snafu(display("Serde json failed"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("Io error occur: {detail}"))]
    Io {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Encryption error occur,detail:{detail}"))]
    Encryption { detail: String },
    #[snafu(display("Send header error"))]
    SendHeader { source: super::Error },
    #[snafu(display("Proxy error happen"))]
    Proxy { source: super::Error },
}

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

pub async fn handle_client(client_socket: TcpStream, msg_key: Option<String>) -> Result<()> {
    if let Some(key) = msg_key.as_ref() {
        tracing::info!("Start handle stream:random key is:{}", key);
    }
    let (r, w) = client_socket.into_split();
    let (mut client_reader, mut client_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let mut buffer = [0; 4096];
    client_reader.read(&mut buffer).await.context(IoSnafu {
        detail: "Read Http Header",
    })?;

    // 解析客户端请求
    let request = String::from_utf8_lossy(&buffer[..]);
    let mut lines = request.lines();
    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        let method = parts.next().context(MethodSnafu)?;
        let uri = parts.next().context(UriSnafu)?;
        let _version = parts.next().context(VersionSnafu)?;
        let method = method.to_ascii_lowercase();
        if method != "connect" {
            NotSupportedSnafu {
                detail: format!(
                    "Only `CONNECT` in http request supported and you are using `{method}`"
                ),
            }
            .fail()?
        }

        let mut parts = uri.split(':');
        let host = parts.next().context(HostSnafu)?;
        let port: u16 = parts
            .next()
            .context(PortSnafu)?
            .parse()
            .context(StrPortSnafu)?;

        // 响应客户端连接已建立
        client_writer
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .await
            .context(IoSnafu {
                detail: "Write Http Connection Ok",
            })?;

        tracing::info!("Start proxy {}:{}", host, port);

        // 通知服务器进行流量转发
        let proxy_header = ProxyHeader {
            host: host.into(),
            port,
            key: msg_key,
        };
        let mut header_json = serde_json::to_string(&proxy_header).context(SerdeJsonSnafu)?;
        let mut cryption =
            Aes256GcmCryption::try_new_with_default_key().map_err(|e| ClientError::Encryption {
                detail: e.to_string(),
            })?;

        let (addr, tag, len) = unsafe {
            let addr = header_json.as_bytes_mut();
            let tag = cryption
                .encrypt(addr)
                .map_err(|e| ClientError::Encryption {
                    detail: e.to_string(),
                })?;
            let len = addr.len() + tag.as_ref().len();
            (addr, tag, len as u32)
        };
        let server_socket = TcpStream::connect((SERVER_HOST.as_ref(), SERVER_PORT))
            .await
            .context(IoSnafu {
                detail: "Connect to proxy server",
            })?;
        let (r, w) = server_socket.into_split();
        let (server_reader, mut server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));

        // 发送数据头部用于确定数据包大小
        set_data_size(&mut server_writer, len)
            .await
            .context(SendHeaderSnafu)?;
        // 发送addr信息给代理服务器
        server_writer.write_all(addr).await.context(IoSnafu {
            detail: "Send Header(host,ip)",
        })?;
        server_writer
            .write_all(tag.as_ref())
            .await
            .context(IoSnafu {
                detail: "Send Header(tag)",
            })?;
        tracing::info!(
            "Proxy Header({}) send Ok! Start to forward net flow",
            proxy_header
        );

        // 开始进行流量转发
        if let Some(key) = proxy_header.key.as_ref() {
            client_proxy_with_cryptor_codec(
                key,
                client_reader,
                server_reader,
                client_writer,
                server_writer,
            )
            .await
            .context(ProxySnafu)?;
        } else {
            proxy_with_norlmal_codec(client_reader, server_reader, client_writer, server_writer)
                .await
                .context(ProxySnafu)?;
        }
    }

    Ok(())
}

pub async fn start_normal_client(host: impl AsRef<str>, port: u16) {
    let listener = TcpListener::bind((host.as_ref(), port)).await.unwrap();
    loop {
        let (client_socket, _) = listener.accept().await.unwrap();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, None).await {
                let report = Report::from_error(e).to_string();
                tracing::error!("Error happens in client handling: {}", report);
            }
        });
    }
}

pub async fn start_codec_msg_client(host: impl AsRef<str>, port: u16) {
    let listener = TcpListener::bind((host.as_ref(), port)).await.unwrap();
    loop {
        let (client_socket, _) = listener.accept().await.unwrap();

        tokio::spawn(async move {
            let rand_key = gen_random_key();
            if let Err(e) = handle_client(client_socket, Some(rand_key.clone())).await {
                let report = Report::from_error(e).to_string();
                tracing::error!(
                    "random_key_is:{} Error happens in client handling: {}",
                    rand_key,
                    report
                );
            }
        });
    }
}
