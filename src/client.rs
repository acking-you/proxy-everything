use crate::runtime_codec::{new_normal_codec, AsyncReader, AsyncWriter};
use crate::{
    copy, gen_random_key, proxy_result_handle, set_data_size, Address, Aes256GcmCryption,
    MyAsyncReadExt, MyAsyncWriteExt,
};
use futures::future;
use once_cell::sync::Lazy;
use snafu::{OptionExt, ResultExt, Snafu};
use std::str::FromStr;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

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

pub async fn handle_client(client_socket: TcpStream) -> Result<()> {
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
        let addr_struct = Address {
            host: host.into(),
            port,
            key: gen_random_key(),
        };
        let mut addr_json = serde_json::to_string(&addr_struct).context(SerdeJsonSnafu)?;
        let mut cryption =
            Aes256GcmCryption::try_new_with_default_key().map_err(|e| ClientError::Encryption {
                detail: e.to_string(),
            })?;

        let (addr, tag, len) = unsafe {
            let addr = addr_json.as_bytes_mut();
            let tag = cryption
                .encrypt(addr)
                .map_err(|e| ClientError::Encryption {
                    detail: e.to_string(),
                })?;
            let len = addr.len() + tag.as_ref().len();
            (addr, tag, len as u32)
        };
        let mut server_socket = TcpStream::connect((SERVER_HOST.as_ref(), SERVER_PORT))
            .await
            .context(IoSnafu {
                detail: "Connect to proxy server",
            })?;
        let (r, w) = server_socket.split();
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
            addr_struct
        );

        // 开始进行流量转发
        let client_to_server = copy(new_normal_codec(client_reader), server_writer);
        let server_to_client = copy(new_normal_codec(server_reader), client_writer);
        let (r1, r2) = future::join(client_to_server, server_to_client).await;
        proxy_result_handle(r1, r2).context(ProxySnafu)?;
    }

    Ok(())
}
