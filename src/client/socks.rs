#[cfg(feature = "auto-proxy")]
use crate::client::need_proxy;
use snafu::{ResultExt, Snafu};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    client::{SERVER_HOST, SERVER_PORT},
    codec::{AsyncReader, AsyncWriter},
};

use super::{auto_proxy::SenderChan, ProxierImpl, ProxierProvider, SocksProxySnafu};

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Error in socks5 first shakehand,detail:{detail}"))]
    FirstRequest { detail: &'static str },
    #[snafu(display("Unsupported operate:{detail}"))]
    NotSupported { detail: &'static str },
    #[snafu(display("Sock5 proxy io error occur: {detail}"))]
    Io {
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Invalid proxy header({proxy})"))]
    InvliadProxy { proxy: &'static str },
}

type Result<T, E = SocksError> = std::result::Result<T, E>;

const SOCK5_VER: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const TCP_CONN: u8 = 0x01;
const IPV4_ADDR: u8 = 0x01;
const NAMING_SERVER: u8 = 0x03;

pub struct SocksProxierProvider {
    msg_key: Option<String>,
}

impl ProxierProvider for SocksProxierProvider {
    type Item = ProxierImpl;

    fn try_new_from_header_context(header_context: super::HeaderContext<'_>) -> super::Result<Self>
    where
        Self: std::marker::Sized,
    {
        if header_context.header.len() < 2 {
            FirstRequestSnafu {
                detail: "`VER` and `NMETHODS` not found",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }

        if header_context.header[0] != SOCK5_VER {
            NotSupportedSnafu {
                detail: "not sock5 version in first shakehand",
            }
            .fail()
            .context(SocksProxySnafu)?
        }
        let n = header_context.header[1];
        if ((header_context.header.len() - 2) as u8) < n {
            FirstRequestSnafu {
                detail: "`METHODS` not valid",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }
        Ok(Self {
            msg_key: header_context.msg_key.map(|s| s.to_string()),
        })
    }

    async fn try_build_from_proxy_context(
        self,
        mut proxy_context: super::ProxyContext<'_>,
    ) -> super::Result<Self::Item> {
        let (host, port) = auth(&mut proxy_context.stream)
            .await
            .context(SocksProxySnafu)?;
        response(&mut proxy_context.stream)
            .await
            .context(SocksProxySnafu)?;
        let (server_stream, need_proxy) =
            get_server_stream(host.as_str(), port, proxy_context.sender).await?;
        let (r, w) = proxy_context.stream.into_split();
        let (s_r, s_w) = server_stream.into_split();
        Ok(Self::Item {
            context: super::ForwardContext {
                host,
                port,
                need_proxy,
                msg_key: self.msg_key,
            },
            client_reader: AsyncReader::new(r),
            client_writer: AsyncWriter::new(w),
            server_reader: AsyncReader::new(s_r),
            server_writer: AsyncWriter::new(s_w),
        })
    }
}

async fn auth(stream: &mut TcpStream) -> Result<(String, u16)> {
    stream.write_u8(SOCK5_VER).await.context(IoSnafu {
        detail: "write version",
    })?;
    stream.write_u8(NO_AUTH).await.context(IoSnafu {
        detail: "write no_auth",
    })?;
    if stream.read_u8().await.context(IoSnafu {
        detail: "read version in auth",
    })? != SOCK5_VER
    {
        NotSupportedSnafu {
            detail: "sock5 version in auth",
        }
        .fail()?
    }
    if stream.read_u8().await.context(IoSnafu {
        detail: "read cmd in auth",
    })? != TCP_CONN
    {
        NotSupportedSnafu {
            detail: "only support tcp",
        }
        .fail()?
    }
    stream.read_u8().await.context(IoSnafu {
        detail: "read reserve in auth",
    })?;
    let atyp = stream.read_u8().await.context(IoSnafu {
        detail: "read inet type in auth",
    })?;
    match atyp {
        IPV4_ADDR => {
            let mut buf: [u8; 4] = [0; 4];
            stream.read_exact(&mut buf).await.context(IoSnafu {
                detail: "read host in auth",
            })?;
            let port = stream.read_u16().await.context(IoSnafu {
                detail: "read port in ipv4 addr",
            })?;
            Ok((format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]), port))
        }
        NAMING_SERVER => {
            let host_len = stream.read_u8().await.context(IoSnafu {
                detail: "read host len in auth",
            })?;
            let mut buf: [u8; 255] = [0; 255];
            let buf = &mut buf[0..host_len as usize];
            stream.read_exact(buf).await.context(IoSnafu {
                detail: "read naming server in auth",
            })?;
            let port = stream.read_u16().await.context(IoSnafu {
                detail: "read port in naming server",
            })?;
            Ok((String::from_utf8_lossy(buf).into_owned(), port))
        }
        _ => NotSupportedSnafu {
            detail: "only support IPV4 and NAME_ADDR",
        }
        .fail()?,
    }
}

/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// VER socks版本，这里为0x05
/// REP Relay field,内容取值如下 X’00’ succeeded
/// RSV 保留字段
/// ATYPE 地址类型
/// BND.ADDR 服务绑定的地址
/// BND.PORT 服务绑定的端口DST.PORT
async fn response(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .context(IoSnafu {
            detail: "send response ok",
        })
}

async fn get_server_stream(
    host: impl AsRef<str>,
    port: u16,
    sender: &SenderChan,
) -> super::Result<(TcpStream, bool)> {
    #[inline]
    async fn get_stream(host: &str, port: u16, detail: &'static str) -> super::Result<TcpStream> {
        TcpStream::connect((host, port))
            .await
            .with_context(|_| IoSnafu { detail })
            .context(SocksProxySnafu)
    }

    // check auto proxy to prevent proxy to remote server
    #[cfg(feature = "auto-proxy")]
    {
        if let Some(detail) = need_proxy(host.as_ref(), port, sender).await? {
            return Ok((get_stream(host.as_ref(), port, detail).await?, false));
        }
    }
    Ok((
        get_stream(&SERVER_HOST, SERVER_PORT, "[PROXY] we will proxy socks5").await?,
        true,
    ))
}
