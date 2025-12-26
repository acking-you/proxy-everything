use std::borrow::Cow;
use std::net::Ipv6Addr;

use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    resolve_server_connection, split_and_wrap, ForwardContext, ForwarderProvider, ServerConnection,
    SocksProxySnafu, TcpForwardImpl,
};

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Error in socks5 first shakehand,detail:{detail}"))]
    FirstRequest { detail: &'static str },
    #[snafu(display("Unsupported operate:{detail}"))]
    NotSupported { detail: &'static str },
    #[snafu(display("Unsupported operate:{detail} with atyp(`{atyp:#x}`)"))]
    NotSupportedHost { atyp: u8, detail: &'static str },
    #[snafu(display("Unsupported operate:{detail} with cmd(`{cmd:#x}`)"))]
    NotSupportedTransport { cmd: u8, detail: &'static str },
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
const IPV6_ADDR: u8 = 0x04;
const NAMING_SERVER: u8 = 0x03;

pub struct SocksProxierProvider {
    msg_key: Option<Cow<'static, str>>,
}

impl ForwarderProvider for SocksProxierProvider {
    type Item = TcpForwardImpl;

    fn try_new(header_context: super::HeaderContext<'_>) -> super::Result<Self>
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
            msg_key: header_context.msg_key.map(|s| Cow::Owned(s.to_owned())),
        })
    }

    async fn try_build_forwarder(
        self,
        mut proxy_context: super::ProxyContext<'_>,
    ) -> super::Result<Self::Item> {
        let (host, port) = auth(&mut proxy_context.stream)
            .await
            .context(SocksProxySnafu)?;
        response(&mut proxy_context.stream)
            .await
            .context(SocksProxySnafu)?;

        // Use unified server connection resolution
        let ServerConnection {
            stream: server_stream,
            need_proxy,
            msg_key,
        } = resolve_server_connection(host.as_str(), port, proxy_context.sender, self.msg_key)
            .await?;

        // Split streams using common helper
        let (client_reader, client_writer) = split_and_wrap(proxy_context.stream);
        let (server_reader, server_writer) = split_and_wrap(server_stream);

        Ok(Self::Item {
            context: ForwardContext {
                host,
                port,
                need_proxy,
                msg_key,
            },
            client_reader,
            client_writer,
            server_reader,
            server_writer,
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
    let cmd = stream.read_u8().await.context(IoSnafu {
        detail: "read cmd in auth",
    })?;
    if cmd != TCP_CONN {
        NotSupportedTransportSnafu {
            cmd,
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
                detail: "read ipv4 host in auth",
            })?;
            let port = stream.read_u16().await.context(IoSnafu {
                detail: "read port in ipv4 addr",
            })?;
            Ok((format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]), port))
        }
        IPV6_ADDR => {
            let mut buf: [u8; 16] = [0; 16];
            stream.read_exact(&mut buf).await.context(IoSnafu {
                detail: "read ipv6 host in auth",
            })?;
            let port = stream.read_u16().await.context(IoSnafu {
                detail: "read port in ipv6 addr",
            })?;
            Ok((Ipv6Addr::from(buf).to_string(), port))
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
        atyp => NotSupportedHostSnafu {
            atyp,
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

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    #[test]
    fn test_ip_display() {
        let buf: [u8; 16] = [0; 16]; // 假设 buf 包含了长度为 16 的字节数据，表示 IPv6 地址

        // 将 buf 中的字节数据转换为 Ipv6Addr 对象
        let ipv6_addr = Ipv6Addr::from(buf);

        // 将 Ipv6Addr 对象转换为字符串表示
        let ipv6_str = ipv6_addr.to_string();

        println!("IPv6 address: {}", ipv6_str);
    }
}
