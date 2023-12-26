use snafu::{ResultExt, Snafu};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::{ProxierImpl, ProxierProvider, SocksProxySnafu};

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Error in socks5 first shakehand,detail:{detail}"))]
    FirstRequest { detail: &'static str },
    #[snafu(display("Unsupported version of `SOCKS`, currently only `SOCKS5` is supported"))]
    NotSupported,
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

pub struct SocksProxierProvider {
    msg_key: Option<String>,
}

impl ProxierProvider for SocksProxierProvider {
    type Item = ProxierImpl;

    fn try_new_from_header_context(header_context: super::HeaderContext<'_>) -> super::Result<Self>
    where
        Self: std::marker::Sized,
    {
        if header_context.header.len() >= 2 {
            FirstRequestSnafu {
                detail: "`VER` and `NMETHODS` not found",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }

        if header_context.header[0] != SOCK5_VER {
            NotSupportedSnafu {}.fail().context(SocksProxySnafu)?
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
        todo!()
    }
}

async fn auth(stream: &mut TcpStream) -> Result<(String, u16)> {
    stream.write_u8(SOCK5_VER).await.context(IoSnafu {
        detail: "write version",
    })?;
    stream.write_u8(NO_AUTH).await.context(IoSnafu {
        detail: "write no_auth",
    })?;
    todo!()
}
