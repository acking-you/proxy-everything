#[cfg(feature = "auto-proxy")]
use crate::client::need_proxy;
use crate::{
    client::{HttpProxySnafu, SERVER_HOST, SERVER_PORT},
    codec::{AsyncReader, AsyncWriter},
};
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::{ForwardContext, HeaderContext, ProxierImpl, ProxierProvider, ProxyContext};

#[derive(Debug, Snafu)]
pub enum HttpProxyError {
    #[snafu(display("URI(`{uri}`) Parse host from http request fails"))]
    Host { uri: String },
    #[snafu(display("URI(`{uri}`) Parse port from http request fails"))]
    Port { uri: String },
    #[snafu(display("URI(`{uri}`) Parse method from http request fails"))]
    Method { uri: String },
    #[snafu(display("Parse uri from http request fails"))]
    Uri,
    #[snafu(display("URI(`{uri}`) Parse http version from request fails"))]
    Version { uri: String },
    #[snafu(display("URI(`{uri}`) Not supported method:{method}"))]
    NotSupported { uri: String, method: String },
    #[snafu(display("URI(`{uri:?}`),Io error occur: {detail}"))]
    Io {
        uri: Option<String>,
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Invalid proxy header({proxy})"))]
    InvliadProxy { proxy: &'static str },
}

type Result<T, E = HttpProxyError> = std::result::Result<T, E>;

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
const HTTP_SCHEMA: &str = "http://";

fn extract_host_uri(uri: &str, default_port: u16) -> Result<(&str, u16)> {
    let mut parts = uri.split(':');
    let host = parts.next().context(HostSnafu { uri })?;
    let port = parts
        .next()
        .map(|port| port.trim().parse::<u16>().unwrap_or(default_port))
        .unwrap_or(default_port);
    Ok((host, port))
}

fn extract_host_from_http_uri(uri: &str) -> Result<(&str, u16)> {
    let uri = uri
        .trim()
        .strip_prefix(HTTP_SCHEMA)
        .context(HostSnafu { uri })?;
    let uri = uri.find('/').map(|i| &uri[..i]).unwrap_or(uri);
    extract_host_uri(uri, HTTP_PORT)
}

fn extract_host_from_https_uri(uri: &str) -> Result<(&str, u16)> {
    extract_host_uri(uri, HTTPS_PORT)
}

pub struct HttpProxierProvider {
    host: String,
    port: u16,
    has_ssl: bool,
    msg_key: Option<String>,
}

impl ProxierProvider for HttpProxierProvider {
    type Item = ProxierImpl;

    fn try_new_from_header_context(header: HeaderContext) -> super::Result<Self>
    where
        Self: std::marker::Sized,
    {
        let HeaderContext { header, msg_key } = header;
        let request = String::from_utf8_lossy(header);
        let mut lines = request.lines();
        if let Some(first_line) = lines.next() {
            let mut parts = first_line.split_whitespace();
            let method = parts
                .next()
                .context(MethodSnafu {
                    uri: first_line.to_string(),
                })
                .context(HttpProxySnafu)?;
            let uri = parts.next().context(UriSnafu).context(HttpProxySnafu)?;
            let _version = parts
                .next()
                .context(VersionSnafu { uri })
                .context(HttpProxySnafu)?;
            let method = method.to_ascii_lowercase();
            let has_ssl = method == "connect";
            let (host, port) = if has_ssl {
                extract_host_from_https_uri(uri).context(HttpProxySnafu)?
            } else {
                extract_host_from_http_uri(uri).context(HttpProxySnafu)?
            };
            let msg_key = msg_key.map(|s| s.to_string());
            return Ok(Self {
                host: host.to_string(),
                port,
                has_ssl,
                msg_key,
            });
        }
        InvliadProxySnafu {
            proxy: "http or https",
        }
        .fail()
        .context(HttpProxySnafu)?
    }

    // when it is https proxy we will decide start proxy or not
    async fn try_build_from_proxy_context(
        self,
        mut context: ProxyContext<'_>,
    ) -> super::Result<Self::Item> {
        let (server_stream, need_proxy) = self.get_server_stream(&mut context).await?;
        let ProxyContext { stream, .. } = context;
        let (r, w) = stream.into_split();
        let (s_r, s_w) = server_stream.into_split();
        Ok(ProxierImpl {
            context: ForwardContext {
                need_proxy,
                host: self.host,
                port: self.port,
                msg_key: self.msg_key,
            },
            client_reader: AsyncReader::new(r),
            client_writer: AsyncWriter::new(w),
            server_reader: AsyncReader::new(s_r),
            server_writer: AsyncWriter::new(s_w),
        })
    }
}

impl HttpProxierProvider {
    fn get_uri(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    async fn get_server_stream(
        &self,
        context: &mut ProxyContext<'_>,
    ) -> super::Result<(TcpStream, bool)> {
        #[inline]
        async fn get_stream(
            host: &str,
            port: u16,
            detail: &'static str,
        ) -> super::Result<TcpStream> {
            TcpStream::connect((host, port))
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(format!("{}:{}", host, port)),
                    detail,
                })
                .context(HttpProxySnafu)
        }
        if !self.has_ssl {
            let mut server = get_stream(
                &self.host,
                self.port,
                "[NOPROXY-HTTP] we will start connect http server directly",
            )
            .await?;
            server
                .write_all(context.buffer)
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(self.get_uri()),
                    detail: "http direct proxy first write error",
                })
                .context(HttpProxySnafu)?;
            Ok((server, false))
        } else {
            // response to 200
            context
                .stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(self.get_uri()),
                    detail: "Write Http Connection Ok",
                })
                .context(HttpProxySnafu)?;

            // check auto proxy to prevent proxy to remote server
            #[cfg(feature = "auto-proxy")]
            {
                if let Some(detail) =
                    need_proxy(self.host.as_str(), self.port, context.sender).await?
                {
                    return Ok((get_stream(&self.host, self.port, detail).await?, false));
                }
            }
            Ok((
                get_stream(&SERVER_HOST, SERVER_PORT, "[PROXY] we will proxy https").await?,
                true,
            ))
        }
    }
}
