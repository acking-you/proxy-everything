use std::borrow::Cow;

use snafu::{OptionExt, ResultExt, Snafu};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{
    change_msg_key, get_tcp_proxy_stream, get_tcp_stream, ForwardContext, ForwarderProvider,
    HeaderContext, ProxyContext, TcpForwardImpl,
};
#[cfg(feature = "auto-proxy")]
use crate::client::need_proxy;
use crate::client::{HttpProxySnafu, PROXY_KEYWORDS};
use crate::codec::{AsyncReader, AsyncWriter};
use crate::{SERVER_HOST, SERVER_PORT};

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
const HTTPS_SCHEMA: &str = "https://";

fn extract_host_uri(uri: &str, default_port: u16) -> Result<(&str, u16)> {
    let mut parts = uri.split(':');
    let host = parts.next().context(HostSnafu { uri })?;
    let port = parts
        .next()
        .map(|port| port.trim().parse::<u16>().unwrap_or(default_port))
        .unwrap_or(default_port);
    Ok((host, port))
}

/// may http/https
fn extract_host_from_raw_uri(uri: &str) -> Result<(&str, u16)> {
    let url = uri.trim().strip_prefix(HTTP_SCHEMA);
    let (url, port) = match url {
        Some(v) => (v, HTTP_PORT),
        None => {
            // try https parse
            tracing::warn!(
                "Uri(`{}`) not use proxy and not a http request,we try to parsing with https",
                uri
            );
            (
                uri.trim()
                    .strip_prefix(HTTPS_SCHEMA)
                    .context(HostSnafu { uri })?,
                HTTPS_PORT,
            )
        }
    };
    let url = url.find('/').map(|i| &url[..i]).unwrap_or(url);
    extract_host_uri(url, port)
}

fn extract_host_from_connect_uri(uri: &str) -> Result<(&str, u16)> {
    extract_host_uri(uri, HTTPS_PORT)
}

pub struct HttpProxierProvider {
    host: String,
    port: u16,
    has_ssl: bool,
    msg_key: Option<Cow<'static, str>>,
}

impl ForwarderProvider for HttpProxierProvider {
    type Item = TcpForwardImpl;

    fn try_new(header: HeaderContext) -> super::Result<Self>
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
                extract_host_from_connect_uri(uri).context(HttpProxySnafu)?
            } else {
                extract_host_from_raw_uri(uri).context(HttpProxySnafu)?
            };
            let msg_key = msg_key.map(|s| Cow::Owned(s.to_owned()));
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
    async fn try_build_forwarder(self, mut context: ProxyContext<'_>) -> super::Result<Self::Item> {
        let (server_stream, need_proxy, msg_key) = self.get_server_stream(&mut context).await?;
        let ProxyContext { stream, .. } = context;
        let (r, w) = stream.into_split();
        let (s_r, s_w) = server_stream.into_split();
        Ok(TcpForwardImpl {
            context: ForwardContext {
                need_proxy,
                host: self.host,
                port: self.port,
                msg_key,
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
    ) -> super::Result<(TcpStream, bool, Option<Cow<'static, str>>)> {
        // if we don't have ssl,only use proxy when host is part of `PROXY_KEYWORDS`
        if !self.has_ssl {
            let has_proxy_status = PROXY_KEYWORDS
                .iter()
                .find(|e| self.host.contains(&e.name_server));
            let (mut server_stream, msg_key) = match has_proxy_status {
                Some(proxy_status) => {
                    let server_ip = proxy_status.proxy_server.as_ref().unwrap_or(&SERVER_HOST);
                    let msg_key = change_msg_key(server_ip.as_str(), self.msg_key.clone());
                    (
                        get_tcp_proxy_stream(
                            self.host.as_str(),
                            self.port,
                            server_ip,
                            *SERVER_PORT,
                            msg_key.clone(),
                            "[PROXY] we will proxy http",
                        )
                        .await?,
                        msg_key,
                    )
                }
                None => (
                    get_tcp_stream(
                        &self.host,
                        self.port,
                        "[NOPROXY-HTTP] we will start connect http server directly",
                    )
                    .await?,
                    self.msg_key.clone(),
                ),
            };
            server_stream
                .write_all(context.buffer)
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(self.get_uri()),
                    detail: "http direct proxy first write error",
                })
                .context(HttpProxySnafu)?;

            Ok((server_stream, has_proxy_status.is_some(), msg_key))
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
                match need_proxy(self.host.as_str(), self.port, context.sender).await? {
                    crate::client::ProxyStatus::NorlmalProxy => {}
                    crate::client::ProxyStatus::NoProxy(detail) => {
                        return Ok((
                            get_tcp_stream(&self.host, self.port, detail).await?,
                            false,
                            self.msg_key.clone(),
                        ))
                    }
                    crate::client::ProxyStatus::NeedSpecialProxy(proxy_host) => {
                        let msg_key = change_msg_key(proxy_host.as_str(), self.msg_key.clone());
                        return Ok((
                            get_tcp_proxy_stream(
                                self.host.as_str(),
                                self.port,
                                &proxy_host,
                                *SERVER_PORT,
                                msg_key.clone(),
                                "[PROXY] we will proxy https",
                            )
                            .await?,
                            true,
                            msg_key,
                        ));
                    }
                }
            }
            let msg_key = change_msg_key(SERVER_HOST.as_str(), self.msg_key.clone());
            Ok((
                get_tcp_proxy_stream(
                    self.host.as_str(),
                    self.port,
                    &SERVER_HOST,
                    *SERVER_PORT,
                    msg_key.clone(),
                    "[PROXY] we will proxy https",
                )
                .await?,
                true,
                msg_key,
            ))
        }
    }
}
