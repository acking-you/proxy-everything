use std::borrow::Cow;

use base64::Engine;
use proxy_core::config::runtime;
use proxy_core::relay::{ExternalProxyKind, ExternalProxyTarget};
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{
    ForwardContext, ForwarderProvider, HeaderContext, HttpProxySnafu, ProxyContext,
    ServerConnection, TcpForwardImpl, change_msg_key, get_tcp_proxy_stream, get_tcp_stream,
    resolve_server_connection, split_and_wrap,
};

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

fn is_proxy_authorization_header(line: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
}

fn proxy_authorization_header(proxy: &ExternalProxyTarget) -> Option<String> {
    let (Some(username), Some(password)) = (&proxy.username, &proxy.password) else {
        return None;
    };
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    Some(format!("Proxy-Authorization: Basic {auth}\r\n"))
}

fn rewrite_proxy_authorization(buffer: &[u8], proxy: &ExternalProxyTarget) -> Vec<u8> {
    let Some(headers_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return buffer.to_vec();
    };

    let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
    let mut lines = header_text.split("\r\n");
    let mut rewritten = Vec::with_capacity(buffer.len() + 128);

    if let Some(request_line) = lines.next() {
        rewritten.extend_from_slice(request_line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }

    if let Some(header) = proxy_authorization_header(proxy) {
        rewritten.extend_from_slice(header.as_bytes());
    }

    for line in lines {
        if !is_proxy_authorization_header(line) {
            rewritten.extend_from_slice(line.as_bytes());
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(&buffer[headers_end + 4..]);
    rewritten
}

fn extract_host_uri(uri: &str, default_port: u16) -> Result<(&str, u16)> {
    let mut parts = uri.split(':');
    let host = parts.next().context(HostSnafu { uri })?;
    let port = match parts.next() {
        Some(port_str) => port_str
            .trim()
            .parse::<u16>()
            .map_err(|_| HttpProxyError::Port {
                uri: uri.to_string(),
            })?,
        None => default_port,
    };
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

        // Split streams using common helper
        let (client_reader, client_writer) = split_and_wrap(context.stream);
        let (server_reader, server_writer) = split_and_wrap(server_stream);

        Ok(TcpForwardImpl {
            context: ForwardContext {
                need_proxy,
                host: self.host,
                port: self.port,
                msg_key,
            },
            client_reader,
            client_writer,
            server_reader,
            server_writer,
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
            // Compiled-in direct hosts win over the upstream proxy and over
            // `force_proxy`; see `proxy_core::config::FORCED_DIRECT_HOSTS`.
            if context.honor_forced_direct
                && proxy_core::config::is_forced_direct_host(self.host.as_str())
            {
                let mut server_stream = get_tcp_stream(
                    &self.host,
                    self.port,
                    "[NOPROXY-FORCED] compiled-in direct host",
                )
                .await?;
                server_stream
                    .write_all(context.buffer)
                    .await
                    .with_context(|_| IoSnafu {
                        uri: Some(self.get_uri()),
                        detail: "http forced-direct first write error",
                    })
                    .context(HttpProxySnafu)?;
                return Ok((server_stream, false, self.msg_key.clone()));
            }

            if let Some(upstream_proxy) = context.upstream_proxy {
                tracing::info!(
                    host = %self.host,
                    port = self.port,
                    upstream_proxy = %upstream_proxy.display_url(),
                    "forwarding plain HTTP through upstream proxy"
                );
                let mut server_stream = match upstream_proxy.kind {
                    ExternalProxyKind::Http => {
                        get_tcp_stream(
                            upstream_proxy.host.as_str(),
                            upstream_proxy.port,
                            "[UPSTREAM-PROXY] connect to http proxy",
                        )
                        .await?
                    }
                    ExternalProxyKind::Socks5 => {
                        proxy_core::transport::get_tcp_external_proxy_stream(
                            upstream_proxy,
                            self.host.as_str(),
                            self.port,
                            "[UPSTREAM-PROXY] connect http target through socks5 proxy",
                        )
                        .await
                        .context(super::ExternalProxySnafu)?
                    }
                };
                let request = if upstream_proxy.kind == ExternalProxyKind::Http {
                    rewrite_proxy_authorization(context.buffer, upstream_proxy)
                } else {
                    context.buffer.to_vec()
                };
                server_stream
                    .write_all(&request)
                    .await
                    .with_context(|_| IoSnafu {
                        uri: Some(self.get_uri()),
                        detail: "write http request to upstream proxy",
                    })
                    .context(HttpProxySnafu)?;

                return Ok((server_stream, true, None));
            }

            // Hold one endpoint snapshot for the full connection setup so a
            // concurrent node switch cannot mix address generations.
            let server_endpoint = runtime::server_endpoint();
            let (mut server_stream, need_proxy, msg_key) = if context.force_proxy {
                let msg_key = change_msg_key(server_endpoint.host.as_str(), self.msg_key.clone());
                (
                    get_tcp_proxy_stream(
                        self.host.as_str(),
                        self.port,
                        &server_endpoint.host,
                        server_endpoint.port,
                        msg_key.clone(),
                        "[PROXY] auto-proxy disabled; force proxy",
                    )
                    .await?,
                    true,
                    msg_key,
                )
            } else {
                let proxy_keywords = runtime::proxy_keywords();
                let has_proxy_status = proxy_keywords
                    .iter()
                    .find(|e| self.host.contains(&e.name_server));
                match has_proxy_status {
                    Some(proxy_status) => {
                        let server_ip = proxy_status
                            .proxy_server
                            .as_ref()
                            .unwrap_or(&server_endpoint.host);
                        let msg_key = change_msg_key(server_ip.as_str(), self.msg_key.clone());
                        (
                            get_tcp_proxy_stream(
                                self.host.as_str(),
                                self.port,
                                server_ip,
                                server_endpoint.port,
                                msg_key.clone(),
                                "[PROXY] we will proxy http",
                            )
                            .await?,
                            true,
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
                        false,
                        self.msg_key.clone(),
                    ),
                }
            };
            server_stream
                .write_all(context.buffer)
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(self.get_uri()),
                    detail: "http direct proxy first write error",
                })
                .context(HttpProxySnafu)?;

            Ok((server_stream, need_proxy, msg_key))
        } else {
            // HTTPS CONNECT: respond with 200 OK first
            context
                .stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(self.get_uri()),
                    detail: "Write Http Connection Ok",
                })
                .context(HttpProxySnafu)?;

            // Use unified server connection resolution for HTTPS
            let ServerConnection {
                stream,
                need_proxy,
                msg_key,
            } = resolve_server_connection(
                self.host.as_str(),
                self.port,
                context.sender,
                self.msg_key.clone(),
                context.upstream_proxy,
                context.honor_forced_direct,
            )
            .await?;

            Ok((stream, need_proxy, msg_key))
        }
    }
}
