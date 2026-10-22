//! Route selection and opening direct, external, or encrypted native sessions.
use std::borrow::Cow;

use proxy_core::relay::ExternalProxyTarget;
use proxy_core::secure_transport::ProxyStream;
#[cfg(feature = "auto-proxy")]
use proxy_core::util::error_report;
use snafu::ResultExt;

#[cfg(feature = "auto-proxy")]
use super::{ClientError, LocalHostSnafu, auto_proxy::RouteSelector};
use super::{IoSnafu, Result, TransportSnafu};

/// Result of server connection resolution.
///
/// Encapsulates the connection state after proxy decision,
/// including the established stream and routing information.
pub struct ServerConnection {
    /// The established TCP connection to the server (direct or proxy).
    pub stream: ProxyStream,
    /// Whether the connection goes through the proxy server.
    pub need_proxy: bool,
    /// Optional session encryption key.
    pub msg_key: Option<Cow<'static, str>>,
}

/// Resolves server connection based on proxy rules.
///
/// This function unifies the connection establishment logic for both
/// HTTP and SOCKS5 protocols. It handles:
///
/// 1. Auto-proxy decision (if enabled)
/// 2. Direct connection for non-proxy hosts
/// 3. Proxy connection through configured server
///
/// # Arguments
///
/// * `host` - Target hostname or IP
/// * `port` - Target port
/// * `sender` - Channel for auto-proxy queries (None = always proxy)
///
/// # Returns
///
/// A `ServerConnection` containing the established stream and routing info.
pub async fn resolve_server_connection(
    host: &str,
    port: u16,
    #[cfg(feature = "auto-proxy")] sender: Option<&RouteSelector>,
    upstream_proxy: Option<&ExternalProxyTarget>,
    honor_forced_direct: bool,
) -> Result<ServerConnection> {
    use proxy_core::config::runtime;

    // Captured DNS uses this same listener, including independently started TUN
    // sessions. Never let geo, cache or direct-host rules send a DNS CONNECT
    // outside the configured upstream. Other destinations retain their policy.
    #[cfg(feature = "auto-proxy")]
    let sender = if port == 53 { None } else { sender };
    let honor_forced_direct = honor_forced_direct && port != 53;
    #[cfg(feature = "network-extension")]
    let honor_forced_direct =
        honor_forced_direct && !matches!(sender, Some(RouteSelector::Packet(_)));

    // Ahead of the upstream proxy and of every keyword or geo rule: these hosts
    // are compiled in as direct, so no configuration can route them elsewhere.
    if honor_forced_direct && proxy_core::config::is_forced_direct_host(host) {
        return Ok(ServerConnection {
            stream: get_tcp_stream(host, port, "[NOPROXY-FORCED] compiled-in direct host").await?,
            need_proxy: false,
            msg_key: None,
        });
    }

    if let Some(upstream_proxy) = upstream_proxy {
        tracing::debug!(
            host,
            port,
            upstream_proxy = %upstream_proxy.display_url(),
            "connecting target through upstream proxy"
        );
        let stream = proxy_core::transport::get_tcp_external_proxy_stream(
            upstream_proxy,
            host,
            port,
            "[UPSTREAM-PROXY] connect through external proxy",
        )
        .await
        .context(TransportSnafu)?;
        return Ok(ServerConnection {
            stream: stream.into(),
            need_proxy: true,
            msg_key: None,
        });
    }

    // One connection must observe one complete upstream generation. The FFI
    // may replace this snapshot while TUN remains enabled.
    let server_endpoint = runtime::server_endpoint();

    // If sender is None (auto-proxy disabled), always use proxy
    #[cfg(feature = "auto-proxy")]
    if let Some(sender) = sender {
        match need_proxy(host, port, sender).await? {
            ProxyStatus::NormalProxy => {}
            #[cfg(feature = "network-extension")]
            ProxyStatus::DirectAddresses(addresses) => {
                let stream = proxy_core::transport::connect_tcp_addresses(&addresses, port)
                    .await
                    .with_context(|_| IoSnafu {
                        uri: Some(get_uri(host, port)),
                        detail: "connect classified direct address",
                    })?;
                return Ok(ServerConnection {
                    stream: stream.into(),
                    need_proxy: false,
                    msg_key: None,
                });
            }
            ProxyStatus::NoProxy(detail) => {
                return Ok(ServerConnection {
                    stream: get_tcp_stream(host, port, detail).await?,
                    need_proxy: false,
                    msg_key: None,
                });
            }
            ProxyStatus::NeedSpecialProxy(proxy_server) => {
                return connect_native(host, port, &proxy_server, server_endpoint.port).await;
            }
        }
    }

    connect_native(host, port, &server_endpoint.host, server_endpoint.port).await
}

// ============================================================================
// URI and Proxy Status
// ============================================================================

#[inline]
pub fn get_uri(host: impl AsRef<str>, port: u16) -> String {
    format!("{}:{}", host.as_ref(), port)
}

pub enum ProxyStatus {
    #[cfg(feature = "network-extension")]
    DirectAddresses(std::sync::Arc<[std::net::IpAddr]>),
    NormalProxy,
    NoProxy(&'static str),
    NeedSpecialProxy(String),
}

/// How long a connection waits for a first-time geo decision before proceeding
/// through the proxy.
///
/// Sized from measured ip-api round-trips (170-680ms from the development
/// machine), so a healthy lookup still answers within it and keeps its accurate
/// decision. A shorter bound would discard good answers in the common case; a
/// longer one would be felt as a stall. Expiring is safe and self-correcting: the
/// connection uses the proxy, and the lookup finishes in the background and
/// records the answer for the next connection to that host.
///
/// The geo HTTP client has its own 2s timeout, so this is what actually bounds the
/// front end.
#[cfg(feature = "auto-proxy")]
pub(super) const AUTO_PROXY_DECISION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(800);

/// we will not proxy if option is some
#[cfg(feature = "auto-proxy")]
pub async fn need_proxy(
    host: impl AsRef<str>,
    port: u16,
    sender: &RouteSelector,
) -> Result<ProxyStatus> {
    use proxy_core::config::runtime;

    let sender = match sender {
        #[cfg(feature = "network-extension")]
        RouteSelector::Packet(router) => {
            return Ok(match router.route(host.as_ref()).await {
                super::packet_routing::PacketRoute::Proxy => ProxyStatus::NormalProxy,
                super::packet_routing::PacketRoute::Direct(ips) => {
                    ProxyStatus::DirectAddresses(ips)
                }
            });
        }
        RouteSelector::Online(sender) => sender,
    };
    if host.as_ref() == "127.0.0.1" {
        LocalHostSnafu { port }.fail()?;
    }
    // prehandle when host contain `NONPROXY_KEYWORS` or `PROXY_KEYWORDS`
    let nonproxy_keywords = runtime::nonproxy_keywords();
    let proxy_keywords = runtime::proxy_keywords();
    let has_nonproxy_list = nonproxy_keywords.iter().any(|v| host.as_ref().contains(v));
    let has_proxy_status = proxy_keywords
        .iter()
        .find(|v| host.as_ref().contains(&v.name_server))
        .map(|v| match v.proxy_server.as_ref() {
            Some(proxy_server) => ProxyStatus::NeedSpecialProxy(proxy_server.clone()),
            None => ProxyStatus::NormalProxy,
        });
    if has_nonproxy_list && has_proxy_status.is_none() {
        return Ok(ProxyStatus::NoProxy(
            "[NOPROXY-RULES] we will start connect server directly",
        ));
    }
    match has_proxy_status {
        None => {
            // Fast-path: check global cache before sending to channel
            // This bypasses channel overhead for cache hits (O(1) lookup)
            if let Some(need_proxy) = super::auto_proxy::PROXY_CACHE.get(host.as_ref()) {
                let need_proxy = *need_proxy;
                tracing::debug!(host = host.as_ref(), need_proxy, "cache hit (fast-path)");
                return if need_proxy {
                    Ok(ProxyStatus::NormalProxy)
                } else {
                    Ok(ProxyStatus::NoProxy(
                        "[NOPROXY-AUTO] we will start connect server by proxy",
                    ))
                };
            }

            // Cache miss: send to background task for geo query
            let (tx, rx) = kanal::bounded_async(1);
            if sender.try_send((host.as_ref().to_string(), tx)).is_err() {
                tracing::debug!(
                    host = host.as_ref(),
                    "geo lookup queue unavailable; using proxy"
                );
                return Ok(ProxyStatus::NormalProxy);
            }
            // Bounded so a slow or throttled lookup cannot hold up the
            // connection. Giving up does not waste the query: it finishes in the
            // background and records the answer, so the next connection to this
            // host is decided immediately and accurately.
            let received = match tokio::time::timeout(AUTO_PROXY_DECISION_TIMEOUT, rx.recv()).await
            {
                Ok(result) => result.map_err(|_| ClientError::ReceiveAutoProxy {
                    uri: get_uri(host.as_ref(), port),
                }),
                Err(_) => {
                    tracing::debug!(
                        host = host.as_ref(),
                        port,
                        timeout = ?AUTO_PROXY_DECISION_TIMEOUT,
                        "geo lookup did not answer in time; using the proxy for this connection"
                    );
                    // Same direction as a failed lookup: never leak a connection
                    // that should have been proxied.
                    return Ok(ProxyStatus::NormalProxy);
                }
            };
            match received {
                Ok(v) => {
                    if v {
                        Ok(ProxyStatus::NormalProxy)
                    } else {
                        Ok(ProxyStatus::NoProxy(
                            "[NOPROXY-AUTO] we will start connect server by proxy",
                        ))
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "{}:{} check ip error: {},we will use normal proxy by default",
                        host.as_ref(),
                        port,
                        error_report(&e)
                    );
                    Ok(ProxyStatus::NormalProxy)
                }
            }
        }
        Some(proxy_status) => Ok(proxy_status),
    }
}

#[inline]
pub async fn get_tcp_stream(host: &str, port: u16, detail: &'static str) -> Result<ProxyStream> {
    proxy_core::transport::connect_tcp_host(host, port)
        .await
        .map(Into::into)
        .with_context(|_| IoSnafu {
            uri: Some(format!("TcpStream({}:{})", host, port)),
            detail,
        })
}

pub(super) async fn connect_native(
    host: &str,
    port: u16,
    node: &str,
    node_port: u16,
) -> Result<ServerConnection> {
    let (stream, msg_key) = proxy_core::session::NativeSession::connect(
        host,
        port,
        node,
        node_port,
        proxy_core::ProxyTransport::Tcp,
    )
    .await
    .context(TransportSnafu)?
    .into_parts();
    Ok(ServerConnection {
        stream,
        need_proxy: true,
        msg_key,
    })
}
