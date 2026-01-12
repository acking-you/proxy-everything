//! Transport utilities for establishing proxy connections.
//!
//! This module provides low-level TCP connection utilities that are shared
//! between the client and control modules, avoiding circular dependencies.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::LazyLock;

use dashmap::DashMap;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::net::TcpStream;

/// Permanent DNS cache for resolved domain names.
///
/// This cache is designed primarily for proxy server addresses, which are expected
/// to have stable IP addresses. Once resolved, the IP is cached permanently without
/// expiration, avoiding repeated DNS lookups for frequently accessed proxy servers.
static DNS_CACHE: LazyLock<DashMap<String, IpAddr>> = LazyLock::new(DashMap::new);

use crate::codec::AsyncReaderWriterRef;
use crate::config::runtime;
use crate::protocol::set_data_size;
use crate::{Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader};

#[derive(Debug, Snafu)]
pub enum TransportError {
    #[snafu(display("URI(`{uri:?}`), IO error: {detail}"))]
    Io {
        uri: Option<String>,
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("URI(`{uri}`) Encryption error: {detail}"))]
    Encryption { uri: String, detail: String },
    #[snafu(display("URI(`{uri}`) Send header error"))]
    SendHeader {
        uri: String,
        source: crate::ProxyError,
    },
    #[snafu(display("URI(`{uri}`) Serde json failed"))]
    SerdeJson {
        uri: String,
        source: serde_json::Error,
    },
    #[snafu(display("Empty DNS record"))]
    EmptyDNSRecord,
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[inline]
fn get_uri(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Establishes a TCP connection to the given host and port.
///
/// If the host is an IP address, connects directly.
/// If the host is a domain name, performs DNS resolution first.
#[inline]
pub async fn get_tcp_stream(host: &str, port: u16, detail: &'static str) -> Result<TcpStream> {
    // The input might be an IP address represented as a string, in which case DNS resolution is not
    // required
    let ipaddr = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Fast path: check permanent cache first
            // This cache is mainly for proxy server IPs which should remain stable
            if let Some(cached_ip) = DNS_CACHE.get(host) {
                let ip = *cached_ip;
                tracing::debug!(host, ?ip, "DNS cache hit");
                return TcpStream::connect((ip, port))
                    .await
                    .with_context(|_| IoSnafu {
                        uri: Some(format!("TcpStream({}:{})", host, port)),
                        detail,
                    });
            }

            // Try uni_stream DNS resolution first
            let ip = match uni_stream::addr::get_ip_addrs(host).await {
                Ok(addrs) => addrs.into_iter().next(),
                Err(e) => {
                    tracing::warn!(host, error = %e, "uni_stream DNS failed, falling back to tokio");
                    None
                }
            };

            // Fallback to tokio DNS resolution if uni_stream failed or returned empty
            let ip = match ip {
                Some(ip) => ip,
                None => tokio::net::lookup_host((host, port))
                    .await
                    .context(IoSnafu {
                        uri: Some(host.into()),
                        detail,
                    })?
                    .next()
                    .map(|addr| addr.ip())
                    .context(EmptyDNSRecordSnafu)?,
            };

            // Cache the resolved IP permanently (primarily for proxy server addresses)
            DNS_CACHE.insert(host.to_string(), ip);
            tracing::debug!(host, ?ip, "DNS resolved and cached");
            ip
        }
    };

    TcpStream::connect((ipaddr, port))
        .await
        .with_context(|_| IoSnafu {
            uri: Some(format!("TcpStream({}:{})", host, port)),
            detail,
        })
}

/// Establishes a TCP connection through the proxy server.
///
/// This function:
/// 1. Connects to the proxy server
/// 2. Sends an encrypted ProxyHeader with the target host/port
/// 3. Returns the connected stream ready for bidirectional forwarding
pub async fn get_tcp_proxy_stream(
    host: &str,
    port: u16,
    proxy_server: &str,
    proxy_server_port: u16,
    msg_key: Option<Cow<'static, str>>,
    detail: &'static str,
) -> Result<TcpStream> {
    // 1. get proxy server stream
    let mut proxy_server_stream = get_tcp_stream(proxy_server, proxy_server_port, detail).await?;

    // 2. prepare proxy header
    let proxy_header = ProxyHeader {
        host: host.into(),
        port,
        key: msg_key,
    };
    let mut header_json =
        serde_json::to_string(&proxy_header).with_context(|_| SerdeJsonSnafu {
            uri: get_uri(host, port),
        })?;
    let mut cryption =
        Aes256GcmCryption::try_new_with_default_key().map_err(|e| TransportError::Encryption {
            uri: get_uri(host, port),
            detail: e.to_string(),
        })?;

    // SAFETY: We use `as_bytes_mut()` to encrypt the JSON string in-place.
    // After encryption, the bytes are no longer valid UTF-8, but we only use
    // `addr` as a byte slice for network transmission (write_all), never as
    // a String again. The String is dropped after this scope.
    let (addr, tag, len) = unsafe {
        let addr = header_json.as_bytes_mut();
        let tag = cryption
            .encrypt(addr)
            .map_err(|e| TransportError::Encryption {
                uri: get_uri(host, port),
                detail: e.to_string(),
            })?;
        let len = addr.len() + tag.as_ref().len();
        (addr, tag, len as u32)
    };

    let mut proxy_server_stream_ref = AsyncReaderWriterRef::new(&mut proxy_server_stream);

    // 3. send proxy header
    set_data_size(&mut proxy_server_stream_ref, len)
        .await
        .with_context(|_| SendHeaderSnafu {
            uri: get_uri(host, port),
        })?;
    proxy_server_stream_ref
        .write_all(addr)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(get_uri(host, port)),
            detail: "Send Header(host,ip)",
        })?;
    proxy_server_stream_ref
        .write_all(tag.as_ref())
        .await
        .with_context(|_| IoSnafu {
            uri: Some(get_uri(host, port)),
            detail: "Send Header(tag)",
        })?;
    Ok(proxy_server_stream)
}

/// Returns a message key if the given IP requires encryption.
#[inline]
pub fn get_msg_key_from_codec_ip(ip: impl AsRef<str>) -> Option<String> {
    let codec_ips = runtime::need_codec_ips();
    codec_ips
        .iter()
        .find(|codec_ip| codec_ip.as_str() == ip.as_ref())
        .map(|_| crate::config::gen_random_key())
}

/// Changes `msg_key` when it is None and the IP requires encryption.
#[inline]
pub fn change_msg_key(
    ip: impl AsRef<str>,
    msg_key: Option<Cow<'static, str>>,
) -> Option<Cow<'static, str>> {
    if msg_key.is_none() {
        get_msg_key_from_codec_ip(ip).map(Cow::Owned)
    } else {
        msg_key
    }
}
