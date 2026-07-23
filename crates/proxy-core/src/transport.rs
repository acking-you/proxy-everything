//! Transport utilities for establishing proxy connections.
//!
//! This module provides low-level TCP connection utilities that are shared
//! between the client and control modules, avoiding circular dependencies.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use moka::sync::Cache;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

const DNS_CACHE_CAPACITY: u64 = 4096;
const DNS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Bounded, expiring cache for system DNS results.
///
/// Proxy endpoints can move during failover and users can change networks while
/// the process remains alive. A permanent single-address cache made both cases
/// fail until restart and allowed arbitrary destination names to grow memory
/// without a limit.
static DNS_CACHE: LazyLock<Cache<String, Arc<[IpAddr]>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(DNS_CACHE_CAPACITY)
        .time_to_live(DNS_CACHE_TTL)
        .build()
});

use crate::codec::AsyncReaderWriterRef;
use crate::config::runtime;
use crate::protocol::set_data_size;
use crate::relay::{ExternalProxyKind, ExternalProxyTarget};
use crate::{Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader, ProxyTransport};

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
    #[snafu(display("External proxy `{proxy}` error: {detail}"))]
    ExternalProxy { proxy: String, detail: String },
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[inline]
fn get_uri(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

fn dns_cache_key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Resolve all addresses for a host through the bounded process cache.
pub async fn resolve_host_addresses(host: &str) -> std::io::Result<Arc<[IpAddr]>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Arc::from([ip]));
    }

    let cache_key = dns_cache_key(host);
    if cache_key.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS host is empty",
        ));
    }
    if let Some(cached) = DNS_CACHE.get(&cache_key) {
        tracing::debug!(host, addresses = ?cached, "DNS cache hit");
        return Ok(cached);
    }

    let mut addresses = match tokio::net::lookup_host((host, 0)).await {
        Ok(addresses) => addresses.map(|address| address.ip()).collect(),
        Err(error) => {
            tracing::warn!(host, %error, "system DNS failed, falling back to secondary resolvers");
            Vec::new()
        }
    };
    if addresses.is_empty() {
        addresses = uni_stream::addr::get_ip_addrs(host).await?;
    }
    let mut seen = HashSet::with_capacity(addresses.len());
    addresses.retain(|address| seen.insert(*address));
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Empty DNS record",
        ));
    }

    let addresses: Arc<[IpAddr]> = addresses.into();
    DNS_CACHE.insert(cache_key, Arc::clone(&addresses));
    tracing::debug!(host, ?addresses, "DNS resolved and cached");
    Ok(addresses)
}

/// Resolves a hostname to the first currently preferred IP address.
#[inline]
pub async fn resolve_host(host: &str) -> std::io::Result<IpAddr> {
    resolve_host_addresses(host)
        .await?
        .first()
        .copied()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Empty DNS record"))
}

/// Connect to every resolved address in resolver preference order, refreshing
/// the cache once when all cached candidates fail.
pub async fn connect_tcp_host(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut addresses = resolve_host_addresses(host).await?;
    let mut socket_addresses = addresses
        .iter()
        .map(|address| std::net::SocketAddr::new(*address, port))
        .collect::<Vec<std::net::SocketAddr>>();

    match TcpStream::connect(socket_addresses.as_slice()).await {
        Ok(stream) => return Ok(stream),
        Err(_) if host.parse::<IpAddr>().is_err() => {
            // A cached endpoint can disappear before its TTL expires. Force
            // one fresh lookup before reporting the connection failure.
            DNS_CACHE.invalidate(&dns_cache_key(host));
            addresses = resolve_host_addresses(host).await?;
            socket_addresses.clear();
            socket_addresses.extend(
                addresses
                    .iter()
                    .map(|address| std::net::SocketAddr::new(*address, port)),
            );
        }
        Err(source) => return Err(source),
    }

    TcpStream::connect(socket_addresses.as_slice()).await
}

/// Establishes a TCP connection to the given host and port.
///
/// If the host is an IP address, connects directly.
/// If the host is a domain name, performs DNS resolution first.
#[inline]
pub async fn get_tcp_stream(host: &str, port: u16, detail: &'static str) -> Result<TcpStream> {
    connect_tcp_host(host, port)
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
    let proxy_header = ProxyHeader {
        host: host.into(),
        port,
        key: msg_key,
        transport: ProxyTransport::Tcp,
    };
    get_proxy_stream(
        proxy_header,
        proxy_server,
        proxy_server_port,
        detail,
        &get_uri(host, port),
    )
    .await
}

/// Establishes a framed UDP-association tunnel through the proxy server.
pub async fn get_udp_proxy_stream(
    proxy_server: &str,
    proxy_server_port: u16,
    msg_key: Option<Cow<'static, str>>,
    detail: &'static str,
) -> Result<TcpStream> {
    let proxy_header = ProxyHeader {
        host: String::new(),
        port: 0,
        key: msg_key,
        transport: ProxyTransport::UdpAssociate,
    };
    get_proxy_stream(
        proxy_header,
        proxy_server,
        proxy_server_port,
        detail,
        "udp-associate",
    )
    .await
}

async fn get_proxy_stream(
    proxy_header: ProxyHeader,
    proxy_server: &str,
    proxy_server_port: u16,
    detail: &'static str,
    uri: &str,
) -> Result<TcpStream> {
    // Do not log the session key or the encrypted header. The transport and
    // boolean encryption flag are enough to diagnose protocol negotiation
    // without leaking credentials into debug output.
    tracing::debug!(
        proxy_server,
        proxy_server_port,
        target = uri,
        transport = ?proxy_header.transport,
        session_encrypted = proxy_header.key.is_some(),
        "opening proxy transport connection"
    );
    let mut proxy_server_stream = get_tcp_stream(proxy_server, proxy_server_port, detail).await?;
    let mut header_json =
        serde_json::to_string(&proxy_header).with_context(|_| SerdeJsonSnafu {
            uri: uri.to_string(),
        })?;
    let mut cryption =
        Aes256GcmCryption::try_new_with_default_key().map_err(|e| TransportError::Encryption {
            uri: uri.to_string(),
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
                uri: uri.to_string(),
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
            uri: uri.to_string(),
        })?;
    proxy_server_stream_ref
        .write_all(addr)
        .await
        .with_context(|_| IoSnafu {
            uri: Some(uri.to_string()),
            detail: "Send Header(host,ip)",
        })?;
    proxy_server_stream_ref
        .write_all(tag.as_ref())
        .await
        .with_context(|_| IoSnafu {
            uri: Some(uri.to_string()),
            detail: "Send Header(tag)",
        })?;
    tracing::debug!(
        proxy_server,
        proxy_server_port,
        target = uri,
        transport = ?proxy_header.transport,
        encrypted_header_bytes = len,
        "sent encrypted proxy connection header"
    );
    Ok(proxy_server_stream)
}

/// Establish a TCP tunnel to a destination through an external SOCKS5 or HTTP proxy.
pub async fn get_tcp_external_proxy_stream(
    proxy: &ExternalProxyTarget,
    host: &str,
    port: u16,
    detail: &'static str,
) -> Result<TcpStream> {
    match proxy.kind {
        ExternalProxyKind::Socks5 => {
            let proxy_stream = get_tcp_stream(proxy.host.as_str(), proxy.port, detail).await?;
            let target_host = if proxy.remote_dns {
                host.to_string()
            } else {
                resolve_host(host)
                    .await
                    .context(IoSnafu {
                        uri: Some(host.to_string()),
                        detail,
                    })?
                    .to_string()
            };
            let socks_stream = match (&proxy.username, &proxy.password) {
                (Some(username), Some(password)) => Socks5Stream::connect_with_password_and_socket(
                    proxy_stream,
                    (target_host.as_str(), port),
                    username,
                    password,
                )
                .await
                .map_err(|e| TransportError::ExternalProxy {
                    proxy: proxy.display_url(),
                    detail: e.to_string(),
                })?,
                _ => Socks5Stream::connect_with_socket(proxy_stream, (target_host.as_str(), port))
                    .await
                    .map_err(|e| TransportError::ExternalProxy {
                        proxy: proxy.display_url(),
                        detail: e.to_string(),
                    })?,
            };
            Ok(socks_stream.into_inner())
        }
        ExternalProxyKind::Http => {
            let mut stream = get_tcp_stream(proxy.host.as_str(), proxy.port, detail).await?;
            let authority = format!("{host}:{port}");
            let mut request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: \
                 Keep-Alive\r\n"
            );
            if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
            }
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(proxy.display_url()),
                    detail: "write http proxy connect request",
                })?;

            let mut response = Vec::new();
            let mut chunk = [0u8; 512];
            while !response.windows(4).any(|window| window == b"\r\n\r\n") {
                if response.len() > 16 * 1024 {
                    return Err(TransportError::ExternalProxy {
                        proxy: proxy.display_url(),
                        detail: "HTTP proxy response headers too large".to_string(),
                    });
                }
                let n = stream.read(&mut chunk).await.with_context(|_| IoSnafu {
                    uri: Some(proxy.display_url()),
                    detail: "read http proxy connect response",
                })?;
                if n == 0 {
                    return Err(TransportError::ExternalProxy {
                        proxy: proxy.display_url(),
                        detail: "HTTP proxy closed connection during CONNECT".to_string(),
                    });
                }
                response.extend_from_slice(&chunk[..n]);
            }

            let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                return Err(TransportError::ExternalProxy {
                    proxy: proxy.display_url(),
                    detail: "Malformed HTTP proxy response".to_string(),
                });
            };
            let header_text = String::from_utf8_lossy(&response[..headers_end + 4]);
            let status_line = header_text.lines().next().unwrap_or_default();
            let status_ok = status_line
                .split_whitespace()
                .nth(1)
                .is_some_and(|code| code == "200");
            if !status_ok {
                return Err(TransportError::ExternalProxy {
                    proxy: proxy.display_url(),
                    detail: format!("HTTP CONNECT failed: {status_line}"),
                });
            }
            Ok(stream)
        }
    }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;
    use crate::relay::ExternalProxyTarget;

    #[test]
    fn dns_cache_keys_are_case_and_root_dot_insensitive() {
        assert_eq!(dns_cache_key("Example.COM."), "example.com");
    }

    async fn start_echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
        });
        addr.to_string()
    }

    async fn start_http_proxy(expected_auth: Option<String>) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_log = Arc::new(Mutex::new(String::new()));
        let request_log_clone = request_log.clone();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = inbound.read(&mut buf).await.unwrap();
                if n == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request_str = String::from_utf8_lossy(&request).into_owned();
            *request_log_clone.lock().await = request_str.clone();
            if let Some(auth) = expected_auth {
                assert!(request_str.contains(&format!("Proxy-Authorization: Basic {auth}\r\n")));
            }
            let connect_line = request_str.lines().next().unwrap();
            let target = connect_line
                .strip_prefix("CONNECT ")
                .and_then(|v| v.split_whitespace().next())
                .unwrap();
            let mut target_parts = target.rsplitn(2, ':');
            let port: u16 = target_parts.next().unwrap().parse().unwrap();
            let host = target_parts.next().unwrap();
            let mut outbound = TcpStream::connect((host, port)).await.unwrap();
            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        (addr.to_string(), request_log)
    }

    async fn start_socks5_proxy(
        username: Option<&'static str>,
        password: Option<&'static str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();

            let ver = inbound.read_u8().await.unwrap();
            assert_eq!(ver, 0x05);
            let methods_len = inbound.read_u8().await.unwrap() as usize;
            let mut methods = vec![0u8; methods_len];
            inbound.read_exact(&mut methods).await.unwrap();
            let method = if username.is_some() { 0x02 } else { 0x00 };
            assert!(methods.contains(&method));
            inbound.write_all(&[0x05, method]).await.unwrap();

            if let (Some(username), Some(password)) = (username, password) {
                assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
                let username_len = inbound.read_u8().await.unwrap() as usize;
                let mut username_buf = vec![0u8; username_len];
                inbound.read_exact(&mut username_buf).await.unwrap();
                let password_len = inbound.read_u8().await.unwrap() as usize;
                let mut password_buf = vec![0u8; password_len];
                inbound.read_exact(&mut password_buf).await.unwrap();
                assert_eq!(String::from_utf8(username_buf).unwrap(), username);
                assert_eq!(String::from_utf8(password_buf).unwrap(), password);
                inbound.write_all(&[0x01, 0x00]).await.unwrap();
            }

            assert_eq!(inbound.read_u8().await.unwrap(), 0x05);
            assert_eq!(inbound.read_u8().await.unwrap(), 0x01);
            assert_eq!(inbound.read_u8().await.unwrap(), 0x00);
            let atyp = inbound.read_u8().await.unwrap();
            let host = match atyp {
                0x01 => {
                    let mut buf = [0u8; 4];
                    inbound.read_exact(&mut buf).await.unwrap();
                    std::net::Ipv4Addr::from(buf).to_string()
                }
                0x03 => {
                    let len = inbound.read_u8().await.unwrap() as usize;
                    let mut buf = vec![0u8; len];
                    inbound.read_exact(&mut buf).await.unwrap();
                    String::from_utf8(buf).unwrap()
                }
                other => panic!("unexpected atyp: {other:#x}"),
            };
            let port = inbound.read_u16().await.unwrap();
            let mut outbound = TcpStream::connect((host.as_str(), port)).await.unwrap();
            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn test_connect_via_http_proxy_with_basic_auth() {
        let target_addr = start_echo_server().await;
        let (target_host, target_port) = target_addr.split_once(':').unwrap();
        let target_port: u16 = target_port.parse().unwrap();

        let expected_auth = "dXNlcjpzZWNyZXQ=".to_string();
        let (proxy_addr, request_log) = start_http_proxy(Some(expected_auth)).await;
        let proxy =
            ExternalProxyTarget::parse(&format!("http://user:secret@{proxy_addr}")).unwrap();

        let mut stream =
            get_tcp_external_proxy_stream(&proxy, target_host, target_port, "http proxy auth test")
                .await
                .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(request_log.lock().await.starts_with("CONNECT "));
    }

    #[tokio::test]
    async fn test_connect_via_socks5_proxy_with_password_auth() {
        let target_addr = start_echo_server().await;
        let (target_host, target_port) = target_addr.split_once(':').unwrap();
        let target_port: u16 = target_port.parse().unwrap();

        let proxy_addr = start_socks5_proxy(Some("user"), Some("secret")).await;
        let proxy =
            ExternalProxyTarget::parse(&format!("socks5://user:secret@{proxy_addr}")).unwrap();

        let mut stream = get_tcp_external_proxy_stream(
            &proxy,
            target_host,
            target_port,
            "socks5 proxy auth test",
        )
        .await
        .unwrap();
        stream.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }
}
