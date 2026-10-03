//! Transport utilities for establishing proxy connections.
//!
//! This module provides low-level TCP connection utilities that are shared
//! between the client and control modules, avoiding circular dependencies.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use moka::sync::Cache;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;
use tokio_socks::tcp::Socks5Stream;

const DNS_CACHE_CAPACITY: u64 = 4096;
const DNS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_REFRESH_FLOOR: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const EXTERNAL_PROXY_TIMEOUT: Duration = Duration::from_secs(15);
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(3);
const ADDRESS_STAGGER: Duration = Duration::from_millis(250);
static DNS_SLOTS: Semaphore = Semaphore::const_new(8);

struct DnsEntry {
    addresses: Arc<[IpAddr]>,
    refreshed: Instant,
}

static DNS_LOOKUPS: LazyLock<Cache<String, Arc<Mutex<()>>>> =
    LazyLock::new(|| Cache::builder().max_capacity(DNS_CACHE_CAPACITY).build());

/// Bounded, expiring cache for system DNS results.
///
/// Proxy endpoints can move during failover and users can change networks while
/// the process remains alive. A permanent single-address cache made both cases
/// fail until restart and allowed arbitrary destination names to grow memory
/// without a limit.
static DNS_CACHE: LazyLock<Cache<String, Arc<DnsEntry>>> = LazyLock::new(|| {
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
    resolve_addresses(host, false).await
}

async fn resolve_addresses(host: &str, refresh: bool) -> std::io::Result<Arc<[IpAddr]>> {
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
    let lookup = async {
        let gate = DNS_LOOKUPS.get_with(cache_key.clone(), || Arc::new(Mutex::new(())));
        let _guard = gate.lock().await;
        if let Some(cached) = DNS_CACHE.get(&cache_key)
            && (!refresh || cached.refreshed.elapsed() < DNS_REFRESH_FLOOR)
        {
            return Ok(Arc::clone(&cached.addresses));
        }

        // The permit stays with the OS call even if the async waiter times out.
        // Cancelling lookup_host itself otherwise leaves an unbounded blocking job.
        let permit = DNS_SLOTS.acquire().await.map_err(std::io::Error::other)?;
        let owned_host = host.to_owned();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            (owned_host.as_str(), 0)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>())
        })
        .await
        .map_err(std::io::Error::other)?;
        let mut addresses = match result {
            Ok(addresses) => addresses.into_iter().map(|address| address.ip()).collect(),
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
        DNS_CACHE.insert(
            cache_key,
            Arc::new(DnsEntry {
                addresses: Arc::clone(&addresses),
                refreshed: Instant::now(),
            }),
        );
        tracing::debug!(host, ?addresses, "DNS resolved and cached");
        Ok(addresses)
    };
    tokio::time::timeout(DNS_TIMEOUT, lookup)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup budget exhausted")
        })?
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
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let addresses = resolve_host_addresses(host).await?;
        match race_addresses(&addresses, port, TcpStream::connect).await {
            Ok(stream) => Ok(stream),
            Err(error) if host.parse::<IpAddr>().is_err() => {
                let refreshed = resolve_addresses(host, true).await?;
                if refreshed == addresses {
                    return Err(error);
                }
                race_addresses(&refreshed, port, TcpStream::connect).await
            }
            Err(error) => Err(error),
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TCP connection budget exhausted",
        )
    })?
}

// At most two sockets are in flight. A blackholed preferred address must not
// delay the other family until the operating system's SYN retries expire.
async fn race_addresses<T, F, Fut>(
    addresses: &[IpAddr],
    port: u16,
    connect: F,
) -> std::io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;
    let mut ordered = addresses.to_vec();
    if let Some(first) = ordered.first()
        && let Some(other) = ordered
            .iter()
            .position(|ip| ip.is_ipv4() != first.is_ipv4())
    {
        let other = ordered.remove(other);
        ordered.insert(1, other);
    }
    let mut remaining = ordered.into_iter();
    let mut pending = FuturesUnordered::new();
    let mut next_start = Instant::now();
    let mut last_error = std::io::Error::new(std::io::ErrorKind::NotFound, "Empty DNS record");
    loop {
        if pending.is_empty() || (pending.len() < 2 && Instant::now() >= next_start) {
            if let Some(ip) = remaining.next() {
                pending.push(tokio::time::timeout(
                    ADDRESS_TIMEOUT,
                    connect(SocketAddr::new(ip, port)),
                ));
                next_start = Instant::now() + ADDRESS_STAGGER;
            } else if pending.is_empty() {
                return Err(last_error);
            }
        }
        tokio::select! {
            result = pending.next(), if !pending.is_empty() => {
                match result {
                    Some(Ok(Ok(stream))) => return Ok(stream),
                    Some(Ok(Err(error))) => last_error = error,
                    Some(Err(_)) => last_error = std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP address timed out"),
                    None => {}
                }
                next_start = Instant::now();
            }
            _ = tokio::time::sleep_until(next_start), if pending.len() < 2 && remaining.len() > 0 => {}
        }
    }
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
    tokio::time::timeout(
        EXTERNAL_PROXY_TIMEOUT,
        negotiate_external_proxy(proxy, host, port, detail),
    )
    .await
    .map_err(|_| TransportError::ExternalProxy {
        proxy: proxy.display_url(),
        detail: "proxy connection and handshake exceeded 15 seconds".to_string(),
    })?
}

async fn negotiate_external_proxy(
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
            let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
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
            read_http_header(&mut stream, &mut response, 16 * 1024)
                .await
                .with_context(|_| IoSnafu {
                    uri: Some(proxy.display_url()),
                    detail: "read http proxy connect response",
                })?;

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

/// Append one HTTP header through its terminating CRLF pair, leaving payload
/// bytes on the socket. `header` may contain an already-read protocol prefix.
/// The caller owns the setup deadline and the maximum header size.
pub async fn read_http_header(
    stream: &mut TcpStream,
    header: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<()> {
    let mut chunk = [0; 4096];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy header exceeds its size limit",
            ));
        }
        let capacity = chunk.len().min(limit - header.len());
        let n = stream.peek(&mut chunk[..capacity]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP proxy header",
            ));
        }
        // A header can share a packet with a request body or a tunnel greeting.
        // Inspect the previous three bytes too, in case CRLF straddles reads.
        let prefix = header.len().min(3);
        let mut boundary = [0; 4099];
        boundary[..prefix].copy_from_slice(&header[header.len() - prefix..]);
        boundary[prefix..prefix + n].copy_from_slice(&chunk[..n]);
        let consume = boundary[..prefix + n]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map_or(n, |end| end + 4 - prefix);
        stream.read_exact(&mut chunk[..consume]).await?;
        header.extend_from_slice(&chunk[..consume]);
    }
    Ok(())
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

    #[tokio::test(start_paused = true)]
    async fn silent_external_proxies_release_the_connection_at_the_setup_deadline() {
        for scheme in ["http", "socks5h"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = ExternalProxyTarget::parse(&format!(
                "{scheme}://{}",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let client = tokio::spawn(async move {
                get_tcp_external_proxy_stream(&proxy, "example.test", 443, "deadline test").await
            });
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(peer.read(&mut request).await.unwrap() > 0);
            tokio::time::advance(EXTERNAL_PROXY_TIMEOUT).await;
            let error = client.await.unwrap().unwrap_err();
            assert!(error.to_string().contains("handshake exceeded 15 seconds"));
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
        }
    }

    #[tokio::test]
    async fn http_connect_preserves_coalesced_payload_and_formats_ipv6_authorities() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            ExternalProxyTarget::parse(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT [::1]:443 HTTP/1.1\r\n"));
            // Split the delimiter across reads, then coalesce its end with data.
            peer.write_all(b"HTTP/1.1 200 OK\r\n\r").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            peer.write_all(b"\nserver greeting").await.unwrap();
        });
        let mut stream = get_tcp_external_proxy_stream(&proxy, "::1", 443, "payload test")
            .await
            .unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"server greeting");
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_blackholed_preferred_address_does_not_delay_the_other_family() {
        let started = Instant::now();
        let ips = [
            "::1".parse().unwrap(),
            "::2".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ];
        let connected = race_addresses(&ips, 80, |address| async move {
            if address.is_ipv6() {
                std::future::pending::<()>().await;
            }
            Ok(address)
        })
        .await
        .unwrap();
        assert!(connected.is_ipv4());
        assert_eq!(started.elapsed(), ADDRESS_STAGGER);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_candidates_advance_without_the_stagger_delay() {
        let started = Instant::now();
        let ips = ["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
        let connected = race_addresses(&ips, 80, |address| async move {
            if address.ip() == "127.0.0.1".parse::<IpAddr>().unwrap() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            Ok(address)
        })
        .await
        .unwrap();
        assert_eq!(connected.ip(), ips[1]);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_stalled_dial_drops_every_candidate_and_bounds_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let ips = (1..=20)
            .map(|n| IpAddr::from([127, 0, 0, n]))
            .collect::<Vec<_>>();
        let attempt = race_addresses(&ips, 80, |_| {
            let active = Active(Arc::clone(&count));
            peak.fetch_max(count.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            async move {
                let _active = active;
                std::future::pending::<std::io::Result<()>>().await
            }
        });
        assert!(
            tokio::time::timeout(CONNECT_TIMEOUT, attempt)
                .await
                .is_err()
        );
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(count.load(Ordering::SeqCst), 0);
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
