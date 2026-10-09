//! Geo IP query implementations.
//!
//! Supports two modes:
//! - API mode (default): Query ip-api.com
//! - Local mode (USE_LOCAL_GEOIP=true): Use local GeoLite2 database

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use snafu::{ResultExt, Snafu};

use crate::config::USE_LOCAL_GEOIP;

/// Global HTTP client (no proxy, reused across requests)
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        crate::util::http_client_builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("Failed to create HTTP client")
    })
}

/// GeoLite2-City database download URL (jsDelivr CDN)
const GEOIP_DB_URL: &str = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz";
const GEOIP_DB_NAME: &str = "GeoLite2-City.mmdb";

#[derive(Debug, Snafu)]
pub enum GeoError {
    #[snafu(display("Geographic lookup is disabled in this distribution"))]
    ExternalLookupDisabled,
    #[snafu(display("HTTP request failed"))]
    Http { source: reqwest::Error },
    #[snafu(display("ip-api.com returned error: {detail}"))]
    ApiError { detail: String },
    /// The endpoint refused the request, or this process declined to send it
    /// because doing so would have. Distinct from [`GeoError::ApiError`] so a
    /// caller can tell "we are over budget" from "that host does not resolve":
    /// the first is temporary and must not be cached, the second is about the
    /// host itself.
    #[snafu(display("ip-api.com rate limit reached; retry after {retry_after:?}"))]
    RateLimited { retry_after: Option<Duration> },
    #[snafu(display("DNS resolution failed for {host}"))]
    DnsResolve {
        source: std::io::Error,
        host: String,
    },
    #[snafu(display("Empty DNS record"))]
    EmptyDns,
    // Local database errors
    #[snafu(display("Failed to get data directory"))]
    DataDir,
    #[snafu(display("Failed to create data directory: {source}"))]
    CreateDir { source: std::io::Error },
    #[snafu(display("Failed to download GeoIP database: {source}"))]
    Download { source: reqwest::Error },
    #[snafu(display("Failed to write GeoIP database: {source}"))]
    WriteDb { source: std::io::Error },
    #[snafu(display("Failed to open GeoIP database: {source}"))]
    OpenDb { source: maxminddb::MaxMindDbError },
    #[snafu(display("Failed to lookup IP: {source}"))]
    Lookup { source: maxminddb::MaxMindDbError },
    #[snafu(display("JSON parse error: {detail}"))]
    JsonParse { detail: String },
    #[snafu(display("IO error: {source}"))]
    Io { source: std::io::Error },
}

type Result<T> = std::result::Result<T, GeoError>;

// ============================================================================
// API Mode (ip-api.com)
// ============================================================================

/// Whether `host` is safe to interpolate into the query URL path.
///
/// Hosts arrive from client requests (a `ProxyHeader` or a SOCKS5 address), so a
/// value containing `/`, `?` or `#` would rewrite the request rather than name a
/// lookup target. Accepts the characters a hostname or an IP literal can contain
/// and nothing else.
fn is_queryable_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':' | b'[' | b']' | b'%')
        })
}

/// Whether `host` is an address whose location is knowable without asking.
///
/// A LAN peer, a loopback address, or the TUN gateway has no meaningful country,
/// and ip-api answers such a query by echoing the address back. Sending them
/// spends quota that a real host needs, and the fallback then records them as
/// "needs proxy" — observed in a live cache, which held `10.0.0.1`,
/// `192.168.1.10` and friends alongside genuine hosts.
///
/// Reported as local rather than proxied: traffic to your own network must not be
/// sent through a remote proxy.
fn is_local_address(host: &str) -> bool {
    let Ok(address) = host.parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Shared address space (CGNAT) and the TUN's own pool.
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
                // Benchmarking range, which is where virtual DNS allocates from.
                || v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1])
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local and link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Build the ip-api line-API URL for `host`.
///
/// The host is sent as-is rather than pre-resolved. ip-api resolves names
/// server-side, and resolving here would be actively wrong under TUN mode: the
/// system resolver returns a fake IP from the virtual-DNS pool, and geo-locating
/// that placeholder yields a meaningless country for every host.
fn geo_api_url(host: &str) -> String {
    format!("http://ip-api.com/line/{host}")
}

/// Shared admission control for every request to the API.
fn rate_limiter() -> &'static crate::geo::limiter::GeoRateLimiter {
    static LIMITER: OnceLock<crate::geo::limiter::GeoRateLimiter> = OnceLock::new();
    LIMITER.get_or_init(crate::geo::limiter::GeoRateLimiter::new)
}

/// `Retry-After`, or ip-api's own `X-Ttl`, as a duration.
fn retry_after_of(response: &reqwest::Response) -> Option<Duration> {
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    header("retry-after")
        .or_else(|| header("x-ttl"))
        .map(Duration::from_secs)
}

/// Query geo info for a single IP/host using ip-api.com line API.
async fn query_geo_api(host: &str) -> Result<String> {
    if !is_queryable_host(host) {
        return Err(GeoError::ApiError {
            detail: format!("host `{host}` is not a queryable hostname or address"),
        });
    }

    // Shape the request rate before spending it. Nothing user-facing waits on
    // this: the caller takes a safe default after a short deadline and this fills
    // the cache for the next connection.
    let limiter = rate_limiter();
    let _permit = limiter
        .acquire()
        .await
        .ok_or(GeoError::RateLimited { retry_after: None })?;

    let url = geo_api_url(host);
    let response = http_client().get(&url).send().await.context(HttpSnafu)?;

    // A 429 costs a full minute of rejections, so record it and stop sending
    // rather than discovering it again on the next request.
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = retry_after_of(&response);
        limiter.note_rate_limited(retry_after).await;
        return Err(GeoError::RateLimited { retry_after });
    }

    let text = response.text().await.context(HttpSnafu)?;

    // Parse response: first line is "success" or "fail", second line is country code
    let mut lines = text.lines();
    if !lines.any(|line| line == "success") {
        // The endpoint starts answering `fail` slightly before the quota is
        // exhausted, so a failure with no budget left is throttling rather than a
        // statement about this host.
        if text.contains("rate limit") || text.contains("too many requests") {
            limiter.note_rate_limited(None).await;
            return Err(GeoError::RateLimited { retry_after: None });
        }
        return Err(GeoError::ApiError { detail: text });
    }

    // Find country code in remaining lines
    for line in lines {
        let trimmed = line.trim();
        if trimmed.len() == 2 && trimmed.chars().all(|c| c.is_ascii_uppercase()) {
            return Ok(trimmed.to_string());
        }
    }

    Err(GeoError::ApiError {
        detail: "Country code not found".to_string(),
    })
}

/// Query geo info for multiple IPs using ip-api.com batch API.
async fn query_geo_batch_api<T: AsRef<str> + Serialize>(
    ips: &[T],
) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    if ips.is_empty() {
        return Ok(result);
    }

    let data: serde_json::Value = http_client()
        .post("http://ip-api.com/batch?fields=query,countryCode")
        .json(&ips)
        .send()
        .await
        .context(HttpSnafu)?
        .json()
        .await
        .context(HttpSnafu)?;

    if let Value::Array(arr) = data {
        for item in &arr {
            if let (Some(ip), Some(code)) = (
                item.get("query").and_then(|v| v.as_str()),
                item.get("countryCode").and_then(|v| v.as_str()),
            ) {
                result.insert(ip.to_string(), code.to_string());
            }
        }
        Ok(result)
    } else {
        Err(GeoError::JsonParse {
            detail: format!("Expected JSON array, got: {}", data),
        })
    }
}

// ============================================================================
// Local Database Mode (GeoLite2)
// ============================================================================

/// Global database reader (lazy initialized)
static DB_READER: Mutex<Option<maxminddb::Reader<Vec<u8>>>> = Mutex::new(None);

/// Get the path to the GeoIP database file.
fn get_db_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(GeoError::DataDir)?;
    Ok(home.join("http-proxy-cli-config").join(GEOIP_DB_NAME))
}

/// Download and decompress the GeoIP database (with progress bar).
#[cfg(feature = "cli-dep")]
async fn download_db(path: &PathBuf) -> Result<()> {
    use flate2::read::GzDecoder;
    use futures::StreamExt;
    use indicatif::{ProgressBar, ProgressStyle};

    tracing::info!("Downloading GeoIP database from {}", GEOIP_DB_URL);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context(CreateDirSnafu)?;
    }

    let response = http_client()
        .get(GEOIP_DB_URL)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .context(DownloadSnafu)?;

    let total = response.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.set_message("Downloading GeoIP database");

    let mut downloaded = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context(DownloadSnafu)?;
        pb.inc(chunk.len() as u64);
        downloaded.extend_from_slice(&chunk);
    }
    pb.finish_with_message("Download complete");

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message("Decompressing...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut decoder = GzDecoder::new(&downloaded[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).context(IoSnafu)?;

    std::fs::write(path, &decompressed).context(WriteDbSnafu)?;

    pb.finish_with_message(format!("Done! Saved to {}", path.display()));
    tracing::info!("GeoIP database saved to {:?}", path);
    Ok(())
}

/// Download and decompress the GeoIP database (simple version without progress bar).
#[cfg(not(feature = "cli-dep"))]
async fn download_db(path: &PathBuf) -> Result<()> {
    use flate2::read::GzDecoder;

    tracing::info!("Downloading GeoIP database from {}", GEOIP_DB_URL);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context(CreateDirSnafu)?;
    }

    let bytes = http_client()
        .get(GEOIP_DB_URL)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .context(DownloadSnafu)?
        .bytes()
        .await
        .context(DownloadSnafu)?;

    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).context(IoSnafu)?;

    std::fs::write(path, &decompressed).context(WriteDbSnafu)?;
    tracing::info!("GeoIP database saved to {:?}", path);
    Ok(())
}

/// Ensure the GeoIP database exists, downloading if necessary.
pub async fn ensure_db() -> Result<PathBuf> {
    if cfg!(feature = "no-external-geo") {
        return Err(GeoError::ExternalLookupDisabled);
    }
    let path = get_db_path()?;
    if !path.exists() {
        download_db(&path).await?;
    }
    Ok(path)
}

/// Get or initialize the database reader.
fn get_reader() -> Result<()> {
    let mut guard = DB_READER.lock().expect("DB_READER lock poisoned");
    if guard.is_none() {
        let start = std::time::Instant::now();
        let path = get_db_path()?;
        if !path.exists() {
            return Err(GeoError::DataDir);
        }
        let data = std::fs::read(&path).context(IoSnafu)?;
        let reader = maxminddb::Reader::from_source(data).context(OpenDbSnafu)?;
        *guard = Some(reader);
        tracing::info!("GeoIP database loaded in {:?}", start.elapsed());
    }
    Ok(())
}

/// Query country code for a single IP address using local database.
fn lookup_country_local(ip: IpAddr) -> Result<String> {
    get_reader()?;
    let guard = DB_READER.lock().expect("DB_READER lock poisoned");
    let reader = guard.as_ref().ok_or(GeoError::DataDir)?;
    let result = reader.lookup(ip).context(LookupSnafu)?;
    let city: maxminddb::geoip2::City = result
        .decode()
        .context(LookupSnafu)?
        .ok_or(GeoError::DataDir)?;

    if let Some(code) = city.country.iso_code {
        return Ok(code.to_string());
    }

    // No country code found, log the city structure for debugging
    tracing::warn!(
        ip = %ip,
        city = ?city.city,
        continent = ?city.continent,
        registered_country = ?city.registered_country,
        "No country code found, using XX"
    );
    Ok("XX".to_string())
}

/// Query geo info for a single host using local database.
async fn query_geo_local(host: &str) -> Result<String> {
    // Ensure database exists
    ensure_db().await?;

    // Resolve hostname to IP
    let ip = crate::transport::resolve_host(host)
        .await
        .map_err(|e| GeoError::DnsResolve {
            source: e,
            host: host.to_string(),
        })?;

    lookup_country_local(ip)
}

/// Query geo info for multiple hosts using local database.
async fn query_geo_batch_local(hosts: &[impl AsRef<str>]) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    if hosts.is_empty() {
        return Ok(result);
    }

    // Ensure database exists
    ensure_db().await?;

    for host in hosts {
        let host_str = host.as_ref();
        // Try parse as IP first, fallback to DNS resolution
        let ip = if let Ok(ip) = host_str.parse::<IpAddr>() {
            ip
        } else if let Ok(addrs) = uni_stream::addr::get_ip_addrs(host_str).await {
            if let Some(ip) = addrs.into_iter().next() {
                ip
            } else {
                continue;
            }
        } else {
            continue;
        };

        if let Ok(code) = lookup_country_local(ip) {
            result.insert(host_str.to_string(), code);
        }
    }

    Ok(result)
}

// ============================================================================
// Public API (auto-selects mode based on USE_LOCAL_GEOIP)
// ============================================================================

/// Whether `host` names an address on the local network or the TUN's own pool.
///
/// Callers should route these directly without consulting a geo backend: they have
/// no meaningful country, ip-api just echoes the address back, and each query
/// spends budget a real host needs. A live cache was observed holding `10.0.0.1`
/// and `192.168.1.10` recorded as "needs proxy" for exactly this reason.
///
/// Exposed rather than applied inside [`query_geo_single`] because the decision
/// must not pass through the reverse-geo inversion — sending LAN traffic to a
/// remote proxy is wrong in either polarity.
pub fn is_local_network_host(host: &str) -> bool {
    is_local_address(host)
}

/// Query geo info for a single host.
/// Returns the country code (e.g., "CN", "US").
pub async fn query_geo_single(host: &str) -> Result<String> {
    if cfg!(feature = "no-external-geo") {
        return Err(GeoError::ExternalLookupDisabled);
    }
    if *USE_LOCAL_GEOIP {
        query_geo_local(host).await
    } else {
        query_geo_api(host).await
    }
}

/// Query geo info for multiple IPs.
/// Returns a map of IP -> country code (e.g., "8.8.8.8" -> "US").
pub async fn query_geo_batch<T: AsRef<str> + Serialize>(
    ips: &[T],
) -> Result<HashMap<String, String>> {
    if cfg!(feature = "no-external-geo") {
        return Err(GeoError::ExternalLookupDisabled);
    }
    if *USE_LOCAL_GEOIP {
        query_geo_batch_local(ips).await
    } else {
        query_geo_batch_api(ips).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "no-external-geo")]
    #[tokio::test]
    async fn restricted_distribution_never_resolves_or_downloads_geo_data() {
        assert!(matches!(
            query_geo_single("review.example").await,
            Err(GeoError::ExternalLookupDisabled)
        ));
        assert!(matches!(
            query_geo_batch(&["203.0.113.42"]).await,
            Err(GeoError::ExternalLookupDisabled)
        ));
        assert!(matches!(
            ensure_db().await,
            Err(GeoError::ExternalLookupDisabled)
        ));
    }

    /// The lookup target must be the host itself. Resolving it first would break
    /// under TUN mode, where the system resolver answers with a fake IP from the
    /// virtual-DNS pool and the geo answer would describe that placeholder.
    #[test]
    fn the_query_names_the_host_rather_than_a_resolved_address() {
        assert_eq!(
            geo_api_url("github.com"),
            "http://ip-api.com/line/github.com"
        );
        assert_eq!(geo_api_url("8.8.8.8"), "http://ip-api.com/line/8.8.8.8");
        // A fake-IP address must never appear in a query; passing the name
        // through is what prevents it.
        assert!(!geo_api_url("github.com").contains("198.1"));
    }

    /// Addresses on the local network must never reach the API. Each one spends
    /// budget a real host needs, and ip-api answers by echoing the address back —
    /// which the fallback then records as "needs proxy". A live cache was found
    /// holding `10.0.0.1` and `192.168.1.10` for exactly this reason.
    #[test]
    fn local_addresses_are_recognised_without_a_query() {
        // Private ranges.
        assert!(is_local_network_host("192.168.1.10"));
        assert!(is_local_network_host("10.0.0.1"), "the TUN gateway");
        assert!(is_local_network_host("172.16.4.9"));
        // Loopback, link-local, unspecified, multicast.
        assert!(is_local_network_host("127.0.0.1"));
        assert!(is_local_network_host("169.254.1.1"));
        assert!(is_local_network_host("0.0.0.0"));
        assert!(is_local_network_host("224.0.0.251"));
        // CGNAT and the virtual-DNS fake-IP pool.
        assert!(is_local_network_host("100.64.0.1"));
        assert!(
            is_local_network_host("198.19.0.110"),
            "a virtual-DNS fake IP"
        );
        // IPv6 loopback and unique/link-local.
        assert!(is_local_network_host("::1"));
        assert!(is_local_network_host("fd00::1"));
        assert!(is_local_network_host("fe80::1"));

        // Real routable addresses and hostnames are not local.
        assert!(!is_local_network_host("8.8.8.8"));
        assert!(!is_local_network_host("1.1.1.1"));
        assert!(
            !is_local_network_host("100.128.0.1"),
            "outside the CGNAT range"
        );
        assert!(
            !is_local_network_host("198.20.0.1"),
            "outside the benchmark range"
        );
        assert!(!is_local_network_host("github.com"));
        assert!(!is_local_network_host("2606:4700::1111"));
    }

    /// Hosts come from client requests, so a path separator would rewrite the
    /// request rather than name a target.
    #[test]
    fn only_plausible_hosts_are_queried() {
        assert!(is_queryable_host("github.com"));
        assert!(is_queryable_host("sub.domain.example"));
        assert!(is_queryable_host("8.8.8.8"));
        assert!(is_queryable_host("[2001:db8::1]"));
        assert!(is_queryable_host("xn--fiqs8s.example"));

        assert!(!is_queryable_host(""));
        assert!(!is_queryable_host("evil/../json"));
        assert!(!is_queryable_host("host?fields=all"));
        assert!(!is_queryable_host("host#frag"));
        assert!(!is_queryable_host("has space"));
        assert!(!is_queryable_host("new\nline"));
        assert!(!is_queryable_host(&"a".repeat(256)));
    }

    #[tokio::test]
    async fn an_unqueryable_host_fails_without_a_request() {
        let error = query_geo_api("evil/../json").await.unwrap_err();
        assert!(
            error.to_string().contains("not a queryable"),
            "unexpected error: {error}"
        );
    }

    /// Proves the fix end to end, so it is kept even though CI cannot run it.
    /// `cargo test -p proxy-core --lib -- --ignored geo_api_classifies`
    #[tokio::test]
    #[ignore = "requires network access to ip-api.com"]
    async fn geo_api_classifies_hosts_by_name() {
        assert_eq!(query_geo_api("baidu.com").await.unwrap(), "CN");
        assert_ne!(query_geo_api("github.com").await.unwrap(), "CN");
        // An address still works, unchanged.
        assert_eq!(query_geo_api("8.8.8.8").await.unwrap(), "US");
    }

    /// A burst larger than the per-minute budget must be shaped rather than
    /// rejected. Before the limiter this produced HTTP 429s and a minute-long
    /// penalty window.
    ///
    /// `cargo test -p proxy-core --lib -- --ignored --nocapture a_burst_is_shaped`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires network access to ip-api.com and takes ~30s"]
    async fn a_burst_is_shaped_instead_of_hitting_the_rate_limit() {
        // More hosts than the burst allowance, so the token bucket has to throttle.
        let hosts: Vec<String> = (0..25).map(|i| format!("example{i}.com")).collect();

        let results = futures::future::join_all(hosts.iter().map(|host| query_geo_api(host))).await;

        let rate_limited = results
            .iter()
            .filter(|r| matches!(r, Err(GeoError::RateLimited { .. })))
            .count();
        let resolved = results.iter().filter(|r| r.is_ok()).count();
        println!(
            "resolved={resolved} rate_limited={rate_limited} of {}",
            hosts.len()
        );

        assert_eq!(
            rate_limited, 0,
            "the limiter must shape the burst rather than let it be refused"
        );
        assert!(
            resolved > 0,
            "expected at least some hosts to be classified"
        );
    }
}
