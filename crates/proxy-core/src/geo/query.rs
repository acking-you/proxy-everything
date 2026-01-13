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

use serde::Serialize;
use serde_json::Value;
use snafu::{ResultExt, Snafu};

use crate::config::USE_LOCAL_GEOIP;

/// Global HTTP client (no proxy, reused across requests)
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
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
    #[snafu(display("HTTP request failed"))]
    Http { source: reqwest::Error },
    #[snafu(display("ip-api.com returned error: {detail}"))]
    ApiError { detail: String },
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

/// Query geo info for a single IP/host using ip-api.com line API.
async fn query_geo_api(host: &str) -> Result<String> {
    let ipaddr = crate::transport::resolve_host(host)
        .await
        .with_context(|_| DnsResolveSnafu {
            host: host.to_string(),
        })?;

    let url = format!("http://ip-api.com/line/{}", ipaddr);
    let text = http_client()
        .get(&url)
        .send()
        .await
        .context(HttpSnafu)?
        .text()
        .await
        .context(HttpSnafu)?;

    // Parse response: first line is "success" or "fail", second line is country code
    let mut lines = text.lines();
    if !lines.any(|line| line == "success") {
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

/// Query geo info for a single host.
/// Returns the country code (e.g., "CN", "US").
pub async fn query_geo_single(host: &str) -> Result<String> {
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
    if *USE_LOCAL_GEOIP {
        query_geo_batch_local(ips).await
    } else {
        query_geo_batch_api(ips).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_query_geo_api() {
        let result = query_geo_api("8.8.8.8").await;
        println!("API Result: {:?}", result);
        let result = query_geo_batch_api(&["8.8.8.8"]).await;
        println!("API Result: {:?}", result);
    }
}
