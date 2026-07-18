use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use rand::Rng;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, fmt};

pub fn init_tracing() {
    let subcriber = tracing_subscriber::registry().with(
        fmt::layer()
            .pretty()
            .with_writer(std::io::stdout)
            .with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
    );
    tracing::subscriber::set_global_default(subcriber).expect("setting tracing default failed");
}

pub fn gen_random_key() -> String {
    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    let mut rng = rand::rng();
    let random_string: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    random_string
}

fn parse_bool_env(var: &str, default: bool) -> bool {
    match std::env::var(var) {
        Ok(val) => matches!(
            val.trim().to_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

/// Runtime-updatable configuration for FFI
pub mod runtime {
    use super::*;

    /// One immutable upstream snapshot. Keeping the host and port in the same
    /// `ArcSwap` prevents a connection accepted during a node switch from
    /// combining the old host with the new port (or vice versa).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ServerEndpoint {
        pub host: String,
        pub port: u16,
    }

    #[cfg(feature = "auto-proxy")]
    static REVERSE_GEO_RT: AtomicBool = AtomicBool::new(false);

    // ArcSwap for complex types (lock-free reads)
    type SecretKey = Option<(Vec<u8>, u32)>;
    static SERVER_ENDPOINT_RT: Lazy<ArcSwap<ServerEndpoint>> = Lazy::new(|| {
        ArcSwap::from_pointee(ServerEndpoint {
            host: String::new(),
            port: 1081,
        })
    });
    static NEED_CODEC_IP_RT: Lazy<ArcSwap<Vec<String>>> =
        Lazy::new(|| ArcSwap::from_pointee(Vec::new()));
    static SECRET_KEY_RT: Lazy<ArcSwap<SecretKey>> = Lazy::new(|| ArcSwap::from_pointee(None));
    #[cfg(feature = "auto-proxy")]
    static PROXY_KEYWORDS_RT: Lazy<ArcSwap<Vec<ParsedProxyKeyWord>>> =
        Lazy::new(|| ArcSwap::from_pointee(Vec::new()));
    #[cfg(feature = "auto-proxy")]
    static NONPROXY_KEYWORDS_RT: Lazy<ArcSwap<Vec<String>>> =
        Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

    // ===== Setters (for FFI direct use) =====

    pub fn set_server_host(host: String) {
        let current = SERVER_ENDPOINT_RT.load();
        set_server_endpoint(host, current.port);
    }

    pub fn set_server_port(port: u16) {
        let current = SERVER_ENDPOINT_RT.load();
        set_server_endpoint(current.host.clone(), port);
    }

    /// Atomically replace the upstream address used by newly accepted relay
    /// sessions. Established sessions keep their existing socket until their
    /// owner explicitly drains them.
    pub fn set_server_endpoint(host: String, port: u16) {
        SERVER_ENDPOINT_RT.store(Arc::new(ServerEndpoint { host, port }));
    }

    #[cfg(feature = "auto-proxy")]
    pub fn set_reverse_geo(reverse: bool) {
        REVERSE_GEO_RT.store(reverse, Ordering::SeqCst);
    }

    pub fn set_need_codec_ips(ips: Vec<String>) {
        NEED_CODEC_IP_RT.store(Arc::new(ips));
    }

    pub fn set_secret_key(key: Option<String>) {
        let key_data = key.and_then(|k| {
            let bytes = k.as_bytes();
            if bytes.len() != 32 {
                tracing::warn!(
                    "`SECRET_KEY` must have 256 bit(32 byte)! current: {} bytes",
                    bytes.len()
                );
                return None;
            }
            let hash = bytes
                .iter()
                .fold(0u32, |h, &b| h.wrapping_mul(31).wrapping_add(b as u32));
            Some((bytes.to_vec(), hash))
        });
        SECRET_KEY_RT.store(Arc::new(key_data));
    }

    #[cfg(feature = "auto-proxy")]
    pub fn set_proxy_keywords(reverse: bool) {
        let default_proxy = if reverse {
            CN_KEYWORDS.clone()
        } else {
            FOREIGN_KEYWORDS.clone()
        };
        PROXY_KEYWORDS_RT.store(Arc::new(parse_keywords(default_proxy)));
    }

    #[cfg(feature = "auto-proxy")]
    pub fn set_nonproxy_keywords(reverse: bool) {
        let default_nonproxy = if reverse {
            FOREIGN_KEYWORDS.clone()
        } else {
            CN_KEYWORDS.clone()
        };
        NONPROXY_KEYWORDS_RT.store(Arc::new(default_nonproxy));
    }

    // ===== Getters (lock-free) =====

    pub fn server_port() -> u16 {
        SERVER_ENDPOINT_RT.load().port
    }

    pub fn server_host() -> Arc<String> {
        let endpoint = SERVER_ENDPOINT_RT.load();
        if endpoint.host.is_empty() {
            Arc::new("127.0.0.1".to_string())
        } else {
            Arc::new(endpoint.host.clone())
        }
    }

    /// Load a consistent upstream host/port pair for one connection attempt.
    pub fn server_endpoint() -> Arc<ServerEndpoint> {
        let endpoint = SERVER_ENDPOINT_RT.load_full();
        if endpoint.host.is_empty() {
            Arc::new(ServerEndpoint {
                host: "127.0.0.1".to_string(),
                port: endpoint.port,
            })
        } else {
            endpoint
        }
    }

    #[cfg(feature = "auto-proxy")]
    pub fn reverse_geo() -> bool {
        REVERSE_GEO_RT.load(Ordering::SeqCst)
    }

    #[cfg(not(feature = "auto-proxy"))]
    pub fn reverse_geo() -> bool {
        false
    }

    pub fn need_codec_ips() -> Arc<Vec<String>> {
        NEED_CODEC_IP_RT.load_full()
    }

    /// Get secret key via closure (zero-copy for sync callers)
    pub fn with_secret_key<R>(f: impl FnOnce(&[u8], u32) -> R) -> R {
        let guard = SECRET_KEY_RT.load();
        match guard.as_ref() {
            Some((key, hash)) => f(key, *hash),
            None => f(&DEFAULT_KEY.0, DEFAULT_KEY.1),
        }
    }

    #[cfg(feature = "auto-proxy")]
    pub fn proxy_keywords() -> Arc<Vec<ParsedProxyKeyWord>> {
        PROXY_KEYWORDS_RT.load_full()
    }

    #[cfg(feature = "auto-proxy")]
    pub fn nonproxy_keywords() -> Arc<Vec<String>> {
        NONPROXY_KEYWORDS_RT.load_full()
    }

    /// Initialize all runtime config from values (for FFI)
    pub fn init_config(
        host: String,
        port: u16,
        reverse: bool,
        codec_ips: Vec<String>,
        secret: Option<String>,
    ) {
        set_server_endpoint(host, port);
        set_secret_key(secret);
        set_need_codec_ips(codec_ips);

        #[cfg(feature = "auto-proxy")]
        {
            set_reverse_geo(reverse);
            set_proxy_keywords(reverse);
            set_nonproxy_keywords(reverse);
        }
        #[cfg(not(feature = "auto-proxy"))]
        let _ = reverse;

        tracing::info!(
            "Runtime config initialized: server={}:{}",
            server_host(),
            server_port()
        );
    }
}

/// Port for connect to proxy server
pub static SERVER_PORT: Lazy<u16> = Lazy::new(|| {
    let default_port = 1081;
    match std::env::var("SERVER_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "`SERVER_PORT` is invalid port! error:{}",
                    crate::util::error_report(&e)
                );
                default_port
            }
        },
        Err(_) => {
            tracing::warn!(
                "No ENV:`SERVER_PORT` provided,we use default server port:{default_port}"
            );
            default_port
        }
    }
});

/// Port for provide to local proxy server
pub static CLIENT_PORT: Lazy<u16> = Lazy::new(|| {
    let default_port = 1080;
    match std::env::var("CLIENT_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "`CLIENT_PORT` is invalid port! error:{}",
                    crate::util::error_report(&e)
                );
                default_port
            }
        },
        Err(_) => {
            tracing::warn!(
                "No ENV:`CLIENT_PORT` provided,we use default client port:{default_port}"
            );
            default_port
        }
    }
});

/// Ip or URL to connect server
pub static SERVER_HOST: Lazy<String> = Lazy::new(|| match std::env::var("SERVER_HOST") {
    Ok(s) => s,
    Err(_) => {
        tracing::error!("You are not set `ENV:SERVER_HOST`. we will use `localhost` as default!");
        "127.0.0.1".to_string()
    }
});

/// Optional override for the persisted server state directory.
pub fn proxy_data_dir() -> Option<PathBuf> {
    std::env::var_os("PROXY_DATA_DIR").and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        }
    })
}

/// Default directory used to store relay and node state.
pub fn default_state_dir() -> PathBuf {
    proxy_data_dir().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".proxy-everything")
    })
}

/// Turly proxy server (ip/addr:port)
pub static TURELY_PROXY_SERVER: Lazy<Option<String>> =
    Lazy::new(|| match std::env::var("TURELY_PROXY_SERVER") {
        Ok(s) if !s.trim().is_empty() => Some(s),
        _ => {
            tracing::info!("No `ENV:TURELY_PROXY_SERVER` set. Running as real proxy server.");
            None
        }
    });

/// Control plane admin token (optional). If set, control requests must include it.
pub static CONTROL_ADMIN_TOKEN: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("CONTROL_ADMIN_TOKEN").ok());

/// Require encrypted control payloads (default: true).
pub static CONTROL_REQUIRE_ENCRYPTION: Lazy<bool> =
    Lazy::new(|| parse_bool_env("CONTROL_REQUIRE_ENCRYPTION", true));

/// Session key for control plane (optional; 32 bytes).
pub static CONTROL_SESSION_KEY: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("CONTROL_SESSION_KEY").ok());

/// Reverse geo-proxy logic: if true, CN sites use proxy, others direct.
#[cfg(feature = "auto-proxy")]
pub static REVERSE_GEO_PROXY: Lazy<bool> = Lazy::new(|| parse_bool_env("REVERSE_GEO_PROXY", false));

/// Use local GeoIP database instead of ip-api.com API.
/// When enabled, will auto-download GeoLite2-City.mmdb if not exists.
#[cfg(feature = "auto-proxy")]
pub static USE_LOCAL_GEOIP: Lazy<bool> = Lazy::new(|| parse_bool_env("USE_LOCAL_GEOIP", false));

/// Advertised address for node sync (e.g., "1.2.3.4:1081").
pub static NODE_ADVERTISE_ADDR: Lazy<Option<String>> = Lazy::new(|| {
    std::env::var("NODE_ADVERTISE_ADDR")
        .ok()
        .filter(|v| !v.trim().is_empty())
});

/// Optional stable node ID (defaults to NODE_ADVERTISE_ADDR if unset).
pub static NODE_ID: Lazy<Option<String>> = Lazy::new(|| {
    std::env::var("NODE_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
});

/// Node sync interval (seconds).
pub static NODE_SYNC_INTERVAL_SECS: Lazy<u64> = Lazy::new(|| {
    std::env::var("NODE_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
});

/// Default secret key (32 bytes) used when SECRET_KEY env is not set
pub const DEFAULT_SECRET_KEY: &str = "my-secret-key123my-secret-key123";

// 256-bit key,must be 256/8 = 32 byte key and hashcode
pub static DEFAULT_KEY: Lazy<(Vec<u8>, u32)> = Lazy::new(|| {
    let default_key = DEFAULT_SECRET_KEY;
    let key = match std::env::var("SECRET_KEY") {
        Ok(k) => {
            let key = k.as_bytes();
            if key.len() != 32 {
                tracing::warn!(current_length = key.len(), "`SECRET_KEY` must be 32 bytes");
                std::process::exit(1);
            }
            key.to_vec()
        }
        Err(_) => {
            tracing::warn!("No `SECRET_KEY` provided; using the built-in default");
            default_key.as_bytes().to_vec()
        }
    };
    let hash = key.iter().fold(0u32, |hash, &byte| {
        hash.wrapping_mul(31).wrapping_add(byte as u32)
    });
    (key, hash)
});

const DEFAULT_WORD: &str = "%DEFAULT%";

/// Get user-configured keywords from environment variable (excluding %DEFAULT% placeholder).
/// This is used to check what keywords the user explicitly configured,
/// so we can remove conflicting keywords from the opposite list.
///
/// For example, if user sets NONPROXY_KEYWORDS="google", we need to remove "google"
/// from PROXY_KEYWORDS to respect user's preference.
///
/// Returns empty Vec if env var is not set.
fn get_user_keywords(env_var: &str) -> Vec<String> {
    std::env::var(env_var)
        .map(|k| {
            k.trim()
                .split(',')
                .filter(|v| *v != DEFAULT_WORD)
                .map(|v| v.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn split_concat_with_default(data: String, mut default: Vec<String>) -> Vec<String> {
    let keyowrds_iter = data.trim().split(',').map(|v| v.to_string());
    let mut keywords = Vec::with_capacity(default.len());
    let mut need_default = false;
    keyowrds_iter.for_each(|k| {
        if k == DEFAULT_WORD {
            need_default = true;
        } else {
            keywords.push(k);
        }
    });
    if need_default {
        keywords.append(&mut default);
    }
    keywords
}

/// CN sites keyword list (direct in normal mode, proxy in reverse mode)
#[cfg(feature = "auto-proxy")]
static CN_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    vec![
        "chaoxing".to_string(),
        "bilibili".to_string(),
        "bili".to_string(),
        "xigua".to_string(),
        "byte".to_string(),
        "douyin".to_string(),
        "cnblogs".to_string(),
        "qq.com".to_string(),
        "jd.com".to_string(),
        "retiehe".to_string(),
        "meituan".to_string(),
        "jianguoyun".to_string(),
        "taobao.com".to_string(),
        "csdn".to_string(),
        "juejin".to_string(),
        "baidu".to_string(),
        "zhihu".to_string(),
        "ximalaya".to_string(),
        "cn".to_string(),
    ]
});

/// Foreign sites keyword list (proxy in normal mode, direct in reverse mode)
#[cfg(feature = "auto-proxy")]
static FOREIGN_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    vec![
        "tiktok".to_string(),
        "youtube".to_string(),
        "scholar.google".to_string(),
        "reddit".to_string(),
        "google".to_string(),
        "chatgpt".to_string(),
        "twitter".to_string(),
        "facebook".to_string(),
        "bilibili.tv".to_string(),
        "github".to_string(),
        "docker".to_string(),
    ]
});

/// NONPROXY_KEYWORDS: Sites that should connect directly without proxy.
///
/// User configuration priority logic:
/// 1. Load default keywords based on reverse_geo mode:
///    - Normal mode: CN_KEYWORDS (Chinese sites direct)
///    - Reverse-geo mode: FOREIGN_KEYWORDS (foreign sites direct)
/// 2. If user set NONPROXY_KEYWORDS env var, use user's config (with %DEFAULT% expansion)
/// 3. Remove any keywords that user explicitly put in PROXY_KEYWORDS
/// 4. Add user's NONPROXY_KEYWORDS to ensure they're included
///
/// In reverse-geo mode, users should still configure normally:
/// - Put sites you want to connect directly in NONPROXY_KEYWORDS
/// - Put sites you want to proxy in PROXY_KEYWORDS
#[cfg(feature = "auto-proxy")]
pub static NONPROXY_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    // Swap defaults in reverse-geo mode:
    // Normal: CN sites direct, Foreign sites proxy
    // Reverse: Foreign sites direct, CN sites proxy
    let default_keywords = if *REVERSE_GEO_PROXY {
        FOREIGN_KEYWORDS.clone()
    } else {
        CN_KEYWORDS.clone()
    };
    // Get user's explicit keywords from both lists
    let user_proxy = get_user_keywords("PROXY_KEYWORDS");
    let user_nonproxy = get_user_keywords("NONPROXY_KEYWORDS");

    let keywords = match std::env::var("NONPROXY_KEYWORDS") {
        Ok(k) => split_concat_with_default(k, default_keywords),
        Err(_) => default_keywords,
    };
    // Remove keywords that user explicitly put in proxy list (user config takes priority)
    let mut keywords: Vec<String> = keywords
        .into_iter()
        .filter(|k| !user_proxy.iter().any(|p| p.contains(k) || k.contains(p)))
        .collect();
    // Add user's nonproxy keywords to ensure they're included (even if not in defaults)
    for kw in user_nonproxy {
        if !keywords.iter().any(|k| k.contains(&kw) || kw.contains(k)) {
            keywords.push(kw);
        }
    }
    tracing::info!("`NONPROXY_KEYWORDS` is `{keywords:?}`");
    keywords
});

#[derive(Debug, Clone)]
pub struct ParsedProxyKeyWord {
    pub name_server: String,
    pub proxy_server: Option<String>,
}

fn parse_keywords(keywords: Vec<String>) -> Vec<ParsedProxyKeyWord> {
    keywords
        .into_iter()
        .map(|v| match v.find(':') {
            Some(i) => ParsedProxyKeyWord {
                name_server: v[..i].trim().to_string(),
                proxy_server: Some(v[i + 1..].trim().to_string()),
            },
            None => ParsedProxyKeyWord {
                name_server: v,
                proxy_server: None,
            },
        })
        .collect()
}

/// PROXY_KEYWORDS: Sites that should use proxy.
///
/// User configuration priority logic:
/// 1. Load default keywords based on reverse_geo mode:
///    - Normal mode: FOREIGN_KEYWORDS (foreign sites proxy)
///    - Reverse-geo mode: CN_KEYWORDS (Chinese sites proxy)
/// 2. If user set PROXY_KEYWORDS env var, use user's config (with %DEFAULT% expansion)
/// 3. Remove any keywords that user explicitly put in NONPROXY_KEYWORDS
/// 4. Add user's PROXY_KEYWORDS to ensure they're included
///
/// In reverse-geo mode, users should still configure normally:
/// - Put sites you want to proxy in PROXY_KEYWORDS
/// - Put sites you want to connect directly in NONPROXY_KEYWORDS
#[cfg(feature = "auto-proxy")]
pub static PROXY_KEYWORDS: Lazy<Vec<ParsedProxyKeyWord>> = Lazy::new(|| {
    // Swap defaults in reverse-geo mode:
    // Normal: Foreign sites proxy, CN sites direct
    // Reverse: CN sites proxy, Foreign sites direct
    let default_keywords = if *REVERSE_GEO_PROXY {
        CN_KEYWORDS.clone()
    } else {
        FOREIGN_KEYWORDS.clone()
    };
    // Get user's explicit keywords from both lists
    let user_nonproxy = get_user_keywords("NONPROXY_KEYWORDS");
    let user_proxy = get_user_keywords("PROXY_KEYWORDS");

    let keywords = match std::env::var("PROXY_KEYWORDS") {
        Ok(k) => split_concat_with_default(k, default_keywords),
        Err(_) => default_keywords,
    };
    // Remove keywords that user explicitly put in nonproxy list (user config takes priority)
    let mut keywords: Vec<String> = keywords
        .into_iter()
        .filter(|k| !user_nonproxy.iter().any(|n| n.contains(k) || k.contains(n)))
        .collect();
    // Add user's proxy keywords to ensure they're included (even if not in defaults)
    for kw in user_proxy {
        if !keywords.iter().any(|k| k.contains(&kw) || kw.contains(k)) {
            keywords.push(kw);
        }
    }
    tracing::info!("`PROXY_KEYWORDS` is `{keywords:?}`");
    parse_keywords(keywords)
});

pub static NEED_CODEC_IP: Lazy<Vec<String>> = Lazy::new(|| {
    let default_codec_ip = vec![
        // US node
        "64.23.159.180".to_string(),
        // Your default proxy server
        SERVER_HOST.clone(),
    ];
    match std::env::var("NEED_CODEC_IP") {
        Ok(v) => {
            let keywords = split_concat_with_default(v, default_codec_ip);
            tracing::info!("`NEED_CODEC_IP` is `{keywords:?}`");
            keywords
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`NEED_CODEC_IP` provided,we use default need codec ip:{default_codec_ip:?}"
            );
            default_codec_ip
        }
    }
});

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};

    use tokio::time::Instant;
    use uni_stream::addr::get_ip_addrs;

    use crate::config::{default_state_dir, proxy_data_dir, runtime};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        value: Option<OsString>,
    }

    impl EnvVarGuard {
        fn preserve(key: &'static str) -> Self {
            Self {
                key,
                value: std::env::var_os(key),
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.value {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::set_var(self.key, value) };
            } else {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn test_ipaddr_parse() {
        let ipaddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(ipaddr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn runtime_upstream_switch_keeps_endpoint_generations_consistent() {
        let original = runtime::server_endpoint();
        runtime::set_server_endpoint("old.example".to_string(), 1081);
        let old = runtime::server_endpoint();

        runtime::set_server_endpoint("new.example".to_string(), 2081);
        let new = runtime::server_endpoint();

        assert_eq!(old.host, "old.example");
        assert_eq!(old.port, 1081);
        assert_eq!(new.host, "new.example");
        assert_eq!(new.port, 2081);
        runtime::set_server_endpoint(original.host.clone(), original.port);
    }

    #[test]
    fn test_proxy_data_dir_override_wins() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvVarGuard::preserve("PROXY_DATA_DIR");

        let custom = std::env::temp_dir().join("proxy-everything-config-test");
        // SAFETY: tests serialize environment mutation with ENV_LOCK.
        unsafe { std::env::set_var("PROXY_DATA_DIR", &custom) };

        assert_eq!(proxy_data_dir(), Some(custom.clone()));
        assert_eq!(default_state_dir(), custom);
    }

    #[test]
    fn test_proxy_data_dir_default_falls_back_to_home_proxy_everything() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvVarGuard::preserve("PROXY_DATA_DIR");

        // SAFETY: tests serialize environment mutation with ENV_LOCK.
        unsafe { std::env::remove_var("PROXY_DATA_DIR") };

        let expected = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".proxy-everything");
        assert_eq!(default_state_dir(), expected);
    }

    #[tokio::test]
    async fn test_dns_resolver() {
        for _ in 1..10 {
            let ins = Instant::now();
            println!("{:?}", get_ip_addrs("yt3.ggpht.com").await.unwrap());
            println!("{:?}", ins.elapsed());
        }
    }
}
