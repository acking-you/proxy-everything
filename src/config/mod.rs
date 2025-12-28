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

    let mut rng = rand::thread_rng();
    let random_string: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
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

/// Port for connect to proxy server
pub static SERVER_PORT: Lazy<u16> = Lazy::new(|| {
    let default_port = 1081;
    match std::env::var("SERVER_PORT") {
        Ok(port) => match port.parse::<u16>() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("`SERVER_PORT` is invalid port! error:{e}");
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
                tracing::error!("`CLIENT_PORT` is invalid port! error:{e}");
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
                tracing::warn!("`SECRET_KEY` must have 256 bit(32 byte)!. current input key:{k}");
                std::process::exit(1);
            }
            key.to_vec()
        }
        Err(_) => {
            tracing::warn!("No ENV:`SECRET_KEY` provided,we use default key:{default_key}");
            default_key.as_bytes().to_vec()
        }
    };
    let hash = key.iter().fold(0u32, |hash, &byte| {
        hash.wrapping_mul(31).wrapping_add(byte as u32)
    });
    (key, hash)
});

const DEFAULT_WORD: &str = "%DEFAULT%";

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

#[cfg(feature = "auto-proxy")]
pub static NONPROXY_KEYWORDS: Lazy<Vec<String>> = Lazy::new(|| {
    let default_keywords = vec![
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
    ];
    match std::env::var("NONPROXY_KEYWORDS") {
        Ok(k) => {
            let keywords = split_concat_with_default(k, default_keywords);
            tracing::info!("`NONPROXY_KEYWORDS` is `{keywords:?}`");
            keywords
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`NONPROXY_KEYWORDS` provided,we use default keywords:{default_keywords:?}"
            );
            default_keywords
        }
    }
});

#[derive(Debug)]
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

#[cfg(feature = "auto-proxy")]
pub static PROXY_KEYWORDS: Lazy<Vec<ParsedProxyKeyWord>> = Lazy::new(|| {
    let default_keywords = vec![
        "tiktok".to_string(),
        "youtube".to_string(),
        "scholar.google".to_string(),
        // for reddit
        "reddit".to_string(),
        "google".to_string(),
        "chatgpt".to_string(),
        "twitter".to_string(),
        "facebook".to_string(),
        "bilibili.tv".to_string(),
        "github".to_string(),
        "docker".to_string(),
    ];
    match std::env::var("PROXY_KEYWORDS") {
        Ok(k) => {
            let keywords = split_concat_with_default(k, default_keywords);
            tracing::info!("`PROXY_KEYWORDS` is `{keywords:?}`");
            parse_keywords(keywords)
        }
        Err(_) => {
            tracing::info!(
                "No ENV:`PROXY_KEYWORDS` provided,we use default keywords:{default_keywords:?}"
            );
            parse_keywords(default_keywords)
        }
    }
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
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::time::Instant;
    use uni_stream::addr::get_ip_addrs;

    #[test]
    fn test_ipaddr_parse() {
        let ipaddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(ipaddr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
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
