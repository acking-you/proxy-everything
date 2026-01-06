use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use http_proxy::client::start_client;
use http_proxy::config::{CLIENT_PORT, DEFAULT_KEY, SERVER_HOST, SERVER_PORT, init_tracing};
use mimalloc_rust::GlobalMiMalloc;
use serde::Deserialize;
use sysproxy::Sysproxy;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Debug, Deserialize, Default)]
struct Config {
    server_host: Option<String>,
    server_port: Option<u16>,
    client_port: Option<u16>,
    secret_key: Option<String>,
    nonproxy_keywords: Option<Vec<String>>,
    proxy_keywords: Option<Vec<String>>,
    need_codec_ip: Option<Vec<String>>,
    msg_key: Option<bool>,
    reverse_geo: Option<bool>,
    set_system_proxy: Option<bool>,
    /// If true, restore original proxy settings on exit; if false, disable proxy (default: false)
    restore_proxy_on_exit: Option<bool>,
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file '{}'", path.display()))
    }
}

#[derive(Parser)]
#[command(author = "L_B__", version, about, long_about = None)]
struct Cli {
    /// [optional] Path to TOML config file
    #[arg(short = 'f', long, value_name = "CONFIG_FILE")]
    config: Option<PathBuf>,
    /// [optional] IP or domain name of the proxy server
    #[arg(short, long, value_name = "SERVER_HOST")]
    server_host: Option<String>,
    /// [optional] Port number exposed by the local client agent (uses port 1080 by default)
    #[arg(short, long, value_name = "CLIENT_PORT")]
    client_port: Option<u16>,
    /// [optional] Port number exposed by the proxy server (uses port 1081 by default)
    #[arg(short = 'p', long, value_name = "SERVER_PORT")]
    server_port: Option<u16>,
    /// [optional] Keys for symmetric encryption (must be 32 bytes in length)
    #[arg(short = 'k', long = "key", value_name = "SECRET_KEY")]
    secret_key: Option<String>,
    /// [optional] Keywords-set for identify no proxy
    #[arg(long, value_name = "NONPROXY_KEYWORDS")]
    nonproxy_keywords: Option<String>,
    /// [optional] Keywords-set for identify proxy
    #[arg(long, value_name = "PROXY_KEYWORDS")]
    proxy_keywords: Option<String>,
    /// [optional] Keywords-set for identify proxy
    #[arg(long, value_name = "NEED_CODEC_IP")]
    need_codec_ip: Option<String>,
    /// [optional] Enable random key for sending message, default is false
    #[arg(short, long, value_name = "MSG_KEY")]
    msg_key: bool,
    /// [optional] Reverse geo-proxy logic: CN sites use proxy, others direct
    #[arg(long, env = "REVERSE_GEO_PROXY")]
    reverse_geo: bool,
    /// [optional] Set OS system proxy to local client port (Linux/macOS/Windows)
    #[arg(long)]
    set_system_proxy: bool,
}

fn set_system_proxy(port: u16) -> Option<Sysproxy> {
    if !Sysproxy::is_support() {
        tracing::error!("System proxy is not supported on this platform");
        return None;
    }
    let original = match Sysproxy::get_system_proxy() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to get current system proxy: {e}");
            return None;
        }
    };
    let new_proxy = Sysproxy {
        enable: true,
        host: "127.0.0.1".into(),
        port,
        bypass: original.bypass.clone(),
    };
    if let Err(e) = new_proxy.set_system_proxy() {
        tracing::error!("Failed to set system proxy: {e}");
        return None;
    }
    tracing::info!("System proxy set to 127.0.0.1:{port}");
    Some(original)
}

fn disable_system_proxy(original: Sysproxy) {
    let disabled = Sysproxy {
        enable: false,
        host: original.host,
        port: original.port,
        bypass: original.bypass,
    };
    if let Err(e) = disabled.set_system_proxy() {
        tracing::error!("Failed to disable system proxy: {e}");
    } else {
        tracing::info!("System proxy disabled");
    }
}

fn restore_system_proxy(original: Sysproxy) {
    if let Err(e) = original.set_system_proxy() {
        tracing::error!("Failed to restore system proxy: {e}");
    } else {
        tracing::info!("System proxy restored");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = Cli::parse();

    // Load config file if specified
    let config = if let Some(ref path) = cli.config {
        Config::load(path)?
    } else {
        Config::default()
    };

    // Priority: CLI args > config file > env vars > defaults
    let server_host = cli
        .server_host
        .or(config.server_host)
        .or_else(|| std::env::var("SERVER_HOST").ok())
        .context("server_host is required. Use -s/--server-host, config file, or SERVER_HOST env var.")?;

    let msg_key = cli.msg_key || config.msg_key.unwrap_or(false);
    let reverse_geo = cli.reverse_geo || config.reverse_geo.unwrap_or(false);
    let do_set_system_proxy = cli.set_system_proxy || config.set_system_proxy.unwrap_or(false);
    let restore_proxy_on_exit = config.restore_proxy_on_exit.unwrap_or(false);

    // SAFETY: Environment variables are set before any async code runs.
    // The tokio runtime hasn't started yet, so there are no other threads
    // that could race with these set_var calls.
    unsafe {
        std::env::set_var("SERVER_HOST", &server_host);

        if let Some(key) = cli.secret_key.or(config.secret_key) {
            std::env::set_var("SECRET_KEY", key);
        }
        if let Some(keywords) = cli
            .nonproxy_keywords
            .or_else(|| config.nonproxy_keywords.map(|v| v.join(",")))
        {
            std::env::set_var("NONPROXY_KEYWORDS", keywords);
        }
        if let Some(keywords) = cli
            .proxy_keywords
            .or_else(|| config.proxy_keywords.map(|v| v.join(",")))
        {
            std::env::set_var("PROXY_KEYWORDS", keywords);
        }
        if let Some(ips) = cli
            .need_codec_ip
            .or_else(|| config.need_codec_ip.map(|v| v.join(",")))
        {
            std::env::set_var("NEED_CODEC_IP", ips);
        }
        if let Some(port) = cli.client_port.or(config.client_port) {
            std::env::set_var("CLIENT_PORT", port.to_string());
        }
        if let Some(port) = cli.server_port.or(config.server_port) {
            std::env::set_var("SERVER_PORT", port.to_string());
        }
        if reverse_geo {
            std::env::set_var("REVERSE_GEO_PROXY", "true");
        }
    }

    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    tracing::info!("SECRET_KEY:{}", String::from_utf8_lossy(&DEFAULT_KEY.0));
    tracing::info!("CLIENT_PORT:{}", *CLIENT_PORT);
    tracing::info!("SERVER_PORT:{}", *SERVER_PORT);

    let original_proxy = if do_set_system_proxy {
        set_system_proxy(*CLIENT_PORT)
    } else {
        None
    };

    if msg_key {
        start_client::<true>("0.0.0.0", *CLIENT_PORT).await.unwrap();
    } else {
        start_client::<false>("0.0.0.0", *CLIENT_PORT)
            .await
            .unwrap();
    }

    if let Some(original) = original_proxy {
        if restore_proxy_on_exit {
            restore_system_proxy(original);
        } else {
            disable_system_proxy(original);
        }
    }

    Ok(())
}
