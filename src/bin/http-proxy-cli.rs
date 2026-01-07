use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::style::Stylize;
use http_proxy::client::start_client;
use http_proxy::config::{CLIENT_PORT, SERVER_HOST, SERVER_PORT, init_tracing};
use mimalloc_rust::GlobalMiMalloc;
use serde::{Deserialize, Serialize};
use sysproxy::Sysproxy;

const CONFIG_FILE_NAME: &str = "config.toml";
const DATA_DIR_NAME: &str = "http-proxy-cli-config";
/// Default config template embedded at compile time from config.template.toml
const DEFAULT_CONFIG_TEMPLATE: &str = include_str!("../../config.template.toml");

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Debug, Deserialize, Serialize, Default)]
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
    restore_proxy_on_exit: Option<bool>,
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file '{}'", path.display()))
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file '{}'", path.display()))
    }

    /// Create config from CLI args (only non-default values)
    fn from_cli(cli: &Cli) -> Self {
        Self {
            server_host: cli.server_host.clone(),
            server_port: cli.server_port,
            client_port: cli.client_port,
            secret_key: cli.secret_key.clone(),
            nonproxy_keywords: cli.nonproxy_keywords.as_ref().map(|s| s.split(',').map(String::from).collect()),
            proxy_keywords: cli.proxy_keywords.as_ref().map(|s| s.split(',').map(String::from).collect()),
            need_codec_ip: cli.need_codec_ip.as_ref().map(|s| s.split(',').map(String::from).collect()),
            msg_key: if cli.msg_key { Some(true) } else { None },
            reverse_geo: if cli.reverse_geo { Some(true) } else { None },
            set_system_proxy: if cli.set_system_proxy { Some(true) } else { None },
            restore_proxy_on_exit: None,
        }
    }

    /// Check if CLI has any meaningful args
    fn cli_has_args(cli: &Cli) -> bool {
        cli.server_host.is_some()
            || cli.server_port.is_some()
            || cli.client_port.is_some()
            || cli.secret_key.is_some()
            || cli.msg_key
            || cli.reverse_geo
            || cli.set_system_proxy
    }
}

/// Get the directory where the executable is located
fn get_exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

/// Get home directory
fn get_home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// Get data directory: ~/http-proxy-cli/
fn get_data_dir() -> Result<PathBuf> {
    let home = get_home_dir().context("Failed to get home directory")?;
    let data_dir = home.join(DATA_DIR_NAME);
    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data directory '{}'", data_dir.display()))?;
    }
    Ok(data_dir)
}

/// Find config file: exe dir > data dir
fn find_config() -> Option<PathBuf> {
    // 1. Check exe directory
    if let Some(exe_dir) = get_exe_dir() {
        let config_path = exe_dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            return Some(config_path);
        }
    }

    // 2. Check data directory ~/http-proxy-cli/
    if let Ok(data_dir) = get_data_dir() {
        let config_path = data_dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            return Some(config_path);
        }
    }

    None
}

/// Get default config path (data dir)
fn get_default_config_path() -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    Ok(data_dir.join(CONFIG_FILE_NAME))
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
    /// [optional] Use local GeoIP database instead of ip-api.com API
    #[arg(long, env = "USE_LOCAL_GEOIP")]
    use_local_geoip: bool,
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

    // Load config based on scenario:
    // 1. -f specified: use that file
    // 2. Config exists: load it
    // 3. CLI has args: save args to config and run
    // 4. No config, no args: generate template and exit
    let config = if let Some(ref path) = cli.config {
        Config::load(path)?
    } else if let Some(path) = find_config() {
        Config::load(&path)?
    } else if Config::cli_has_args(&cli) {
        // Save CLI args to config file
        let config = Config::from_cli(&cli);
        let config_path = get_default_config_path()?;
        config.save(&config_path)?;
        eprintln!("Config saved to: {}", config_path.display());
        config
    } else {
        // No config, no args: generate template
        let config_path = get_default_config_path()?;
        std::fs::write(&config_path, DEFAULT_CONFIG_TEMPLATE)
            .with_context(|| format!("Failed to create config at '{}'", config_path.display()))?;
        eprintln!();
        eprintln!("  {}", "Welcome to HTTP Proxy CLI!".cyan().bold());
        eprintln!();
        eprintln!("  Config created: {}", config_path.display().to_string().white());
        eprintln!("  Please edit and set {}, then run again.", "server_host".yellow());
        eprintln!();
        return Ok(());
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
        if cli.use_local_geoip {
            std::env::set_var("USE_LOCAL_GEOIP", "true");
        }
    }

    // Check if secret key is configured (not using default)
    let secret_key_configured = std::env::var("SECRET_KEY").is_ok();

    // Check if config is valid (server_host is not template default)
    let config_valid = server_host != "your-server.com" && !server_host.is_empty();

    init_tracing();

    // Force lazy statics to initialize (triggers WARN logs before banner)
    let client_port = *CLIENT_PORT;
    let server_port = *SERVER_PORT;
    let remote_server = SERVER_HOST.clone();

    // Print startup banner
    eprintln!();
    let title = if config_valid {
        "HTTP Proxy CLI Started".green().bold()
    } else {
        "HTTP Proxy CLI Started (Invalid Config)".red().bold()
    };
    eprintln!("  {}", title);
    eprintln!("{}", "─".repeat(50).dark_grey());
    eprintln!("  {:16} {}:{}", "Local Proxy".dark_grey(), "127.0.0.1".white(), client_port.to_string().cyan());
    eprintln!("  {:16} {}:{}", "Remote Server".dark_grey(), remote_server.clone().white(), server_port.to_string().cyan());
    eprintln!("  {:16} {}", "Secret Key".dark_grey(), if secret_key_configured { "configured".green() } else { "default (insecure)".red() });
    eprintln!("  {:16} {}", "Reverse Geo".dark_grey(), if reverse_geo { "enabled".green() } else { "disabled".dark_grey() });
    eprintln!("  {:16} {}", "System Proxy".dark_grey(), if do_set_system_proxy { "enabled".green() } else { "disabled".dark_grey() });
    eprintln!("{}", "─".repeat(50).dark_grey());
    eprintln!();

    if !config_valid {
        eprintln!("{} {}", "WARNING:".yellow().bold(), "server_host not configured properly!");
        eprintln!("  Please edit your config file and set a valid server_host.");
        eprintln!("  Config location: {}", "~/http-proxy-cli-config/config.toml".white());
        return Ok(());
    }

    let original_proxy = if do_set_system_proxy {
        set_system_proxy(client_port)
    } else {
        None
    };

    if msg_key {
        start_client::<true>("0.0.0.0", client_port).await.unwrap();
    } else {
        start_client::<false>("0.0.0.0", client_port)
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
