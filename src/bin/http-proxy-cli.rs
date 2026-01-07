use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use comfy_table::{Cell, Color, Table, presets};
use http_proxy::cli_config::{
    Config, DEFAULT_CONFIG_TEMPLATE, SystemProxyGuard, find_config, get_default_config_path,
};
use http_proxy::client::start_client;
use http_proxy::config::{CLIENT_PORT, SERVER_HOST, SERVER_PORT, init_tracing};
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

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

impl Cli {
    /// Create config from CLI args (only non-default values)
    fn to_config(&self) -> Config {
        Config {
            server_host: self.server_host.clone(),
            server_port: self.server_port,
            client_port: self.client_port,
            secret_key: self.secret_key.clone(),
            nonproxy_keywords: self
                .nonproxy_keywords
                .as_ref()
                .map(|s| s.split(',').map(String::from).collect()),
            proxy_keywords: self
                .proxy_keywords
                .as_ref()
                .map(|s| s.split(',').map(String::from).collect()),
            need_codec_ip: self
                .need_codec_ip
                .as_ref()
                .map(|s| s.split(',').map(String::from).collect()),
            msg_key: if self.msg_key { Some(true) } else { None },
            reverse_geo: if self.reverse_geo { Some(true) } else { None },
            use_local_geoip: if self.use_local_geoip { Some(true) } else { None },
            set_system_proxy: if self.set_system_proxy {
                Some(true)
            } else {
                None
            },
        }
    }

    /// Check if CLI has any meaningful args
    fn has_args(&self) -> bool {
        self.server_host.is_some()
            || self.server_port.is_some()
            || self.client_port.is_some()
            || self.secret_key.is_some()
            || self.msg_key
            || self.reverse_geo
            || self.set_system_proxy
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
    } else if cli.has_args() {
        // Save CLI args to config file
        let config = cli.to_config();
        let config_path = get_default_config_path()?;
        config.save(&config_path)?;
        eprintln!("Config saved to: {}", config_path.display());
        config
    } else {
        // No config, no args: generate template
        let config_path = get_default_config_path()?;
        std::fs::write(&config_path, DEFAULT_CONFIG_TEMPLATE)
            .with_context(|| format!("Failed to create config at '{}'", config_path.display()))?;

        let mut table = Table::new();
        table.load_preset(presets::UTF8_BORDERS_ONLY);
        table.set_header(vec![
            Cell::new("Welcome to HTTP Proxy CLI!").fg(Color::Cyan),
        ]);
        table.add_row(vec![format!("Config created: {}", config_path.display())]);
        table.add_row(vec!["Please edit and set server_host, then run again."]);
        eprintln!("\n{table}\n");
        return Ok(());
    };

    // Priority: CLI args > config file > env vars > defaults
    let server_host = cli
        .server_host
        .or(config.server_host)
        .or_else(|| std::env::var("SERVER_HOST").ok())
        .context(
            "server_host is required. Use -s/--server-host, config file, or SERVER_HOST env var.",
        )?;

    let msg_key = cli.msg_key || config.msg_key.unwrap_or(false);
    let reverse_geo = cli.reverse_geo || config.reverse_geo.unwrap_or(false);
    let do_set_system_proxy = cli.set_system_proxy || config.set_system_proxy.unwrap_or(false);

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
        if cli.use_local_geoip || config.use_local_geoip.unwrap_or(false) {
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
    let title = if config_valid {
        Cell::new("HTTP Proxy CLI Started").fg(Color::Green)
    } else {
        Cell::new("HTTP Proxy CLI Started (Invalid Config)").fg(Color::Red)
    };

    let status_cell = |enabled: bool| -> Cell {
        if enabled {
            Cell::new("enabled").fg(Color::Green)
        } else {
            Cell::new("disabled").fg(Color::DarkGrey)
        }
    };

    let mut table = Table::new();
    table.load_preset(presets::UTF8_FULL);
    table.set_header(vec![title, Cell::new("")]);
    table.add_row(vec![
        Cell::new("Local Proxy"),
        Cell::new(format!("127.0.0.1:{}", client_port)).fg(Color::Cyan),
    ]);
    table.add_row(vec![
        Cell::new("Remote Server"),
        Cell::new(format!("{}:{}", remote_server, server_port)).fg(Color::Cyan),
    ]);
    table.add_row(vec![
        Cell::new("Secret Key"),
        if secret_key_configured {
            Cell::new("configured").fg(Color::Green)
        } else {
            Cell::new("default (insecure)").fg(Color::Red)
        },
    ]);
    table.add_row(vec![Cell::new("Reverse Geo"), status_cell(reverse_geo)]);
    table.add_row(vec![
        Cell::new("System Proxy"),
        status_cell(do_set_system_proxy),
    ]);
    eprintln!("\n{table}\n");

    if !config_valid {
        let mut warn_table = Table::new();
        warn_table.load_preset(presets::UTF8_HORIZONTAL_ONLY);
        warn_table.set_header(vec![Cell::new("⚠ WARNING").fg(Color::Yellow)]);
        warn_table.add_row(vec!["server_host not configured properly!"]);
        warn_table.add_row(vec![
            "Please edit your config file and set a valid server_host.",
        ]);
        warn_table.add_row(vec!["Config location: ~/http-proxy-cli-config/config.toml"]);
        eprintln!("{warn_table}\n");
        return Ok(());
    }

    // RAII: proxy is disabled automatically when _guard is dropped
    let _guard = if do_set_system_proxy {
        SystemProxyGuard::new(client_port)
    } else {
        None
    };

    if msg_key {
        start_client::<true>("0.0.0.0", client_port).await.unwrap();
    } else {
        start_client::<false>("0.0.0.0", client_port).await.unwrap();
    }

    Ok(())
}
