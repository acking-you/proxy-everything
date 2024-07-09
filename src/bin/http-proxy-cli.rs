use clap::Parser;
use http_proxy::client::start_client;
use http_proxy::config::{init_tracing, CLIENT_PORT, DEFAULT_KEY, SERVER_HOST, SERVER_PORT};
use mimalloc_rust::GlobalMiMalloc;
// use serde_derive::Deserialize;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::process::exit;
use toml;


#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Parser)]
#[command(author = "L_B__", version, about, long_about = None)]
struct Cli {
    /// [optional] IP or domain name of the proxy server (port is fixed to 1081)
    // this value is opitonal cuz we may load this from config file.
    #[arg(short, long, value_name = "SERVER_HOST")]
    server_host: Option<String>,
    /// [optional] Port number exposed by the local client agent (uses port 1080 by default)
    #[arg(short, long, value_name = "CLIENT_PORT")]
    client_port: Option<u16>,
    /// [optional] Port number exposed by the proxy server (uses port 1081 by default)
    // remove short cuz server_port share the same prefix '-s' with server_host
    #[arg(long, value_name = "SERVER_PORT")]
    server_port: Option<u16>,
    /// [optional] Keys for symmetric encryption (must be 32 bytes in length, default value is
    /// `my-secret-key123my-secret-key123`)
    #[arg(short, long, value_name = "SECRET_KEY")]
    key: Option<String>,
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
    /// [optional] config file path
    #[arg(long, value_name = "CONFIG_FILE")]
    config_file: Option<String>,
}

// // Top level struct to hold the TOML data.
// #[derive(Deserialize)]
// struct Data {
//     config: Config,
// }

// Config struct holds to data from the `[config]` section.
#[derive(Deserialize)]
struct Config {
    // IP or domain name of the proxy server (port is fixed to 1081)
    server_host: Option<String>,
    // Port number exposed by the local client agent (uses port 1080 by default)
    client_port: Option<u16>,
    // Port number exposed by the proxy server (uses port 1081 by default)
    // remove short cuz server_port share the same prefix '-s' with server_host
    server_port: Option<u16>,
    // Keys for symmetric encryption (must be 32 bytes in length, default value is
    // `my-secret-key123my-secret-key123`)
    key: Option<String>,
    // Keywords-set for identify no proxy
    nonproxy_keywords: Option<String>,
    // Keywords-set for identify proxy
    proxy_keywords: Option<String>,
    // Keywords-set for identify proxy
    need_codec_ip: Option<String>,
    // Enable random key for sending message, default is false
    msg_key: Option<bool>,
}

#[tokio::main]
async fn main() {
    let mut cli: Cli = Cli::parse();
    Some("123").unwrap_or("123");
    let config_file_path = cli.config_file.unwrap_or(
        match std::env::var("HOME") {
            Ok(home) => home + "/.config/proxy_everything.toml",
            Err(_) => {
                eprintln!("Unable to read env $HOME");
                // Exit the program with exit code `1`.
                exit(1);
            }
        });
    let config_file: &Path = Path::new(&config_file_path);

    if fs::metadata(config_file).is_ok() {
        // Read the contents of the file using a `match` block 
        // to return the `data: Ok(c)` as a `String` 
        // or handle any `errors: Err(_)`.
        let config_contents = match fs::read_to_string(&config_file) {
            // If successful return the files text as `contents`.
            // `c` is a local variable.
            Ok(c) => c,
            // Handle the `error` case.
            Err(_) => {
                // Write `msg` to `stderr`.
                eprintln!("Unable to read config from {}", config_file_path);
                // Exit the program with exit code `1`.
                exit(1);
            }
        };

        // Use a `match` block to return the 
        // file `contents` as a `Data struct: Ok(d)`
        // or handle any `errors: Err(_)`.
        let config: Config = match toml::from_str(&config_contents) {
            // If successful, return data as `Data` struct.
            // `d` is a local variable.
            Ok(d) => d,
            // Handle the `error` case.
            Err(e) => {
                // Write `msg` to `stderr`.
                eprintln!("Unable to get config from {}: {}", config_file_path, e);
                // Exit the program with exit code `1`.
                exit(1);
            }
        };

        if let Some(key) = &config.server_host {
            cli.server_host = Some(key.to_owned());
        }
        if let Some(key) = &config.key {
            cli.key = Some(key.to_owned());
        }
        if let Some(key) = &config.nonproxy_keywords {
            cli.nonproxy_keywords = Some(key.to_owned());
        }
        if let Some(key) = &config.proxy_keywords {
            cli.proxy_keywords = Some(key.to_owned());
        }
        if let Some(key) = &config.need_codec_ip {
            cli.need_codec_ip = Some(key.to_owned());
        }
        if let Some(key) = &config.client_port {
            cli.client_port = Some(key.to_owned());
        }
        if let Some(key) = &config.server_port {
            cli.server_port = Some(key.to_owned());
        }
        if let Some(key) = &config.msg_key {
            cli.msg_key = key.to_owned();
        }
    } else {
        tracing::info!("Config file {} does not exist, use args and env only.",
                       config_file_path);
    }

    if let Some(key) = &cli.server_host {
        std::env::set_var("SERVER_HOST", key);
    }
    if let Some(key) = &cli.key {
        std::env::set_var("SECRET_KEY", key);
    }
    if let Some(key) = &cli.nonproxy_keywords {
        std::env::set_var("NONPROXY_KEYWORDS", key);
    }
    if let Some(key) = &cli.proxy_keywords {
        std::env::set_var("PROXY_KEYWORDS", key);
    }
    if let Some(key) = &cli.need_codec_ip {
        std::env::set_var("NEED_CODEC_IP", key)
    }
    if let Some(key) = cli.client_port {
        std::env::set_var("CLIENT_PORT", key.to_string());
    }
    if let Some(key) = cli.server_port {
        std::env::set_var("SERVER_PORT", key.to_string());
    }
    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    tracing::info!("SECRET_KEY:{}", String::from_utf8_lossy(&DEFAULT_KEY.0));
    tracing::info!("CLIENT_PORT:{}", *CLIENT_PORT);
    tracing::info!("SERVER_PORT:{}", *SERVER_PORT);
    if cli.msg_key {
        start_client::<true>("0.0.0.0", *CLIENT_PORT).await.unwrap();
    } else {
        start_client::<false>("0.0.0.0", *CLIENT_PORT)
            .await
            .unwrap();
    }
}
