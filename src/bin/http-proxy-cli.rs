use http_proxy::client::{start_client, CLIENT_PORT, SERVER_HOST};
use http_proxy::{init_tracing, DEFAULT_KEY};

use clap::Parser;

#[derive(Parser)]
#[command(author = "L_B__", version, about, long_about = None)]
struct Cli {
    /// [required] IP or domain name of the proxy server (port is fixed to 1081)
    #[arg(short, long, value_name = "SERVER_HOST")]
    server_host: String,
    /// [optional] Port number exposed by the local client agent (uses port 1080 by default)
    #[arg(short, long, value_name = "CLIENT_PORT")]
    port: Option<u16>,
    /// [optional] Keys for symmetric encryption (must be 32 bytes in length, default value is `my-secret-key123my-secret-key123`)
    #[arg(short, long, value_name = "SECRET_KEY")]
    key: Option<String>,
    /// [optional] Keywords-set for identify no proxy
    #[arg(long, value_name = "NONPROXY_KEYWORDS")]
    nonproxy_keywords: Option<String>,
    /// [optional] Keywords-set for identify proxy
    #[arg(long, value_name = "PROXY_KEYWORDS")]
    proxy_keywords: Option<String>,
    ///[optional] Enable random key for sending message, default is false
    #[arg(short, long, value_name = "MSG_KEY")]
    msg_key: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    std::env::set_var("SERVER_HOST", &cli.server_host);
    if let Some(key) = &cli.key {
        std::env::set_var("SECRET_KEY", key);
    }
    if let Some(key) = &cli.nonproxy_keywords {
        std::env::set_var("NONPROXY_KEYWORDS", key);
    }
    if let Some(key) = &cli.proxy_keywords {
        std::env::set_var("PROXY_KEYWORDS", key);
    }
    let port = match cli.port {
        Some(p) => p,
        None => CLIENT_PORT,
    };
    init_tracing();
    tracing::info!("SERVER_HOST:{}", *SERVER_HOST);
    tracing::info!("SECRET_KEY:{}", String::from_utf8_lossy(&DEFAULT_KEY.0));
    if cli.msg_key {
        start_client::<true>("0.0.0.0", port).await;
    } else {
        start_client::<false>("0.0.0.0", port).await;
    }
}
