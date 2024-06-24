use clap::Parser;
use http_proxy::client::start_client;
use http_proxy::config::{init_tracing, CLIENT_PORT, DEFAULT_KEY, SERVER_HOST, SERVER_PORT};
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Parser)]
#[command(author = "L_B__", version, about, long_about = None)]
struct Cli {
    /// [required] IP or domain name of the proxy server (port is fixed to 1081)
    #[arg(short, long, value_name = "SERVER_HOST")]
    server_host: String,
    /// [optional] Port number exposed by the local client agent (uses port 1080 by default)
    #[arg(short, long, value_name = "CLIENT_PORT")]
    client_port: Option<u16>,
    /// [optional] Port number exposed by the proxy server (uses port 1081 by default)
    #[arg(short, long, value_name = "SERVER_PORT")]
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
}

#[tokio::main]
async fn main() {
    let cli: Cli = Cli::parse();
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
