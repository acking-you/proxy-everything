use clap::Parser;
use http_proxy::config::{init_tracing, SERVER_PORT};
use http_proxy::server::start_server;
use mimalloc_rust::GlobalMiMalloc;

#[derive(Parser)]
#[command(author = "L_B__", version = "0.1.0")]
struct Cli {
    /// [optional] 0.0.0.0 or 127.0.0.1 (uses 0.0.0.0 by default)
    #[arg(short, long, value_name = "SERVER_HOST", default_value = "0.0.0.0")]
    host: String,
    /// [optional] Port number(uses port 1081 by default)
    #[arg(short, long, value_name = "SERVER_PORT", default_value = "1081")]
    port: u16,
    /// [optional] When this option is enabled,
    /// the service will perform an additional layer of transparent forwarding to the specified
    /// server.
    #[arg(
        short,
        long,
        value_name = "TURELY_PROXY_SERVER",
        default_value = "None"
    )]
    turely_proxy_server: Option<String>,
}

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing();
    std::env::set_var("SERVER_PORT", cli.port.to_string());
    if let Some(key) = &cli.turely_proxy_server {
        std::env::set_var("TURELY_PROXY_SERVER", key);
    }
    tracing::info!(
        "Start Listening: {}:{} with truly proxy server:{:?}",
        cli.host,
        cli.port,
        cli.turely_proxy_server
    );
    start_server(cli.host, *SERVER_PORT).await;
}
