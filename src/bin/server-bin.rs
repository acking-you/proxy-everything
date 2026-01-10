use clap::Parser;
use http_proxy::config::{SERVER_PORT, init_tracing, runtime};
use http_proxy::server::start_server;
use mimalloc_rust::GlobalMiMalloc;

#[derive(Parser)]
#[command(author = "L_B__", version = "0.1.0")]
struct Cli {
    /// [optional] 0.0.0.0 or 127.0.0.1 (uses 0.0.0.0 by default)
    #[arg(short = 'H', long, value_name = "SERVER_HOST", default_value = "0.0.0.0")]
    host: String,
    /// [optional] Port number(uses port 1081 by default)
    #[arg(short, long, value_name = "SERVER_PORT", default_value = "1081", env = "SERVER_PORT")]
    port: u16,
    /// [optional] When this option is enabled,
    /// the service will perform an additional layer of transparent forwarding to the specified
    /// server.
    #[arg(short, long, value_name = "TURELY_PROXY_SERVER", env = "TURELY_PROXY_SERVER")]
    turely_proxy_server: Option<String>,
}

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing();
    unsafe {
        std::env::set_var("SERVER_PORT", cli.port.to_string());
        if let Some(key) = &cli.turely_proxy_server {
            std::env::set_var("TURELY_PROXY_SERVER", key);
        }
    }
    runtime::init_from_env();
    let mode = match &cli.turely_proxy_server {
        Some(upstream) => format!("chain mode -> {}", upstream),
        None => "direct mode".to_string(),
    };
    tracing::info!("Server listening on {}:{} ({})", cli.host, cli.port, mode);
    start_server(cli.host, *SERVER_PORT).await;
}
