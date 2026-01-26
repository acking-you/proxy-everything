use clap::Parser;
use better_mimalloc_rs::{MiMalloc, MiMallocConfig};
use proxy_core::config::{SERVER_PORT, init_tracing};
use proxy_server::server::start_server;

#[derive(Parser)]
#[command(author = "L_B__", version = "0.1.0")]
struct Cli {
    /// [optional] 0.0.0.0 or 127.0.0.1 (uses 0.0.0.0 by default)
    #[arg(
        short = 'H',
        long,
        value_name = "SERVER_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,
    /// [optional] Port number(uses port 1081 by default)
    #[arg(
        short,
        long,
        value_name = "SERVER_PORT",
        default_value = "1081",
        env = "SERVER_PORT"
    )]
    port: u16,
    /// [optional] When this option is enabled,
    /// the service will perform an additional layer of transparent forwarding to the specified
    /// server.
    #[arg(
        short,
        long,
        value_name = "TURELY_PROXY_SERVER",
        env = "TURELY_PROXY_SERVER"
    )]
    turely_proxy_server: Option<String>,
}

#[global_allocator]
static GLOBAL_ALLOCATOR: MiMalloc = MiMalloc;

fn init_allocator() {
    // Aggressive RSS reclamation: prioritize faster decommit over raw throughput.
    let config = MiMallocConfig {
        eager_commit: Some(false),
        eager_commit_delay: Some(0),
        arena_eager_commit: Some(0),
        purge_decommits: Some(true),
        purge_delay: Some(0),
        arena_purge_mult: Some(1),
        purge_extend_delay: Some(0),
        generic_collect: Some(200),
    };
    MiMalloc::init_with(&config);
}

#[tokio::main]
async fn main() {
    init_allocator();
    let cli = Cli::parse();
    init_tracing();
    unsafe {
        std::env::set_var("SERVER_PORT", cli.port.to_string());
        if let Some(key) = &cli.turely_proxy_server {
            std::env::set_var("TURELY_PROXY_SERVER", key);
        }
    }
    let mode = match &cli.turely_proxy_server {
        Some(upstream) => format!("chain mode -> {}", upstream),
        None => "direct mode".to_string(),
    };
    tracing::info!("Server listening on {}:{} ({})", cli.host, cli.port, mode);
    start_server(cli.host, *SERVER_PORT).await;
}
