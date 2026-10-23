use clap::Parser;
use proxy_core::config::{SERVER_PORT, init_tracing};
use proxy_server::server::{QuicListenConfig, start_server_with_quic};

#[derive(Parser)]
#[command(author = "L_B__", version)]
struct Cli {
    /// Additional UDP QUIC listener; TCP remains available on --host/--port.
    #[arg(long, env = "PROXY_QUIC_LISTEN", requires_all = ["quic_cert", "quic_key"])]
    quic_listen: Option<std::net::SocketAddr>,
    /// PEM certificate chain, with a DNS/IP SAN matching the client's node host.
    #[arg(long, env = "PROXY_QUIC_CERT", requires = "quic_listen")]
    quic_cert: Option<std::path::PathBuf>,
    /// PEM private key for the QUIC certificate.
    #[arg(long, env = "PROXY_QUIC_KEY", requires = "quic_listen")]
    quic_key: Option<std::path::PathBuf>,
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

#[tokio::main]
async fn main() -> std::io::Result<()> {
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
    let quic = cli.quic_listen.map(|listen| QuicListenConfig {
        listen,
        certificate: cli.quic_cert.expect("required by clap"),
        private_key: cli.quic_key.expect("required by clap"),
    });
    start_server_with_quic(cli.host, *SERVER_PORT, quic).await
}
