//! Proxy admin CLI for control plane operations.

use clap::{Parser, Subcommand};
use http_proxy::config::{CONTROL_SESSION_KEY, DEFAULT_SECRET_KEY, SERVER_PORT};
use http_proxy::control::{ControlClient, ControlOp, ControlRequest};
use http_proxy::metrics::{Granularity, TopCategory};
use mimalloc_rust::GlobalMiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: GlobalMiMalloc = GlobalMiMalloc;

#[derive(Parser)]
#[command(author = "L_B__", version, about = "Proxy admin control plane CLI")]
struct Cli {
    /// Proxy server host
    #[arg(short = 'H', long, value_name = "SERVER_HOST")]
    server_host: String,
    /// Proxy server port (default 1081)
    #[arg(short = 'p', long, value_name = "SERVER_PORT", default_value_t = *SERVER_PORT)]
    server_port: u16,
    /// Admin token (if CONTROL_ADMIN_TOKEN is set on server)
    #[arg(short, long, value_name = "TOKEN")]
    token: Option<String>,
    /// Session key for control payload encryption (32 bytes)
    #[arg(short = 'k', long, value_name = "SESSION_KEY")]
    session_key: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ping server
    Ping,
    /// Manage cluster nodes
    Nodes {
        #[command(subcommand)]
        cmd: NodeCommand,
    },
    /// Query metrics
    Metrics {
        #[command(subcommand)]
        cmd: MetricsCommand,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Add node (host:port)
    Add { addr: String },
    /// Remove node by id
    Remove { node_id: String },
    /// List nodes
    List,
}

#[derive(Subcommand)]
enum MetricsCommand {
    /// Get realtime stats
    Realtime,
    /// Get recent connections
    Connections {
        /// Number of connections to fetch
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },
    /// Get time buckets
    Buckets {
        /// Granularity: minute, hour, day
        #[arg(short, long, default_value = "minute")]
        granularity: String,
        /// Number of buckets to fetch
        #[arg(short, long, default_value = "10")]
        count: u32,
    },
    /// Get top-N statistics
    TopN {
        /// Category: ips, hosts
        #[arg(short, long, default_value = "hosts")]
        category: String,
        /// Number of entries to fetch
        #[arg(short, long, default_value = "10")]
        limit: u32,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let session_key = cli
        .session_key
        .or_else(|| (*CONTROL_SESSION_KEY).clone())
        .or_else(|| std::env::var("SECRET_KEY").ok())
        .or_else(|| Some(DEFAULT_SECRET_KEY.to_string()));
    let mut client =
        match ControlClient::connect(&cli.server_host, cli.server_port, session_key).await {
            Ok(client) => client,
            Err(err) => {
                eprintln!("connect error: {err}");
                return;
            }
        };

    let op = match cli.command {
        Command::Ping => ControlOp::Ping,
        Command::Nodes { cmd } => match cmd {
            NodeCommand::Add { addr } => ControlOp::AddNode { addr },
            NodeCommand::Remove { node_id } => ControlOp::RemoveNode { node_id },
            NodeCommand::List => ControlOp::ListNodes,
        },
        Command::Metrics { cmd } => match cmd {
            MetricsCommand::Realtime => ControlOp::GetRealtimeStats,
            MetricsCommand::Connections { limit } => ControlOp::GetRecentConnections { limit },
            MetricsCommand::Buckets { granularity, count } => {
                let granularity = match granularity.to_lowercase().as_str() {
                    "minute" | "m" => Granularity::Minute,
                    "hour" | "h" => Granularity::Hour,
                    "day" | "d" => Granularity::Day,
                    _ => {
                        eprintln!("invalid granularity: {granularity} (use: minute, hour, day)");
                        return;
                    }
                };
                ControlOp::GetTimeBuckets { granularity, count }
            }
            MetricsCommand::TopN { category, limit } => {
                let category = match category.to_lowercase().as_str() {
                    "ips" | "ip" => TopCategory::Ips,
                    "hosts" | "host" => TopCategory::Hosts,
                    _ => {
                        eprintln!("invalid category: {category} (use: ips, hosts)");
                        return;
                    }
                };
                ControlOp::GetTopN { category, limit }
            }
        },
    };

    let request = ControlRequest {
        token: cli.token,
        op,
    };

    match client.request(request).await {
        Ok(response) => match serde_json::to_string_pretty(&response) {
            Ok(output) => println!("{output}"),
            Err(err) => eprintln!("serialize response error: {err}"),
        },
        Err(err) => {
            eprintln!("request error: {err}");
        }
    }
}
