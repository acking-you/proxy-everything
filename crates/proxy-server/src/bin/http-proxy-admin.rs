use std::process::ExitCode;

use anyhow::{Result, anyhow, bail};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use proxy_core::config::DEFAULT_SECRET_KEY;
use proxy_core::control::{ControlClient, ControlResponse, ControlResult, TopNEntry};
use proxy_core::metrics::{
    ConnectionRecord, Granularity, RealtimeSnapshot, TimeBucket, TopCategory,
};
use proxy_core::nodes::{NodeGroup, NodeInfo};
use proxy_core::relay::{LoadBalanceAlgo, RelayConfig, RelayStatus, UpstreamTarget};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Proxy server admin CLI",
    arg_required_else_help = true
)]
struct Cli {
    /// Proxy server host
    #[arg(short = 'H', long = "server-host", default_value = "127.0.0.1")]
    server_host: String,
    /// Proxy server port
    #[arg(short = 'p', long = "server-port", default_value_t = 1081)]
    server_port: u16,
    /// Admin token (optional)
    #[arg(short = 't', long, env = "CONTROL_ADMIN_TOKEN")]
    token: Option<String>,
    /// Control session key (defaults to CONTROL_SESSION_KEY, SECRET_KEY, then built-in default)
    #[arg(short = 'k', long = "session-key", env = "CONTROL_SESSION_KEY")]
    session_key: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Ping,
    Nodes {
        #[command(subcommand)]
        command: NodesCommand,
    },
    Groups {
        #[command(subcommand)]
        command: GroupsCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    Metrics {
        #[command(subcommand)]
        command: MetricsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum NodesCommand {
    List,
    Add { addr: String },
    Remove { node_id: String },
}

#[derive(Subcommand, Debug)]
enum GroupsCommand {
    List,
    Create {
        #[arg(long = "id")]
        id: String,
        #[arg(long)]
        name: String,
    },
    Delete {
        #[arg(long = "id")]
        id: String,
    },
    AddNode {
        #[arg(long = "group-id")]
        group_id: String,
        #[arg(long = "node-id")]
        node_id: String,
    },
    RemoveNode {
        #[arg(long = "group-id")]
        group_id: String,
        #[arg(long = "node-id")]
        node_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    Get,
    Status,
    Enable,
    Disable,
    AddTarget(AddRelayTargetArgs),
    RemoveTarget {
        #[arg(long)]
        index: usize,
    },
    SetAlgo {
        #[arg(long)]
        algo: AlgoArg,
    },
}

#[derive(Subcommand, Debug)]
enum MetricsCommand {
    Realtime,
    Connections {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Buckets {
        #[arg(long)]
        granularity: GranularityArg,
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
    TopN {
        #[arg(long)]
        category: TopCategoryArg,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(["addr", "group_id", "node_id", "proxy_url"])
))]
struct AddRelayTargetArgs {
    #[arg(long)]
    addr: Option<String>,
    #[arg(long = "group-id")]
    group_id: Option<String>,
    #[arg(long = "node-id")]
    node_id: Option<String>,
    #[arg(long = "proxy-url")]
    proxy_url: Option<String>,
    #[arg(long, default_value_t = 1)]
    weight: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AlgoArg {
    RoundRobin,
    Random,
    Weighted,
    LeastConn,
}

impl From<AlgoArg> for LoadBalanceAlgo {
    fn from(value: AlgoArg) -> Self {
        match value {
            AlgoArg::RoundRobin => Self::RoundRobin,
            AlgoArg::Random => Self::Random,
            AlgoArg::Weighted => Self::Weighted,
            AlgoArg::LeastConn => Self::LeastConn,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GranularityArg {
    Minute,
    Hour,
    Day,
    M,
    H,
    D,
}

impl From<GranularityArg> for Granularity {
    fn from(value: GranularityArg) -> Self {
        match value {
            GranularityArg::Minute | GranularityArg::M => Self::Minute,
            GranularityArg::Hour | GranularityArg::H => Self::Hour,
            GranularityArg::Day | GranularityArg::D => Self::Day,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TopCategoryArg {
    Hosts,
    Host,
    Ips,
    Ip,
}

impl From<TopCategoryArg> for TopCategory {
    fn from(value: TopCategoryArg) -> Self {
        match value {
            TopCategoryArg::Hosts | TopCategoryArg::Host => Self::Hosts,
            TopCategoryArg::Ips | TopCategoryArg::Ip => Self::Ips,
        }
    }
}

fn resolve_session_key(cli: &Cli) -> String {
    cli.session_key
        .clone()
        .or_else(|| std::env::var("SECRET_KEY").ok())
        .unwrap_or_else(|| DEFAULT_SECRET_KEY.to_string())
}

fn ack_response() -> ControlResponse {
    success_response(ControlResult::Ack)
}

fn success_response(result: ControlResult) -> ControlResponse {
    ControlResponse {
        ok: true,
        error: None,
        result: Some(result),
    }
}

fn error_response(error: impl ToString) -> ControlResponse {
    ControlResponse {
        ok: false,
        error: Some(error.to_string()),
        result: None,
    }
}

fn print_response(response: &ControlResponse) {
    println!(
        "{}",
        serde_json::to_string(response).expect("serialize control response")
    );
}

fn add_relay_target(args: AddRelayTargetArgs) -> Result<UpstreamTarget> {
    if let Some(group_id) = args.group_id {
        if args.weight != 1 {
            bail!("group relay targets do not support --weight");
        }
        return Ok(UpstreamTarget::group_ref(group_id));
    }
    if let Some(addr) = args.addr {
        return Ok(UpstreamTarget::node_weighted(addr, args.weight));
    }
    if let Some(node_id) = args.node_id {
        return Ok(UpstreamTarget::NodeRef {
            node_id,
            weight: args.weight,
        });
    }
    if let Some(proxy_url) = args.proxy_url {
        return Ok(UpstreamTarget::external_proxy(proxy_url, args.weight));
    }
    Err(anyhow!("missing relay target"))
}

/// Reject a host that cannot be one, instead of dialing it and timing out.
///
/// A quoted or variable-expanded invocation collapses several arguments into
/// one, so `-H "$HOST_AND_PORT"` arrives as a single host like
/// `10.0.0.1 -p 1081`. Connecting to that name fails after the full connect
/// timeout with nothing but "Connection timeout", which reads as a network or
/// server problem and sends the reader looking in the wrong place entirely.
fn validate_server_host(host: &str) -> Result<()> {
    if host.trim().is_empty() {
        bail!("--server-host is empty");
    }
    if let Some(embedded) = host.split_whitespace().nth(1) {
        bail!(
            "--server-host contains whitespace: {host:?}. This usually means several arguments \
             were passed as one, for example `-H \"$H\"` where H holds `host -p port`. Pass each \
             flag separately: -H <host> -p <port> (saw {embedded:?} inside the host)"
        );
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<ControlResponse> {
    validate_server_host(&cli.server_host)?;
    let session_key = resolve_session_key(&cli);
    let mut client =
        ControlClient::connect(&cli.server_host, cli.server_port, Some(session_key)).await?;
    let token = cli.token.clone();

    match cli.command {
        Command::Ping => client.ping(token).await.map_err(Into::into),
        Command::Nodes { command } => match command {
            NodesCommand::List => {
                let nodes: Vec<NodeInfo> = client.list_nodes(token).await?;
                Ok(success_response(ControlResult::Nodes { nodes }))
            }
            NodesCommand::Add { addr } => {
                client.add_node(token, addr).await?;
                Ok(ack_response())
            }
            NodesCommand::Remove { node_id } => {
                client.remove_node(token, node_id).await?;
                Ok(ack_response())
            }
        },
        Command::Groups { command } => match command {
            GroupsCommand::List => {
                let groups: Vec<NodeGroup> = client.list_groups(token).await?;
                Ok(success_response(ControlResult::Groups { groups }))
            }
            GroupsCommand::Create { id, name } => {
                client.create_group(token, id, name).await?;
                Ok(ack_response())
            }
            GroupsCommand::Delete { id } => {
                client.delete_group(token, id).await?;
                Ok(ack_response())
            }
            GroupsCommand::AddNode { group_id, node_id } => {
                client.add_node_to_group(token, group_id, node_id).await?;
                Ok(ack_response())
            }
            GroupsCommand::RemoveNode { group_id, node_id } => {
                client
                    .remove_node_from_group(token, group_id, node_id)
                    .await?;
                Ok(ack_response())
            }
        },
        Command::Relay { command } => match command {
            RelayCommand::Get => {
                let config: RelayConfig = client.get_relay_config(token).await?;
                Ok(success_response(ControlResult::RelayConfig { config }))
            }
            RelayCommand::Status => {
                let status: RelayStatus = client.get_relay_status(token).await?;
                Ok(success_response(ControlResult::RelayStatus { status }))
            }
            RelayCommand::Enable => {
                client.set_relay_enabled(token, true).await?;
                Ok(ack_response())
            }
            RelayCommand::Disable => {
                client.set_relay_enabled(token, false).await?;
                Ok(ack_response())
            }
            RelayCommand::AddTarget(args) => {
                let target = add_relay_target(args)?;
                client.add_relay_target(token, target).await?;
                Ok(ack_response())
            }
            RelayCommand::RemoveTarget { index } => {
                client.remove_relay_target(token, index).await?;
                Ok(ack_response())
            }
            RelayCommand::SetAlgo { algo } => {
                client.set_relay_algo(token, algo.into()).await?;
                Ok(ack_response())
            }
        },
        Command::Metrics { command } => match command {
            MetricsCommand::Realtime => {
                let stats: Option<RealtimeSnapshot> = client.get_realtime_stats(token).await?;
                let stats = stats.unwrap_or(RealtimeSnapshot {
                    active_connections: 0,
                    cpu_percent: 0.0,
                    memory_bytes: 0,
                    uptime_secs: 0,
                    sys_cpu_percent: 0.0,
                    sys_memory_used: 0,
                    sys_memory_total: 0,
                    sys_net_recv_bytes: 0,
                    sys_net_sent_bytes: 0,
                    sys_net_recv_rate: 0,
                    sys_net_sent_rate: 0,
                    sys_disk_used: 0,
                    sys_disk_total: 0,
                });
                Ok(success_response(ControlResult::RealtimeStats { stats }))
            }
            MetricsCommand::Connections { limit } => {
                let mut connections: Vec<ConnectionRecord> =
                    client.get_recent_connections(token).await?;
                connections.truncate(limit);
                Ok(success_response(ControlResult::Connections { connections }))
            }
            MetricsCommand::Buckets { granularity, count } => {
                let mut buckets: Vec<TimeBucket> =
                    client.get_time_buckets(token, granularity.into()).await?;
                buckets.truncate(count);
                Ok(success_response(ControlResult::TimeBuckets { buckets }))
            }
            MetricsCommand::TopN { category, limit } => {
                let mut entries: Vec<TopNEntry> = client.get_top_n(token, category.into()).await?;
                entries.truncate(limit);
                Ok(success_response(ControlResult::TopN { entries }))
            }
        },
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let response = match run(cli).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    };
    let success = response.ok;
    print_response(&response);
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_hosts_and_addresses_are_accepted() {
        assert!(validate_server_host("127.0.0.1").is_ok());
        assert!(validate_server_host("lb7666.top").is_ok());
    }

    #[test]
    fn a_host_holding_extra_arguments_is_rejected_before_dialing() {
        // The shape produced by `-H "$VAR"` when VAR holds host and port. Left
        // unchecked this only surfaces as a connect timeout, which looks like a
        // server or network fault rather than a quoting mistake.
        let error = validate_server_host("43.161.216.219 -p 1081").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("passed as one"));
        assert!(message.contains("-H <host> -p <port>"));
    }

    #[test]
    fn an_empty_host_is_rejected() {
        assert!(validate_server_host("   ").is_err());
    }
}
