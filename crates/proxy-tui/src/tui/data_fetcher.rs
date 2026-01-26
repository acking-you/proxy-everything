//! Data fetcher task for TUI.

use std::sync::Arc;

use proxy_core::control::ControlClient;
use proxy_core::geo::query_geo_batch;
use proxy_core::metrics::{Granularity, TopCategory};
use proxy_core::util::error_report;
use tokio::sync::mpsc;

use super::types::{Cli, DataCommand, DataResult, FetchedData};
use super::utils::parse_addr;

pub async fn data_fetcher_task(
    cli: Arc<Cli>,
    session_key: Option<String>,
    mut cmd_rx: mpsc::Receiver<DataCommand>,
    data_tx: mpsc::Sender<Result<DataResult, String>>,
) {
    let mut client: Option<ControlClient> = None;
    // Track current server address (starts with CLI default)
    let mut current_server = format!("{}:{}", cli.server_host, cli.server_port);

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            DataCommand::Shutdown => break,
            DataCommand::Refresh => {
                let result =
                    fetch_data_from_addr(&current_server, &cli.token, &session_key, &mut client)
                        .await;
                if data_tx
                    .send(result.map(|d| DataResult::Data(d, Some(current_server.clone()))))
                    .await
                    .is_err()
                {
                    tracing::warn!("Main loop closed, exiting data fetcher");
                    break;
                }
            }
            DataCommand::AddNode(addr) => {
                let result = add_node(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    &addr,
                )
                .await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data_from_addr(
                        &current_server,
                        &cli.token,
                        &session_key,
                        &mut client,
                    )
                    .await;
                    if data_tx
                        .send(result.map(|d| DataResult::Data(d, Some(current_server.clone()))))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
            }
            DataCommand::RemoveNode(node_id) => {
                let result = remove_node(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    &node_id,
                )
                .await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data_from_addr(
                        &current_server,
                        &cli.token,
                        &session_key,
                        &mut client,
                    )
                    .await;
                    if data_tx
                        .send(result.map(|d| DataResult::Data(d, Some(current_server.clone()))))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
            }
            DataCommand::SwitchServer(addr) => {
                let result = switch_server(&addr, &session_key).await;
                match result {
                    Ok(data) => {
                        client = None;
                        current_server = addr.clone();
                        if data_tx
                            .send(Ok(DataResult::Data(data, Some(addr))))
                            .await
                            .is_err()
                        {
                            tracing::warn!("Main loop closed, exiting data fetcher");
                            break;
                        }
                    }
                    Err(e) => {
                        if data_tx.send(Err(e)).await.is_err() {
                            tracing::warn!("Main loop closed, exiting data fetcher");
                            break;
                        }
                    }
                }
            }
            DataCommand::QueryGeo(ips) => match query_geo_batch(&ips).await {
                Ok(result) => {
                    if data_tx.send(Ok(DataResult::Geo(result))).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Geo query failed: {}", error_report(&e));
                    let msg = format!(
                        "Geo query failed: {}. Try --use-local-geoip for offline lookup.",
                        error_report(&e)
                    );
                    if data_tx.send(Ok(DataResult::GeoError(msg))).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
            },
            DataCommand::CreateGroup { group_id, name } => {
                let result = create_group(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    group_id,
                    name,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::DeleteGroup(group_id) => {
                let result = delete_group(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    group_id,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::AddNodeToGroup { group_id, node_id } => {
                let result = add_node_to_group(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    group_id,
                    node_id,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::RemoveNodeFromGroup { group_id, node_id } => {
                let result = remove_node_from_group(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    group_id,
                    node_id,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::SetRelayEnabled(enabled) => {
                let result = set_relay_enabled(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    enabled,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::AddRelayTarget(target) => {
                let result = add_relay_target(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    target,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::RemoveRelayTarget(index) => {
                let result = remove_relay_target(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    index,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::SetRelayAlgo(algo) => {
                let result =
                    set_relay_algo(&current_server, &cli.token, &session_key, &mut client, algo)
                        .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
            DataCommand::SetRelayConfig(config) => {
                let result = set_relay_config(
                    &current_server,
                    &cli.token,
                    &session_key,
                    &mut client,
                    config,
                )
                .await;
                handle_command_result(
                    result,
                    &current_server,
                    cli.as_ref(),
                    &session_key,
                    &mut client,
                    &data_tx,
                )
                .await;
            }
        }
    }
}

async fn switch_server(addr: &str, session_key: &Option<String>) -> Result<FetchedData, String> {
    let (host, port) = parse_addr(addr)?;
    let mut client = ControlClient::connect(&host, port, session_key.clone())
        .await
        .map_err(|e| e.to_string())?;

    let nodes = client.list_nodes(None).await.map_err(|e| e.to_string())?;
    let groups = client.list_groups(None).await.map_err(|e| e.to_string())?;
    let relay_config = client.get_relay_config(None).await.ok();
    let relay_status = client.get_relay_status(None).await.ok();

    let realtime = client
        .get_realtime_stats(None)
        .await
        .map_err(|e| e.to_string())?;

    let connections = client
        .get_recent_connections(None)
        .await
        .map_err(|e| e.to_string())?;

    let buckets = client
        .get_time_buckets(None, Granularity::Minute)
        .await
        .map_err(|e| e.to_string())?;

    let top_hosts = client
        .get_top_n(None, TopCategory::Hosts)
        .await
        .map_err(|e| e.to_string())?;
    let top_hosts = top_hosts
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    let top_ips = client
        .get_top_n(None, TopCategory::Ips)
        .await
        .map_err(|e| e.to_string())?;
    let top_ips = top_ips
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    Ok(FetchedData {
        nodes,
        groups,
        realtime,
        connections,
        buckets,
        top_hosts,
        top_ips,
        relay_config,
        relay_status,
    })
}

/// Fetch data from a specific server address (reuses connection if available)
async fn fetch_data_from_addr(
    addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
) -> Result<FetchedData, String> {
    let (host, port) = parse_addr(addr)?;

    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let nodes = c
        .list_nodes(token.clone())
        .await
        .map_err(|e| e.to_string())?;
    let groups = c
        .list_groups(token.clone())
        .await
        .map_err(|e| e.to_string())?;
    let relay_config = c.get_relay_config(token.clone()).await.ok();
    let relay_status = c.get_relay_status(token.clone()).await.ok();

    let realtime = c
        .get_realtime_stats(token.clone())
        .await
        .map_err(|e| e.to_string())?;

    let connections = c
        .get_recent_connections(token.clone())
        .await
        .map_err(|e| e.to_string())?;

    let buckets = c
        .get_time_buckets(token.clone(), Granularity::Minute)
        .await
        .map_err(|e| e.to_string())?;

    let top_hosts = c
        .get_top_n(token.clone(), TopCategory::Hosts)
        .await
        .map_err(|e| e.to_string())?;
    let top_hosts = top_hosts
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    let top_ips = c
        .get_top_n(token.clone(), TopCategory::Ips)
        .await
        .map_err(|e| e.to_string())?;
    let top_ips = top_ips
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    *client = Some(c);

    Ok(FetchedData {
        nodes,
        groups,
        realtime,
        connections,
        buckets,
        top_hosts,
        top_ips,
        relay_config,
        relay_status,
    })
}

async fn handle_command_result(
    result: Result<(), String>,
    current_server: &str,
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    data_tx: &mpsc::Sender<Result<DataResult, String>>,
) {
    if let Err(e) = result {
        if data_tx.send(Err(e)).await.is_err() {
            tracing::warn!("Main loop closed, exiting data fetcher");
        }
        return;
    }
    let result = fetch_data_from_addr(current_server, &cli.token, session_key, client).await;
    if data_tx
        .send(result.map(|d| DataResult::Data(d, Some(current_server.to_string()))))
        .await
        .is_err()
    {
        tracing::warn!("Main loop closed, exiting data fetcher");
    }
}

async fn add_node(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    addr: &str,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.add_node(token.clone(), addr.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn remove_node(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    node_id: &str,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.remove_node(token.clone(), node_id.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn create_group(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    group_id: String,
    name: String,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.create_group(token.clone(), group_id, name).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn delete_group(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    group_id: String,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.delete_group(token.clone(), group_id).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn add_node_to_group(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    group_id: String,
    node_id: String,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.add_node_to_group(token.clone(), group_id, node_id).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn remove_node_from_group(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    group_id: String,
    node_id: String,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c
        .remove_node_from_group(token.clone(), group_id, node_id)
        .await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn set_relay_enabled(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    enabled: bool,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.set_relay_enabled(token.clone(), enabled).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn add_relay_target(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    target: proxy_core::relay::UpstreamTarget,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.add_relay_target(token.clone(), target).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn remove_relay_target(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    index: usize,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.remove_relay_target(token.clone(), index).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn set_relay_algo(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    algo: proxy_core::relay::LoadBalanceAlgo,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.set_relay_algo(token.clone(), algo).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn set_relay_config(
    server_addr: &str,
    token: &Option<String>,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    config: proxy_core::relay::RelayConfig,
) -> Result<(), String> {
    let (host, port) = parse_addr(server_addr)?;
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&host, port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.set_relay_config(token.clone(), config).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}
