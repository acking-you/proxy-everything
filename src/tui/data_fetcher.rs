//! Data fetcher task for TUI.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::control::ControlClient;
use crate::geo::query_geo_batch;
use crate::metrics::{Granularity, TopCategory};

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
                let result = fetch_data_from_addr(&current_server, &cli.token, &session_key, &mut client).await;
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
                let result = add_node(&current_server, &cli.token, &session_key, &mut client, &addr).await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data_from_addr(&current_server, &cli.token, &session_key, &mut client).await;
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
                let result = remove_node(&current_server, &cli.token, &session_key, &mut client, &node_id).await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data_from_addr(&current_server, &cli.token, &session_key, &mut client).await;
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
                    tracing::error!("Geo query failed: {}", e);
                    let msg = format!(
                        "Geo query failed: {}. Try --use-local-geoip for offline lookup.",
                        e
                    );
                    if data_tx.send(Ok(DataResult::GeoError(msg))).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
            },
        }
    }
}

async fn switch_server(addr: &str, session_key: &Option<String>) -> Result<FetchedData, String> {
    let (host, port) = parse_addr(addr)?;
    let mut client = ControlClient::connect(&host, port, session_key.clone())
        .await
        .map_err(|e| e.to_string())?;

    let nodes = client.list_nodes(None).await.map_err(|e| e.to_string())?;

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
        realtime,
        connections,
        buckets,
        top_hosts,
        top_ips,
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
    let nodes = c.list_nodes(token.clone()).await.map_err(|e| e.to_string())?;

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
        realtime,
        connections,
        buckets,
        top_hosts,
        top_ips,
    })
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
