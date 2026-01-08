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

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            DataCommand::Shutdown => break,
            DataCommand::Refresh => {
                let result = fetch_data(&cli, &session_key, &mut client).await;
                if data_tx
                    .send(result.map(|d| DataResult::Data(d, None)))
                    .await
                    .is_err()
                {
                    tracing::warn!("Main loop closed, exiting data fetcher");
                    break;
                }
            }
            DataCommand::AddNode(addr) => {
                let result = add_node(&cli, &session_key, &mut client, &addr).await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data(&cli, &session_key, &mut client).await;
                    if data_tx
                        .send(result.map(|d| DataResult::Data(d, None)))
                        .await
                        .is_err()
                    {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                }
            }
            DataCommand::RemoveNode(node_id) => {
                let result = remove_node(&cli, &session_key, &mut client, &node_id).await;
                if let Err(e) = result {
                    if data_tx.send(Err(e)).await.is_err() {
                        tracing::warn!("Main loop closed, exiting data fetcher");
                        break;
                    }
                } else {
                    let result = fetch_data(&cli, &session_key, &mut client).await;
                    if data_tx
                        .send(result.map(|d| DataResult::Data(d, None)))
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
                        if data_tx.send(Ok(DataResult::Data(data, Some(addr)))).await.is_err() {
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

async fn fetch_data(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
) -> Result<FetchedData, String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    match fetch_data_inner(cli, c).await {
        Ok((data, c)) => {
            *client = Some(c);
            Ok(data)
        }
        Err(e) => Err(e),
    }
}

async fn fetch_data_inner(
    cli: &Cli,
    mut client: ControlClient,
) -> Result<(FetchedData, ControlClient), String> {
    let nodes = client
        .list_nodes(cli.token.clone())
        .await
        .map_err(|e| e.to_string())?;

    let realtime = client
        .get_realtime_stats(cli.token.clone())
        .await
        .map_err(|e| e.to_string())?;

    let connections = client
        .get_recent_connections(cli.token.clone())
        .await
        .map_err(|e| e.to_string())?;

    let buckets = client
        .get_time_buckets(cli.token.clone(), Granularity::Minute)
        .await
        .map_err(|e| e.to_string())?;

    let top_hosts = client
        .get_top_n(cli.token.clone(), TopCategory::Hosts)
        .await
        .map_err(|e| e.to_string())?;
    let top_hosts = top_hosts
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    let top_ips = client
        .get_top_n(cli.token.clone(), TopCategory::Ips)
        .await
        .map_err(|e| e.to_string())?;
    let top_ips = top_ips
        .into_iter()
        .map(|e| (e.key, e.stats.bytes_up + e.stats.bytes_down))
        .collect();

    let data = FetchedData {
        nodes,
        realtime,
        connections,
        buckets,
        top_hosts,
        top_ips,
    };

    Ok((data, client))
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

async fn add_node(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    addr: &str,
) -> Result<(), String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.add_node(cli.token.clone(), addr.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}

async fn remove_node(
    cli: &Cli,
    session_key: &Option<String>,
    client: &mut Option<ControlClient>,
    node_id: &str,
) -> Result<(), String> {
    let c = match client.take() {
        Some(c) => c,
        None => ControlClient::connect(&cli.server_host, cli.server_port, session_key.clone())
            .await
            .map_err(|e| e.to_string())?,
    };

    let mut c = c;
    let result = c.remove_node(cli.token.clone(), node_id.to_string()).await;
    *client = Some(c);
    result.map_err(|e| e.to_string())
}
