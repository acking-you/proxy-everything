//! Control plane smoke test for proxy-server.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use clap::Parser;

use proxy_core::control::{ControlClient, ControlResponse, ControlResult};
use proxy_core::nodes::{NodeGroup, NodeInfo};
use proxy_core::relay::{LoadBalanceAlgo, RelayConfig, RelayStatus, UpstreamTarget};

#[derive(Parser, Debug)]
#[command(author, version, about = "Proxy server control-plane smoke test")]
struct Cli {
    /// Proxy server host
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Proxy server port
    #[arg(long, default_value_t = 1081)]
    port: u16,
    /// Admin token (optional)
    #[arg(long)]
    token: Option<String>,
    /// Control session key (optional)
    #[arg(long)]
    session_key: Option<String>,
}

/// Validate that a control response is successful and matches the expected result variant.
fn assert_control_result(resp: ControlResponse, expected: &str) -> Result<()> {
    ensure!(resp.ok, "control response failed: {:?}", resp.error);
    match (&resp.result, expected) {
        (Some(ControlResult::Pong), "pong") => Ok(()),
        (Some(ControlResult::Ack), "ack") => Ok(()),
        _ => Err(anyhow!(
            "unexpected control response for {}: {:?}",
            expected,
            resp.result
        )),
    }
}

/// Locate a node by address in a node list.
fn find_node<'a>(nodes: &'a [NodeInfo], addr: &str) -> Option<&'a NodeInfo> {
    nodes.iter().find(|node| node.addr == addr)
}

/// Locate a group by id in a group list.
fn find_group<'a>(groups: &'a [NodeGroup], group_id: &str) -> Option<&'a NodeGroup> {
    groups.iter().find(|group| group.group_id == group_id)
}

/// Validate a group exists with the expected metadata.
fn assert_group(groups: &[NodeGroup], group_id: &str, expected_name: &str) -> Result<()> {
    let group = find_group(groups, group_id)
        .ok_or_else(|| anyhow!("group {} not found in list", group_id))?;
    ensure!(
        group.name == expected_name,
        "group {} name mismatch: expected {}, got {}",
        group_id,
        expected_name,
        group.name
    );
    Ok(())
}

/// Validate a group contains a specific node id.
fn assert_group_contains(group: &NodeGroup, node_id: &str) -> Result<()> {
    ensure!(
        group.node_ids.iter().any(|id| id == node_id),
        "group {} missing node {}",
        group.group_id,
        node_id
    );
    Ok(())
}

/// Validate the relay config matches expected settings.
fn assert_relay_config(
    config: &RelayConfig,
    enabled: bool,
    algo: LoadBalanceAlgo,
    expected_targets: &[UpstreamTarget],
    expected_interval: u64,
) -> Result<()> {
    ensure!(
        config.enabled == enabled,
        "relay enabled mismatch: expected {}, got {}",
        enabled,
        config.enabled
    );
    ensure!(
        config.algo == algo,
        "relay algo mismatch: expected {:?}, got {:?}",
        algo,
        config.algo
    );
    ensure!(
        config.health_check_interval_secs == expected_interval,
        "relay health interval mismatch: expected {}, got {}",
        expected_interval,
        config.health_check_interval_secs
    );
    ensure!(
        config.targets.len() == expected_targets.len(),
        "relay targets length mismatch: expected {}, got {}",
        expected_targets.len(),
        config.targets.len()
    );
    for target in expected_targets {
        ensure!(
            config.targets.contains(target),
            "relay config missing target: {:?}",
            target
        );
    }
    Ok(())
}

/// Validate the relay status reports expected enablement, algo, and resolved targets.
fn assert_relay_status(
    status: &RelayStatus,
    enabled: bool,
    algo: LoadBalanceAlgo,
    expected_addrs: &[&str],
) -> Result<()> {
    ensure!(
        status.enabled == enabled,
        "relay status enabled mismatch: expected {}, got {}",
        enabled,
        status.enabled
    );
    ensure!(
        status.algo == algo,
        "relay status algo mismatch: expected {:?}, got {:?}",
        algo,
        status.algo
    );
    ensure!(
        status.targets.len() == expected_addrs.len(),
        "relay status target count mismatch: expected {}, got {}",
        expected_addrs.len(),
        status.targets.len()
    );
    for addr in expected_addrs {
        ensure!(
            status.targets.iter().any(|target| target.addr == *addr),
            "relay status missing target addr {}",
            addr
        );
    }
    Ok(())
}

/// Execute a full control-plane validation flow against a running server.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = ControlClient::connect(&cli.host, cli.port, cli.session_key.clone())
        .await
        .context("connect control client")?;

    let token = cli.token.clone();
    let ping = client.ping(token.clone()).await.context("ping")?;
    assert_control_result(ping, "pong")?;

    let nodes = client
        .list_nodes(token.clone())
        .await
        .context("list nodes")?;
    tracing::info!(count = nodes.len(), "nodes listed");

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let group_id = format!("tui-smoke-{}", suffix);
    let group_name = "TUI Smoke Group".to_string();

    client
        .create_group(token.clone(), group_id.clone(), group_name.clone())
        .await
        .context("create group")?;
    let groups = client
        .list_groups(token.clone())
        .await
        .context("list groups after create")?;
    assert_group(&groups, &group_id, &group_name)?;

    let node_addr = format!("10.0.0.{}:1081", (suffix % 200) + 1);
    client
        .add_node(token.clone(), node_addr.clone())
        .await
        .context("add node")?;
    let nodes = client
        .list_nodes(token.clone())
        .await
        .context("list nodes after add")?;
    let node = find_node(&nodes, &node_addr)
        .ok_or_else(|| anyhow!("node {} not found after add", node_addr))?;
    ensure!(
        node.node_id == node_addr,
        "node id mismatch: expected {}, got {}",
        node_addr,
        node.node_id
    );

    client
        .add_node_to_group(token.clone(), group_id.clone(), node_addr.clone())
        .await
        .context("add node to group")?;
    let groups = client
        .list_groups(token.clone())
        .await
        .context("list groups after add node to group")?;
    let group = find_group(&groups, &group_id)
        .ok_or_else(|| anyhow!("group {} not found after add node", group_id))?;
    assert_group_contains(group, &node_addr)?;

    let config = RelayConfig {
        enabled: true,
        targets: vec![
            UpstreamTarget::group_ref(group_id.clone()),
            UpstreamTarget::node_weighted("10.0.0.200:1081", 2),
        ],
        algo: LoadBalanceAlgo::Weighted,
        health_check_interval_secs: 30,
    };
    client
        .set_relay_config(token.clone(), config.clone())
        .await
        .context("set relay config")?;
    let fetched = client
        .get_relay_config(token.clone())
        .await
        .context("get relay config")?;
    let expected_targets = vec![
        UpstreamTarget::group_ref(group_id.clone()),
        UpstreamTarget::node_weighted("10.0.0.200:1081", 2),
    ];
    assert_relay_config(
        &fetched,
        true,
        LoadBalanceAlgo::Weighted,
        &expected_targets,
        30,
    )?;

    let status = client
        .get_relay_status(token.clone())
        .await
        .context("get relay status")?;
    let expected_status_addrs = vec![node_addr.as_str(), "10.0.0.200:1081"];
    assert_relay_status(
        &status,
        true,
        LoadBalanceAlgo::Weighted,
        &expected_status_addrs,
    )?;

    client
        .set_relay_algo(token.clone(), LoadBalanceAlgo::Random)
        .await
        .context("set relay algo")?;
    let fetched = client
        .get_relay_config(token.clone())
        .await
        .context("get relay config after algo change")?;
    assert_relay_config(
        &fetched,
        true,
        LoadBalanceAlgo::Random,
        &expected_targets,
        30,
    )?;

    client
        .remove_relay_target(token.clone(), 0)
        .await
        .context("remove relay target")?;
    let fetched = client
        .get_relay_config(token.clone())
        .await
        .context("get relay config after remove target")?;
    let expected_targets = vec![UpstreamTarget::node_weighted("10.0.0.200:1081", 2)];
    assert_relay_config(
        &fetched,
        true,
        LoadBalanceAlgo::Random,
        &expected_targets,
        30,
    )?;

    client
        .set_relay_enabled(token.clone(), false)
        .await
        .context("disable relay")?;
    let fetched = client
        .get_relay_config(token.clone())
        .await
        .context("get relay config after disable")?;
    assert_relay_config(
        &fetched,
        false,
        LoadBalanceAlgo::Random,
        &expected_targets,
        30,
    )?;

    client
        .remove_node_from_group(token.clone(), group_id.clone(), node_addr.clone())
        .await
        .context("remove node from group")?;
    let groups = client
        .list_groups(token.clone())
        .await
        .context("list groups after remove node")?;
    let group = find_group(&groups, &group_id)
        .ok_or_else(|| anyhow!("group {} not found after remove node", group_id))?;
    ensure!(
        !group.node_ids.iter().any(|id| id == &node_addr),
        "node {} still present in group {}",
        node_addr,
        group_id
    );

    client
        .delete_group(token.clone(), group_id.clone())
        .await
        .context("delete group")?;
    let groups = client
        .list_groups(token.clone())
        .await
        .context("list groups after delete")?;
    ensure!(
        find_group(&groups, &group_id).is_none(),
        "group {} still present after delete",
        group_id
    );

    client
        .remove_node(token.clone(), node_addr.clone())
        .await
        .context("remove node")?;
    let nodes = client
        .list_nodes(token.clone())
        .await
        .context("list nodes after remove")?;
    ensure!(
        find_node(&nodes, &node_addr).is_none(),
        "node {} still present after remove",
        node_addr
    );

    tracing::info!("control smoke test completed");
    Ok(())
}
