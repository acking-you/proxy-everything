//! Integration tests for dynamic relay configuration.

use std::sync::Arc;
use std::time::Duration;

use proxy_core::control::{ControlClient, ControlOp, ControlRequest, ControlResult};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_core::relay::{LoadBalanceAlgo, RelayConfig, UpstreamTarget};
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn unique_test_dir() -> std::path::PathBuf {
    let test_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("relay_integration_test_{}", test_id))
}

async fn setup_test_server() -> (String, CancellationToken, std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();

    let test_dir = unique_test_dir();
    let _ = std::fs::create_dir_all(&test_dir);

    let nodes = Arc::new(NodeStore::new(test_dir.join("nodes.json")));
    let relay = Arc::new(RelayManager::new(nodes.clone(), &test_dir));

    let config = ServerConfig {
        metrics: Arc::new(MetricsStore::with_default_config()),
        nodes,
        relay,
        admin_token: None,
        require_control_encryption: false,
        require_secure_transport: false,
        control_session_key: None,
        self_node_id: Some("test-node".to_string()),
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        run_server_with_listener(listener, config, cancel_clone, None).await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    (format!("127.0.0.1:{}", addr.port()), cancel, test_dir)
}

/// Helper to send a control operation
async fn send_op(
    client: &mut ControlClient,
    op: ControlOp,
) -> Result<ControlResult, proxy_core::control::ControlError> {
    let resp = client.request(ControlRequest { token: None, op }).await?;
    if resp.ok {
        Ok(resp.result.unwrap())
    } else {
        Err(proxy_core::control::ControlError::Protocol {
            source: proxy_core::ProxyError::Protocol {
                detail: resp.error.unwrap_or_default(),
            },
        })
    }
}

#[tokio::test]
async fn test_relay_config_crud() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Get initial config (should be disabled)
    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config } = result {
        assert!(!config.enabled);
        assert!(config.targets.is_empty());
    } else {
        panic!("Expected RelayConfig result");
    }

    // Add a target
    let target = UpstreamTarget::node("192.168.1.100:1081");
    send_op(&mut client, ControlOp::AddRelayTarget { target })
        .await
        .unwrap();

    // Verify target was added
    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config } = result {
        assert_eq!(config.targets.len(), 1);
    } else {
        panic!("Expected RelayConfig result");
    }

    // Enable relay
    send_op(&mut client, ControlOp::SetRelayEnabled { enabled: true })
        .await
        .unwrap();

    // Verify enabled
    let result = send_op(&mut client, ControlOp::GetRelayStatus)
        .await
        .unwrap();
    if let ControlResult::RelayStatus { status } = result {
        assert!(status.enabled);
        assert_eq!(status.targets.len(), 1);
    } else {
        panic!("Expected RelayStatus result");
    }

    // Change algorithm
    send_op(
        &mut client,
        ControlOp::SetRelayAlgo {
            algo: LoadBalanceAlgo::Random,
        },
    )
    .await
    .unwrap();

    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config } = result {
        assert_eq!(config.algo, LoadBalanceAlgo::Random);
    } else {
        panic!("Expected RelayConfig result");
    }

    // Remove target
    send_op(&mut client, ControlOp::RemoveRelayTarget { index: 0 })
        .await
        .unwrap();

    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config } = result {
        assert!(config.targets.is_empty());
    } else {
        panic!("Expected RelayConfig result");
    }

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_set_full_relay_config() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Set full config
    let config = RelayConfig {
        enabled: true,
        targets: vec![
            UpstreamTarget::node("10.0.0.1:1081"),
            UpstreamTarget::node_weighted("10.0.0.2:1081", 2),
        ],
        algo: LoadBalanceAlgo::Weighted,
        health_check_interval_secs: 60,
    };

    send_op(
        &mut client,
        ControlOp::SetRelayConfig {
            config: config.clone(),
        },
    )
    .await
    .unwrap();

    // Verify
    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config: got } = result {
        assert!(got.enabled);
        assert_eq!(got.targets.len(), 2);
        assert_eq!(got.algo, LoadBalanceAlgo::Weighted);
    } else {
        panic!("Expected RelayConfig result");
    }

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_external_proxy_relay_status_redacts_password() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();
    let config = RelayConfig {
        enabled: true,
        targets: vec![UpstreamTarget::external_proxy(
            "socks5://relay-user:secret-pass@127.0.0.1:1080",
            2,
        )],
        algo: LoadBalanceAlgo::RoundRobin,
        health_check_interval_secs: 30,
    };

    send_op(
        &mut client,
        ControlOp::SetRelayConfig {
            config: config.clone(),
        },
    )
    .await
    .unwrap();

    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config: got } = result {
        assert_eq!(got.targets, config.targets);
    } else {
        panic!("Expected RelayConfig result");
    }

    let result = send_op(&mut client, ControlOp::GetRelayStatus)
        .await
        .unwrap();
    if let ControlResult::RelayStatus { status } = result {
        assert_eq!(status.targets.len(), 1);
        assert_eq!(status.targets[0].addr, "socks5://relay-user@127.0.0.1:1080");
        assert_eq!(status.targets[0].weight, 2);
        assert!(!status.targets[0].addr.contains("secret-pass"));
    } else {
        panic!("Expected RelayStatus result");
    }

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_group_management() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Create a group
    send_op(
        &mut client,
        ControlOp::CreateGroup {
            group_id: "asia".to_string(),
            name: "Asia Servers".to_string(),
        },
    )
    .await
    .unwrap();

    // List groups
    let result = send_op(&mut client, ControlOp::ListGroups).await.unwrap();
    if let ControlResult::Groups { groups } = result {
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_id, "asia");
        assert_eq!(groups[0].name, "Asia Servers");
    } else {
        panic!("Expected Groups result");
    }

    // Add a node first
    send_op(
        &mut client,
        ControlOp::AddNode {
            addr: "192.168.1.10:1081".to_string(),
        },
    )
    .await
    .unwrap();

    // Add node to group
    send_op(
        &mut client,
        ControlOp::AddNodeToGroup {
            group_id: "asia".to_string(),
            node_id: "192.168.1.10:1081".to_string(),
        },
    )
    .await
    .unwrap();

    // Verify node in group
    let result = send_op(&mut client, ControlOp::ListGroups).await.unwrap();
    if let ControlResult::Groups { groups } = result {
        assert_eq!(groups[0].node_ids.len(), 1);
        assert_eq!(groups[0].node_ids[0], "192.168.1.10:1081");
    } else {
        panic!("Expected Groups result");
    }

    // Remove node from group
    send_op(
        &mut client,
        ControlOp::RemoveNodeFromGroup {
            group_id: "asia".to_string(),
            node_id: "192.168.1.10:1081".to_string(),
        },
    )
    .await
    .unwrap();

    let result = send_op(&mut client, ControlOp::ListGroups).await.unwrap();
    if let ControlResult::Groups { groups } = result {
        assert!(groups[0].node_ids.is_empty());
    } else {
        panic!("Expected Groups result");
    }

    // Delete group
    send_op(
        &mut client,
        ControlOp::DeleteGroup {
            group_id: "asia".to_string(),
        },
    )
    .await
    .unwrap();

    let result = send_op(&mut client, ControlOp::ListGroups).await.unwrap();
    if let ControlResult::Groups { groups } = result {
        assert!(groups.is_empty());
    } else {
        panic!("Expected Groups result");
    }

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_relay_with_group_ref() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Create group
    send_op(
        &mut client,
        ControlOp::CreateGroup {
            group_id: "backend".to_string(),
            name: "Backend Servers".to_string(),
        },
    )
    .await
    .unwrap();

    // Add relay target referencing the group
    let target = UpstreamTarget::group_ref("backend");
    send_op(&mut client, ControlOp::AddRelayTarget { target })
        .await
        .unwrap();

    // Verify config
    let result = send_op(&mut client, ControlOp::GetRelayConfig)
        .await
        .unwrap();
    if let ControlResult::RelayConfig { config } = result {
        assert_eq!(config.targets.len(), 1);
        match &config.targets[0] {
            UpstreamTarget::GroupRef { group_id } => {
                assert_eq!(group_id, "backend");
            }
            _ => panic!("Expected GroupRef target"),
        }
    } else {
        panic!("Expected RelayConfig result");
    }

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_duplicate_group_creation_fails() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Create a group
    send_op(
        &mut client,
        ControlOp::CreateGroup {
            group_id: "test".to_string(),
            name: "Test".to_string(),
        },
    )
    .await
    .unwrap();

    // Try to create duplicate - should fail
    let result = send_op(
        &mut client,
        ControlOp::CreateGroup {
            group_id: "test".to_string(),
            name: "Test 2".to_string(),
        },
    )
    .await;

    assert!(result.is_err());

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_remove_invalid_relay_target_fails() {
    let (addr, cancel, test_dir) = setup_test_server().await;
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();

    let mut client = ControlClient::connect(host, port, None).await.unwrap();

    // Try to remove non-existent target
    let result = send_op(&mut client, ControlOp::RemoveRelayTarget { index: 999 }).await;

    assert!(result.is_err());

    cancel.cancel();
    let _ = std::fs::remove_dir_all(&test_dir);
}
