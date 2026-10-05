use std::sync::Arc;
use std::time::Duration;

use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
use proxy_server::{RelayManager, ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[tokio::test(start_paused = true)]
async fn stalled_headers_expire_and_cancelled_connections_release_metrics() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let directory = std::env::temp_dir().join(format!(
        "proxy-header-test-{}-{}",
        std::process::id(),
        address.port()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let nodes = Arc::new(NodeStore::new(directory.join("nodes.json")));
    let metrics = Arc::new(MetricsStore::with_default_config());
    let config = ServerConfig {
        metrics: Arc::clone(&metrics),
        relay: Arc::new(RelayManager::new(nodes.clone(), &directory)),
        nodes,
        admin_token: None,
        require_control_encryption: false,
        require_secure_transport: false,
        control_session_key: None,
        self_node_id: None,
    };
    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();
    let server = tokio::spawn(run_server_with_listener(
        listener,
        config,
        cancel.clone(),
        Some(tracker.clone()),
    ));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[0]).await.unwrap();
    for _ in 0..100 {
        if metrics.get_realtime_snapshot().active_connections == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(metrics.get_realtime_snapshot().active_connections, 1);
    tokio::time::advance(Duration::from_secs(11)).await;
    let result = client.read(&mut [0]).await;
    assert!(matches!(result, Ok(0)) || result.is_err());
    assert_eq!(metrics.get_realtime_snapshot().active_connections, 0);

    let _pending = TcpStream::connect(address).await.unwrap();
    for _ in 0..100 {
        if metrics.get_realtime_snapshot().active_connections == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(metrics.get_realtime_snapshot().active_connections, 1);
    cancel.cancel();
    server.await.unwrap();
    tracker.close();
    tracker.wait().await;
    assert_eq!(metrics.get_realtime_snapshot().active_connections, 0);
    std::fs::remove_dir_all(directory).unwrap();
}
