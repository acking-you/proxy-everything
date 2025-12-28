//! End-to-end tests for proxy client-server communication.
//!
//! Tests the full proxy chain: App -> ProxyClient -> ProxyServer -> Real Internet

use std::sync::Arc;
use std::time::Duration;

use http_proxy::control::ControlClient;
use http_proxy::metrics::MetricsStore;
use http_proxy::nodes::NodeStore;
use http_proxy::server::{ServerConfig, run_server_with_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Real proxy server fixture.
struct ProxyServer {
    port: u16,
    cancel_token: CancellationToken,
    metrics: Arc<MetricsStore>,
}

impl ProxyServer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancel_token = CancellationToken::new();

        let metrics = Arc::new(MetricsStore::with_default_config());
        let nodes = Arc::new(NodeStore::new("/tmp/test_nodes.json"));

        let config = ServerConfig {
            metrics: metrics.clone(),
            nodes,
            admin_token: None,
            require_control_encryption: false,
            control_session_key: None,
            self_node_id: None,
        };

        let token = cancel_token.clone();
        tokio::spawn(async move {
            run_server_with_listener(listener, config, token, None).await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        Self {
            port,
            cancel_token,
            metrics,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn metrics(&self) -> &Arc<MetricsStore> {
        &self.metrics
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

// ============================================================================
// Full E2E Tests: App -> ProxyServer -> Real Internet
// ============================================================================

/// Test full proxy chain via encrypted connection to httpbin.org
#[tokio::test]
async fn test_full_chain_to_httpbin() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(30), async {
        // Use get_tcp_proxy_stream which handles encryption
        let stream = http_proxy::client::get_tcp_proxy_stream(
            "httpbin.org",
            80,
            "127.0.0.1",
            server.port(),
            None,
            "test-httpbin",
        )
        .await
        .expect("Failed to connect through proxy");

        let (mut reader, mut writer) = stream.into_split();

        // Send HTTP request
        let http_req = "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
        writer.write_all(http_req.as_bytes()).await.unwrap();

        // Read response
        let mut body = Vec::new();
        reader.read_to_end(&mut body).await.unwrap();
        let response = String::from_utf8_lossy(&body);

        assert!(
            response.contains("200"),
            "Expected 200 OK, got: {}",
            &response[..response.len().min(500)]
        );
        assert!(
            response.contains("httpbin.org"),
            "Response should mention httpbin.org"
        );
    })
    .await;

    result.expect("Test timed out");
}

/// Test proxy with large data transfer
#[tokio::test]
async fn test_proxy_large_data_transfer() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(60), async {
        let stream = http_proxy::client::get_tcp_proxy_stream(
            "httpbin.org",
            80,
            "127.0.0.1",
            server.port(),
            None,
            "test-large",
        )
        .await
        .expect("Failed to connect");

        let (mut reader, mut writer) = stream.into_split();

        // Request 10KB of data
        let http_req =
            "GET /bytes/10240 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
        writer.write_all(http_req.as_bytes()).await.unwrap();

        let mut body = Vec::new();
        reader.read_to_end(&mut body).await.unwrap();

        // Should have received headers + 10KB body
        assert!(
            body.len() > 10000,
            "Expected >10KB, got {} bytes",
            body.len()
        );
    })
    .await;

    result.expect("Test timed out");
}

// ============================================================================
// ControlClient E2E Tests
// ============================================================================

/// Test ControlClient can query realtime stats.
#[tokio::test]
async fn test_control_client_realtime_stats() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(5), async {
        let mut client = ControlClient::connect("127.0.0.1", server.port(), None)
            .await
            .expect("Failed to connect control client");

        let stats = client
            .get_realtime_stats(None)
            .await
            .expect("Failed to get realtime stats");

        println!("Realtime stats: {:?}", stats);
        assert!(stats.is_some(), "Should return realtime stats");
    })
    .await;

    result.expect("Test timed out");
}

/// Test ControlClient can list nodes.
#[tokio::test]
async fn test_control_client_list_nodes() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(5), async {
        let mut client = ControlClient::connect("127.0.0.1", server.port(), None)
            .await
            .expect("Failed to connect control client");

        let _nodes = client.list_nodes(None).await.expect("Failed to list nodes");
    })
    .await;

    result.expect("Test timed out");
}

/// Test ControlClient can query recent connections after proxy usage.
#[tokio::test]
async fn test_control_client_recent_connections() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(30), async {
        // Make a connection through the proxy
        let stream = http_proxy::client::get_tcp_proxy_stream(
            "httpbin.org",
            80,
            "127.0.0.1",
            server.port(),
            None,
            "test-metrics",
        )
        .await
        .expect("Failed to connect");

        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf).await;
        drop(reader);
        drop(writer);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Query connections via ControlClient
        let mut ctrl = ControlClient::connect("127.0.0.1", server.port(), None)
            .await
            .expect("Failed to connect control client");

        let connections = ctrl
            .get_recent_connections(None, 10)
            .await
            .expect("Failed to get connections");

        assert!(!connections.is_empty(), "Should have recorded connections");
        assert_eq!(connections[0].dest_host, "httpbin.org");
    })
    .await;

    result.expect("Test timed out");
}

/// Test metrics recording with real traffic
#[tokio::test]
async fn test_metrics_with_real_traffic() {
    let server = ProxyServer::new().await;

    let result = timeout(Duration::from_secs(30), async {
        // Make a connection
        let stream = http_proxy::client::get_tcp_proxy_stream(
            "httpbin.org",
            80,
            "127.0.0.1",
            server.port(),
            None,
            "test-metrics",
        )
        .await
        .expect("Failed to connect");

        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(
                b"GET /bytes/1024 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf).await;
        drop(reader);
        drop(writer);

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify metrics
        let connections = server.metrics().get_recent_connections(10);
        assert!(!connections.is_empty(), "Should have recorded connections");

        let conn = &connections[0];
        assert_eq!(conn.dest_host, "httpbin.org");
        assert!(conn.bytes_up > 0, "Should have recorded bytes uploaded");
        assert!(conn.bytes_down > 0, "Should have recorded bytes downloaded");
    })
    .await;

    result.expect("Test timed out");
}
