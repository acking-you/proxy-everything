//! Relay manager for dynamic upstream configuration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use proxy_core::nodes::NodeStore;
use proxy_core::relay::{
    LoadBalanceAlgo, LoadBalancer, RelayConfig, RelayStatus, ResolvedTarget, UpstreamTarget,
    create_balancer,
};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const HEALTHY_PING_INTERVAL: Duration = Duration::from_secs(60 * 3);
const UNHEALTHY_PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTH_CHECK_TICK: Duration = Duration::from_secs(5);

fn default_config_dir() -> PathBuf {
    proxy_core::config::default_state_dir()
}

/// Relay manager for dynamic upstream selection.
pub struct RelayManager {
    config: RwLock<RelayConfig>,
    balancer: RwLock<Box<dyn LoadBalancer>>,
    nodes: Arc<NodeStore>,
    config_path: PathBuf,
}

impl RelayManager {
    /// Create a new relay manager.
    pub fn new(nodes: Arc<NodeStore>, config_dir: impl AsRef<Path>) -> Self {
        let config_path = config_dir.as_ref().join("relay.json");
        let config = Self::load_config(&config_path).unwrap_or_default();
        let balancer = create_balancer(config.algo);

        let manager = Self {
            config: RwLock::new(config),
            balancer: RwLock::new(balancer),
            nodes,
            config_path,
        };
        manager.refresh_targets();
        manager
    }

    /// Create with default config directory (~/.proxy-everything/).
    pub fn with_default_path(nodes: Arc<NodeStore>) -> Self {
        Self::new(nodes, default_config_dir())
    }

    fn load_config(path: &Path) -> Option<RelayConfig> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn save_config(&self) -> std::io::Result<()> {
        let config = self.config.read();
        let content = serde_json::to_string_pretty(&*config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        drop(config);

        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let temp_path = self.config_path.with_extension("json.tmp");
        std::fs::write(&temp_path, &content)?;
        std::fs::rename(&temp_path, &self.config_path).inspect_err(|_| {
            let _ = std::fs::remove_file(&temp_path);
        })
    }

    /// Check if relay is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    /// Select an upstream target.
    pub fn select(&self) -> Option<String> {
        if !self.is_enabled() {
            return None;
        }
        self.balancer.read().select()
    }

    /// Get current config.
    pub fn get_config(&self) -> RelayConfig {
        self.config.read().clone()
    }

    /// Set entire config.
    pub fn set_config(&self, config: RelayConfig) {
        let algo = config.algo;
        *self.config.write() = config;
        self.update_balancer(algo);
        self.refresh_targets();
        let _ = self.save_config();
    }

    /// Set relay enabled state.
    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
        let _ = self.save_config();
    }

    /// Add a target.
    pub fn add_target(&self, target: UpstreamTarget) {
        self.config.write().targets.push(target);
        self.refresh_targets();
        let _ = self.save_config();
    }

    /// Remove a target by index.
    pub fn remove_target(&self, index: usize) -> bool {
        let mut config = self.config.write();
        if index >= config.targets.len() {
            return false;
        }
        config.targets.remove(index);
        drop(config);
        self.refresh_targets();
        let _ = self.save_config();
        true
    }

    /// Set load balance algorithm.
    pub fn set_algo(&self, algo: LoadBalanceAlgo) {
        self.config.write().algo = algo;
        self.update_balancer(algo);
        self.refresh_targets();
        let _ = self.save_config();
    }

    /// Get relay status with the latest load balancer snapshot.
    ///
    /// This refreshes the resolved targets before reading the balancer so
    /// the status reflects current node/group membership while preserving
    /// connection counts for existing targets.
    pub fn get_status(&self) -> RelayStatus {
        self.refresh_targets();
        let config = self.config.read();
        let targets = self.balancer.read().get_statuses();
        RelayStatus {
            enabled: config.enabled,
            algo: config.algo,
            targets,
        }
    }

    /// Periodically ping relay targets to update health status.
    ///
    /// Healthy targets are checked every few minutes. Unhealthy targets are
    /// checked every 30 seconds to speed up recovery.
    pub async fn run_health_checks(self: Arc<Self>, cancel_token: CancellationToken) {
        let mut last_check: HashMap<String, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(HEALTH_CHECK_TICK);

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = ticker.tick() => {}
            }

            if !self.is_enabled() {
                continue;
            }

            let status = self.get_status();
            let now = Instant::now();

            let mut current = HashMap::new();
            for target in status.targets {
                let interval = if target.healthy {
                    HEALTHY_PING_INTERVAL
                } else {
                    UNHEALTHY_PING_INTERVAL
                };
                let last = last_check
                    .entry(target.addr.clone())
                    .or_insert_with(|| now - interval);
                current.insert(target.addr.clone(), ());
                if now.duration_since(*last) < interval {
                    continue;
                }
                *last = now;

                let addr = target.addr.clone();
                let ok = ping_target(&addr).await;
                if ok {
                    self.mark_healthy(&addr);
                } else {
                    self.mark_unhealthy(&addr);
                }
            }

            last_check.retain(|addr, _| current.contains_key(addr));
        }
    }

    /// Mark a target as unhealthy.
    pub fn mark_unhealthy(&self, addr: &str) {
        self.balancer.read().mark_unhealthy(addr);
    }

    /// Mark a target as healthy.
    pub fn mark_healthy(&self, addr: &str) {
        self.balancer.read().mark_healthy(addr);
    }

    /// Notify connection start (for LeastConn).
    pub fn on_connect(&self, addr: &str) {
        self.balancer.read().on_connect(addr);
    }

    /// Notify connection end (for LeastConn).
    pub fn on_disconnect(&self, addr: &str) {
        self.balancer.read().on_disconnect(addr);
    }

    fn update_balancer(&self, algo: LoadBalanceAlgo) {
        *self.balancer.write() = create_balancer(algo);
    }

    fn refresh_targets(&self) {
        let config = self.config.read();
        let mut resolved = self.resolve_targets_inner(&config);
        drop(config);

        let health_map: HashMap<String, bool> = self
            .balancer
            .read()
            .get_statuses()
            .into_iter()
            .map(|s| (s.addr, s.healthy))
            .collect();
        for target in &mut resolved {
            if let Some(healthy) = health_map.get(&target.addr) {
                target.healthy = *healthy;
            }
        }

        self.balancer.read().update_targets(resolved);
    }

    fn resolve_targets_inner(&self, config: &RelayConfig) -> Vec<ResolvedTarget> {
        let mut resolved = Vec::new();

        for target in &config.targets {
            match target {
                UpstreamTarget::Node { addr, weight } => {
                    resolved.push(ResolvedTarget {
                        addr: addr.clone(),
                        weight: *weight,
                        healthy: true,
                    });
                }
                UpstreamTarget::NodeRef { node_id, weight } => {
                    if let Some(node) = self
                        .nodes
                        .list_peers()
                        .into_iter()
                        .find(|n| &n.node_id == node_id)
                    {
                        resolved.push(ResolvedTarget {
                            addr: node.addr,
                            weight: *weight,
                            healthy: true,
                        });
                    }
                }
                UpstreamTarget::GroupRef { group_id } => {
                    for addr in self.nodes.get_group_addrs(group_id) {
                        resolved.push(ResolvedTarget {
                            addr,
                            weight: 1,
                            healthy: true,
                        });
                    }
                }
            }
        }

        resolved
    }
}

async fn ping_target(addr: &str) -> bool {
    match tokio::time::timeout(PING_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;

    use super::*;

    #[test]
    fn test_relay_manager() {
        // Use unique directory for this test
        let test_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let config_dir = temp_dir().join(format!("relay_test_{}", test_id));
        let _ = std::fs::create_dir_all(&config_dir);

        let nodes = Arc::new(NodeStore::new(config_dir.join("nodes.json")));
        let manager = RelayManager::new(nodes, &config_dir);

        // Initially disabled
        assert!(!manager.is_enabled());
        assert!(manager.select().is_none());

        // Add targets and enable
        manager.add_target(UpstreamTarget::node("127.0.0.1:1081"));
        manager.add_target(UpstreamTarget::node("127.0.0.2:1081"));
        manager.set_enabled(true);

        // Should select
        let addr = manager.select();
        assert!(addr.is_some());

        // Cleanup
        let _ = std::fs::remove_dir_all(&config_dir);
    }
}
