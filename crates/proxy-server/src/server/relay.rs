//! Relay manager for dynamic upstream configuration.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use proxy_core::nodes::NodeStore;
use proxy_core::relay::{
    LoadBalanceAlgo, LoadBalancer, RelayConfig, RelayStatus, ResolvedTarget, UpstreamTarget,
    create_balancer,
};

fn default_config_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".proxy-everything")
    } else {
        PathBuf::from(".proxy-everything")
    }
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
        let config = self.config.read().unwrap();
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
        self.config.read().unwrap().enabled
    }

    /// Select an upstream target.
    pub fn select(&self) -> Option<String> {
        if !self.is_enabled() {
            return None;
        }
        self.balancer.read().unwrap().select()
    }

    /// Get current config.
    pub fn get_config(&self) -> RelayConfig {
        self.config.read().unwrap().clone()
    }

    /// Set entire config.
    pub fn set_config(&self, config: RelayConfig) {
        let algo = config.algo;
        *self.config.write().unwrap() = config;
        self.update_balancer(algo);
        self.refresh_targets();
        let _ = self.save_config();
    }

    /// Set relay enabled state.
    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().unwrap().enabled = enabled;
        let _ = self.save_config();
    }

    /// Add a target.
    pub fn add_target(&self, target: UpstreamTarget) {
        self.config.write().unwrap().targets.push(target);
        self.refresh_targets();
        let _ = self.save_config();
    }

    /// Remove a target by index.
    pub fn remove_target(&self, index: usize) -> bool {
        let mut config = self.config.write().unwrap();
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
        self.config.write().unwrap().algo = algo;
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
        let config = self.config.read().unwrap();
        let targets = self.balancer.read().unwrap().get_statuses();
        RelayStatus {
            enabled: config.enabled,
            algo: config.algo,
            targets,
        }
    }

    /// Mark a target as unhealthy.
    pub fn mark_unhealthy(&self, addr: &str) {
        self.balancer.read().unwrap().mark_unhealthy(addr);
    }

    /// Mark a target as healthy.
    pub fn mark_healthy(&self, addr: &str) {
        self.balancer.read().unwrap().mark_healthy(addr);
    }

    /// Notify connection start (for LeastConn).
    pub fn on_connect(&self, addr: &str) {
        self.balancer.read().unwrap().on_connect(addr);
    }

    /// Notify connection end (for LeastConn).
    pub fn on_disconnect(&self, addr: &str) {
        self.balancer.read().unwrap().on_disconnect(addr);
    }

    fn update_balancer(&self, algo: LoadBalanceAlgo) {
        *self.balancer.write().unwrap() = create_balancer(algo);
    }

    fn refresh_targets(&self) {
        let config = self.config.read().unwrap();
        let resolved = self.resolve_targets_inner(&config);
        drop(config);
        self.balancer.read().unwrap().update_targets(resolved);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

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
