//! Relay configuration and load balancing.
//!
//! This module provides dynamic relay configuration for the proxy server,
//! allowing runtime switching between proxy and relay modes.

mod balancer;

pub use balancer::{
    LeastConnBalancer, LoadBalancer, RandomBalancer, RoundRobinBalancer, WeightedBalancer,
    create_balancer,
};

use serde::{Deserialize, Serialize};

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceAlgo {
    #[default]
    RoundRobin,
    Random,
    Weighted,
    LeastConn,
}

/// Upstream target specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamTarget {
    /// Direct address with optional weight.
    Node { addr: String, weight: u32 },
    /// Reference to a node by ID.
    NodeRef { node_id: String, weight: u32 },
    /// Reference to a node group.
    GroupRef { group_id: String },
}

impl UpstreamTarget {
    pub fn node(addr: impl Into<String>) -> Self {
        Self::Node {
            addr: addr.into(),
            weight: 1,
        }
    }

    pub fn node_weighted(addr: impl Into<String>, weight: u32) -> Self {
        Self::Node {
            addr: addr.into(),
            weight,
        }
    }

    pub fn node_ref(node_id: impl Into<String>) -> Self {
        Self::NodeRef {
            node_id: node_id.into(),
            weight: 1,
        }
    }

    pub fn group_ref(group_id: impl Into<String>) -> Self {
        Self::GroupRef {
            group_id: group_id.into(),
        }
    }
}

/// Resolved target with address and weight.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub addr: String,
    pub weight: u32,
    pub healthy: bool,
}

/// Relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub enabled: bool,
    pub targets: Vec<UpstreamTarget>,
    pub algo: LoadBalanceAlgo,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
}

fn default_health_check_interval() -> u64 {
    30
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            targets: Vec::new(),
            algo: LoadBalanceAlgo::RoundRobin,
            health_check_interval_secs: default_health_check_interval(),
        }
    }
}

impl RelayConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_target(mut self, target: UpstreamTarget) -> Self {
        self.targets.push(target);
        self
    }

    pub fn with_algo(mut self, algo: LoadBalanceAlgo) -> Self {
        self.algo = algo;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Relay status for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayStatus {
    pub enabled: bool,
    pub algo: LoadBalanceAlgo,
    pub targets: Vec<TargetStatus>,
}

/// Individual target status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStatus {
    pub addr: String,
    pub healthy: bool,
    pub weight: u32,
    pub connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config_serde() {
        let config = RelayConfig {
            enabled: true,
            targets: vec![
                UpstreamTarget::node("127.0.0.1:1081"),
                UpstreamTarget::node_weighted("127.0.0.2:1081", 2),
                UpstreamTarget::node_ref("node-1"),
                UpstreamTarget::group_ref("group-1"),
            ],
            algo: LoadBalanceAlgo::Weighted,
            health_check_interval_secs: 60,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: RelayConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.targets.len(), 4);
        assert_eq!(parsed.algo, LoadBalanceAlgo::Weighted);
    }

    #[test]
    fn test_upstream_target_serde() {
        let target = UpstreamTarget::Node {
            addr: "127.0.0.1:1081".to_string(),
            weight: 1,
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("\"type\":\"node\""));

        let target = UpstreamTarget::GroupRef {
            group_id: "g1".to_string(),
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("\"type\":\"group_ref\""));
    }
}
