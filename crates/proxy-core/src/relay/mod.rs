//! Relay configuration and load balancing.
//!
//! This module provides dynamic relay configuration for the proxy server,
//! allowing runtime switching between proxy and relay modes.

mod balancer;

pub use balancer::{
    LeastConnBalancer, LoadBalancer, RandomBalancer, RoundRobinBalancer, WeightedBalancer,
    create_balancer,
};
use reqwest::Url;
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
    /// External SOCKS5/HTTP proxy URL.
    ExternalProxy { proxy_url: String, weight: u32 },
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

    pub fn external_proxy(proxy_url: impl Into<String>, weight: u32) -> Self {
        Self::ExternalProxy {
            proxy_url: proxy_url.into(),
            weight,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalProxyKind {
    Socks5,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalProxyTarget {
    pub kind: ExternalProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub remote_dns: bool,
}

impl ExternalProxyTarget {
    pub fn parse(proxy_url: &str) -> Result<Self, String> {
        let url = Url::parse(proxy_url).map_err(|e| format!("Invalid proxy URL: {e}"))?;
        if url.cannot_be_a_base() {
            return Err("Proxy URL must include a host".to_string());
        }

        let (kind, remote_dns) = match url.scheme() {
            "socks5" => (ExternalProxyKind::Socks5, false),
            "socks5h" => (ExternalProxyKind::Socks5, true),
            "http" => (ExternalProxyKind::Http, false),
            scheme => {
                return Err(format!(
                    "Unsupported proxy scheme `{scheme}`. Use socks5, socks5h, or http"
                ));
            }
        };

        let host = url
            .host_str()
            .ok_or_else(|| "Proxy URL must include a host".to_string())?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| "Proxy URL must include an explicit port".to_string())?;
        let username = match url.username() {
            "" => None,
            value => Some(value.to_string()),
        };
        let password = url.password().map(ToString::to_string);
        if password.is_some() && username.is_none() {
            return Err("Proxy URL password requires a username".to_string());
        }

        Ok(Self {
            kind,
            host,
            port,
            username,
            password,
            remote_dns,
        })
    }

    pub fn display_url(&self) -> String {
        let scheme = match (self.kind, self.remote_dns) {
            (ExternalProxyKind::Socks5, true) => "socks5h",
            (ExternalProxyKind::Socks5, false) => "socks5",
            (ExternalProxyKind::Http, _) => "http",
        };
        match &self.username {
            Some(username) => format!("{scheme}://{username}@{}:{}", self.host, self.port),
            None => format!("{scheme}://{}:{}", self.host, self.port),
        }
    }

    pub fn stable_id(&self) -> String {
        self.display_url()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRoute {
    ProxyServer { addr: String },
    ExternalProxy(ExternalProxyTarget),
}

impl RelayRoute {
    pub fn stable_id(&self) -> String {
        match self {
            Self::ProxyServer { addr } => addr.clone(),
            Self::ExternalProxy(proxy) => proxy.stable_id(),
        }
    }

    pub fn display_addr(&self) -> String {
        match self {
            Self::ProxyServer { addr } => addr.clone(),
            Self::ExternalProxy(proxy) => proxy.display_url(),
        }
    }
}

/// Resolved target with address and weight.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub id: String,
    pub addr: String,
    pub route: RelayRoute,
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
    fn test_external_proxy_target_serde() {
        let config = RelayConfig {
            enabled: true,
            targets: vec![UpstreamTarget::external_proxy(
                "socks5://user:secret@127.0.0.1:1080",
                3,
            )],
            algo: LoadBalanceAlgo::Weighted,
            health_check_interval_secs: 45,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"type\": \"external_proxy\""));

        let parsed: RelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.targets, config.targets);
    }

    #[test]
    fn test_parse_external_proxy_target_masks_password() {
        let proxy = ExternalProxyTarget::parse("socks5://user:secret@127.0.0.1:1080").unwrap();
        assert_eq!(proxy.kind, ExternalProxyKind::Socks5);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("secret"));
        assert_eq!(proxy.display_url(), "socks5://user@127.0.0.1:1080");
    }

    #[test]
    fn test_parse_external_http_proxy_without_auth() {
        let proxy = ExternalProxyTarget::parse("http://proxy.example.com:8080").unwrap();
        assert_eq!(proxy.kind, ExternalProxyKind::Http);
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8080);
        assert!(proxy.username.is_none());
        assert!(proxy.password.is_none());
        assert_eq!(proxy.display_url(), "http://proxy.example.com:8080");
    }

    #[test]
    fn test_relay_config_serde() {
        let config = RelayConfig {
            enabled: true,
            targets: vec![
                UpstreamTarget::node("127.0.0.1:1081"),
                UpstreamTarget::node_weighted("127.0.0.2:1081", 2),
                UpstreamTarget::node_ref("node-1"),
                UpstreamTarget::group_ref("group-1"),
                UpstreamTarget::external_proxy("http://127.0.0.1:8080", 2),
            ],
            algo: LoadBalanceAlgo::Weighted,
            health_check_interval_secs: 60,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: RelayConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.targets.len(), 5);
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

        let target = UpstreamTarget::external_proxy("socks5://user:pass@127.0.0.1:1080", 1);
        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("\"type\":\"external_proxy\""));
    }
}
