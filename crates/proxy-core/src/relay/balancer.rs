//! Load balancer implementations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::RwLock;

use super::{ResolvedTarget, TargetStatus};

/// Load balancer trait.
pub trait LoadBalancer: Send + Sync {
    /// Select a target address.
    fn select(&self) -> Option<String>;
    /// Update the target list.
    fn update_targets(&self, targets: Vec<ResolvedTarget>);
    /// Mark a target as unhealthy.
    fn mark_unhealthy(&self, addr: &str);
    /// Mark a target as healthy.
    fn mark_healthy(&self, addr: &str);
    /// Record connection start (for LeastConn).
    fn on_connect(&self, _addr: &str) {}
    /// Record connection end (for LeastConn).
    fn on_disconnect(&self, _addr: &str) {}
    /// Get a snapshot of target statuses for monitoring.
    ///
    /// # Notes
    /// - Balancers that track live connections should report them in `connections`.
    /// - Balancers without connection tracking should return `connections = 0`.
    fn get_statuses(&self) -> Vec<TargetStatus>;
}

/// Build a status snapshot for targets that do not track connections.
fn statuses_from_targets(targets: &[ResolvedTarget]) -> Vec<TargetStatus> {
    targets
        .iter()
        .map(|t| TargetStatus {
            addr: t.addr.clone(),
            healthy: t.healthy,
            weight: t.weight,
            connections: 0,
        })
        .collect()
}

/// Round-robin load balancer.
pub struct RoundRobinBalancer {
    targets: RwLock<Vec<ResolvedTarget>>,
    index: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            index: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RoundRobinBalancer {
    fn select(&self) -> Option<String> {
        let targets = self.targets.read();
        let healthy: Vec<_> = targets.iter().filter(|t| t.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Some(healthy[idx].addr.clone())
    }

    fn update_targets(&self, targets: Vec<ResolvedTarget>) {
        *self.targets.write() = targets;
    }

    fn mark_unhealthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = false;
        }
    }

    fn mark_healthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = true;
        }
    }

    fn get_statuses(&self) -> Vec<TargetStatus> {
        let targets = self.targets.read();
        statuses_from_targets(&targets)
    }
}

/// Random load balancer.
pub struct RandomBalancer {
    targets: RwLock<Vec<ResolvedTarget>>,
}

impl RandomBalancer {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
        }
    }
}

impl Default for RandomBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RandomBalancer {
    fn select(&self) -> Option<String> {
        let targets = self.targets.read();
        let healthy: Vec<_> = targets.iter().filter(|t| t.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        // Simple pseudo-random using time
        let idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as usize)
            .unwrap_or(0))
            % healthy.len();
        Some(healthy[idx].addr.clone())
    }

    fn update_targets(&self, targets: Vec<ResolvedTarget>) {
        *self.targets.write() = targets;
    }

    fn mark_unhealthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = false;
        }
    }

    fn mark_healthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = true;
        }
    }

    fn get_statuses(&self) -> Vec<TargetStatus> {
        let targets = self.targets.read();
        statuses_from_targets(&targets)
    }
}

/// Weighted load balancer (weighted round-robin).
pub struct WeightedBalancer {
    targets: RwLock<Vec<ResolvedTarget>>,
    index: AtomicUsize,
}

impl WeightedBalancer {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            index: AtomicUsize::new(0),
        }
    }
}

impl Default for WeightedBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for WeightedBalancer {
    fn select(&self) -> Option<String> {
        let targets = self.targets.read();
        let healthy: Vec<_> = targets.iter().filter(|t| t.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        // Build weighted list
        let total_weight: u32 = healthy.iter().map(|t| t.weight).sum();
        if total_weight == 0 {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) as u32 % total_weight;
        let mut acc = 0u32;
        for t in &healthy {
            acc += t.weight;
            if idx < acc {
                return Some(t.addr.clone());
            }
        }
        healthy.last().map(|t| t.addr.clone())
    }

    fn update_targets(&self, targets: Vec<ResolvedTarget>) {
        *self.targets.write() = targets;
    }

    fn mark_unhealthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = false;
        }
    }

    fn mark_healthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.addr == addr) {
            t.healthy = true;
        }
    }

    fn get_statuses(&self) -> Vec<TargetStatus> {
        let targets = self.targets.read();
        statuses_from_targets(&targets)
    }
}

/// Target with connection count for LeastConn.
struct LeastConnTarget {
    target: ResolvedTarget,
    connections: AtomicU64,
}

/// Least-connections load balancer.
pub struct LeastConnBalancer {
    targets: RwLock<Vec<LeastConnTarget>>,
}

impl LeastConnBalancer {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
        }
    }
}

impl Default for LeastConnBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for LeastConnBalancer {
    fn select(&self) -> Option<String> {
        let targets = self.targets.read();
        targets
            .iter()
            .filter(|t| t.target.healthy)
            .min_by_key(|t| t.connections.load(Ordering::Relaxed))
            .map(|t| t.target.addr.clone())
    }

    fn update_targets(&self, targets: Vec<ResolvedTarget>) {
        let mut store = self.targets.write();
        // Preserve connection counts in O(n) by indexing the previous targets.
        let old_connections: HashMap<_, _> = store
            .iter()
            .map(|old| {
                (
                    old.target.addr.clone(),
                    old.connections.load(Ordering::Relaxed),
                )
            })
            .collect();
        let new_targets: Vec<_> = targets
            .into_iter()
            .map(|t| {
                let conns = old_connections.get(&t.addr).copied().unwrap_or(0);
                LeastConnTarget {
                    target: t,
                    connections: AtomicU64::new(conns),
                }
            })
            .collect();
        *store = new_targets;
    }

    fn mark_unhealthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.target.addr == addr) {
            t.target.healthy = false;
        }
    }

    fn mark_healthy(&self, addr: &str) {
        let mut targets = self.targets.write();
        if let Some(t) = targets.iter_mut().find(|t| t.target.addr == addr) {
            t.target.healthy = true;
        }
    }

    fn on_connect(&self, addr: &str) {
        let targets = self.targets.read();
        if let Some(t) = targets.iter().find(|t| t.target.addr == addr) {
            t.connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_disconnect(&self, addr: &str) {
        let targets = self.targets.read();
        if let Some(t) = targets.iter().find(|t| t.target.addr == addr) {
            t.connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn get_statuses(&self) -> Vec<TargetStatus> {
        let targets = self.targets.read();
        targets
            .iter()
            .map(|t| TargetStatus {
                addr: t.target.addr.clone(),
                healthy: t.target.healthy,
                weight: t.target.weight,
                connections: t.connections.load(Ordering::Relaxed),
            })
            .collect()
    }
}

/// Create a balancer from algorithm type.
pub fn create_balancer(algo: super::LoadBalanceAlgo) -> Box<dyn LoadBalancer> {
    match algo {
        super::LoadBalanceAlgo::RoundRobin => Box::new(RoundRobinBalancer::new()),
        super::LoadBalanceAlgo::Random => Box::new(RandomBalancer::new()),
        super::LoadBalanceAlgo::Weighted => Box::new(WeightedBalancer::new()),
        super::LoadBalanceAlgo::LeastConn => Box::new(LeastConnBalancer::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_targets() -> Vec<ResolvedTarget> {
        vec![
            ResolvedTarget {
                addr: "a".into(),
                weight: 1,
                healthy: true,
            },
            ResolvedTarget {
                addr: "b".into(),
                weight: 2,
                healthy: true,
            },
            ResolvedTarget {
                addr: "c".into(),
                weight: 1,
                healthy: true,
            },
        ]
    }

    #[test]
    fn test_round_robin() {
        let lb = RoundRobinBalancer::new();
        lb.update_targets(make_targets());

        let mut results = Vec::new();
        for _ in 0..6 {
            results.push(lb.select().unwrap());
        }
        // Should cycle through a, b, c
        assert_eq!(results[0], results[3]);
        assert_eq!(results[1], results[4]);
        assert_eq!(results[2], results[5]);
    }

    #[test]
    fn test_weighted() {
        let lb = WeightedBalancer::new();
        lb.update_targets(make_targets());

        // Total weight = 4, so in 4 selections: a=1, b=2, c=1
        let mut counts = std::collections::HashMap::new();
        for _ in 0..400 {
            let addr = lb.select().unwrap();
            *counts.entry(addr).or_insert(0) += 1;
        }
        // b should have ~2x the count of a or c
        assert!(counts.get("b").unwrap_or(&0) > counts.get("a").unwrap_or(&0));
    }

    #[test]
    fn test_least_conn() {
        let lb = LeastConnBalancer::new();
        lb.update_targets(make_targets());

        // All have 0 connections, should pick first
        let first = lb.select().unwrap();
        lb.on_connect(&first);

        // Now first has 1 connection, should pick another
        let second = lb.select().unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn test_mark_unhealthy() {
        let lb = RoundRobinBalancer::new();
        lb.update_targets(make_targets());

        lb.mark_unhealthy("b");

        // Should only return a and c
        let mut results = std::collections::HashSet::new();
        for _ in 0..10 {
            results.insert(lb.select().unwrap());
        }
        assert!(!results.contains("b"));
        assert!(results.contains("a"));
        assert!(results.contains("c"));
    }
}
