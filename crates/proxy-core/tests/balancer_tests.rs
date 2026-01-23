//! Unit tests for load balancer algorithms.

use proxy_core::relay::{
    LeastConnBalancer, LoadBalanceAlgo, LoadBalancer, RandomBalancer, ResolvedTarget,
    RoundRobinBalancer, WeightedBalancer, create_balancer,
};
use std::collections::HashMap;

fn make_targets(count: usize) -> Vec<ResolvedTarget> {
    (0..count)
        .map(|i| ResolvedTarget {
            addr: format!("10.0.0.{}:1081", i + 1),
            weight: 1,
            healthy: true,
        })
        .collect()
}

fn make_weighted_targets() -> Vec<ResolvedTarget> {
    vec![
        ResolvedTarget {
            addr: "a:1".into(),
            weight: 1,
            healthy: true,
        },
        ResolvedTarget {
            addr: "b:1".into(),
            weight: 2,
            healthy: true,
        },
        ResolvedTarget {
            addr: "c:1".into(),
            weight: 1,
            healthy: true,
        },
    ]
}

#[test]
fn test_round_robin_distribution() {
    let lb = RoundRobinBalancer::new();
    lb.update_targets(make_targets(3));

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..300 {
        let addr = lb.select().unwrap();
        *counts.entry(addr).or_insert(0) += 1;
    }

    // Each should get exactly 100
    assert_eq!(counts.len(), 3);
    for count in counts.values() {
        assert_eq!(*count, 100);
    }
}

#[test]
fn test_round_robin_skips_unhealthy() {
    let lb = RoundRobinBalancer::new();
    lb.update_targets(make_targets(3));

    lb.mark_unhealthy("10.0.0.2:1081");

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..100 {
        let addr = lb.select().unwrap();
        *counts.entry(addr).or_insert(0) += 1;
    }

    assert!(!counts.contains_key("10.0.0.2:1081"));
    assert_eq!(counts.len(), 2);
}

#[test]
fn test_round_robin_recovers_healthy() {
    let lb = RoundRobinBalancer::new();
    lb.update_targets(make_targets(3));

    lb.mark_unhealthy("10.0.0.2:1081");
    lb.mark_healthy("10.0.0.2:1081");

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..300 {
        let addr = lb.select().unwrap();
        *counts.entry(addr).or_insert(0) += 1;
    }

    assert_eq!(counts.len(), 3);
}

#[test]
fn test_weighted_distribution() {
    let lb = WeightedBalancer::new();
    lb.update_targets(make_weighted_targets());

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..400 {
        let addr = lb.select().unwrap();
        *counts.entry(addr).or_insert(0) += 1;
    }

    // Total weight = 4, so in 400 selections:
    // a: 100, b: 200, c: 100
    assert_eq!(*counts.get("a:1").unwrap(), 100);
    assert_eq!(*counts.get("b:1").unwrap(), 200);
    assert_eq!(*counts.get("c:1").unwrap(), 100);
}

#[test]
fn test_random_distribution() {
    let lb = RandomBalancer::new();
    lb.update_targets(make_targets(3));

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..300 {
        let addr = lb.select().unwrap();
        *counts.entry(addr).or_insert(0) += 1;
    }

    // All targets should be selected at least once
    assert_eq!(counts.len(), 3);
    for count in counts.values() {
        assert!(*count > 0);
    }
}

#[test]
fn test_least_conn_prefers_idle() {
    let lb = LeastConnBalancer::new();
    lb.update_targets(make_targets(3));

    // First selection - all have 0 connections
    let first = lb.select().unwrap();
    lb.on_connect(&first);

    // Second selection - should pick different one
    let second = lb.select().unwrap();
    assert_ne!(first, second);
    lb.on_connect(&second);

    // Third selection - should pick the remaining one
    let third = lb.select().unwrap();
    assert_ne!(third, first);
    assert_ne!(third, second);
}

#[test]
fn test_least_conn_rebalances_on_disconnect() {
    let lb = LeastConnBalancer::new();
    lb.update_targets(make_targets(2));

    // Connect to first
    let first = lb.select().unwrap();
    lb.on_connect(&first);
    lb.on_connect(&first);

    // Second should be preferred now
    let second = lb.select().unwrap();
    assert_ne!(first, second);

    // Disconnect from first
    lb.on_disconnect(&first);
    lb.on_disconnect(&first);

    // Now first should be preferred again
    let next = lb.select().unwrap();
    assert_eq!(next, first);
}

#[test]
fn test_empty_targets_returns_none() {
    let lb = RoundRobinBalancer::new();
    assert!(lb.select().is_none());

    lb.update_targets(Vec::new());
    assert!(lb.select().is_none());
}

#[test]
fn test_all_unhealthy_returns_none() {
    let lb = RoundRobinBalancer::new();
    lb.update_targets(make_targets(2));

    lb.mark_unhealthy("10.0.0.1:1081");
    lb.mark_unhealthy("10.0.0.2:1081");

    assert!(lb.select().is_none());
}

#[test]
fn test_create_balancer_factory() {
    let rr = create_balancer(LoadBalanceAlgo::RoundRobin);
    let random = create_balancer(LoadBalanceAlgo::Random);
    let weighted = create_balancer(LoadBalanceAlgo::Weighted);
    let lc = create_balancer(LoadBalanceAlgo::LeastConn);

    // All should work
    for lb in [rr, random, weighted, lc] {
        lb.update_targets(make_targets(2));
        assert!(lb.select().is_some());
    }
}

#[test]
fn test_update_targets_preserves_connections() {
    let lb = LeastConnBalancer::new();
    lb.update_targets(make_targets(2));

    // Add connections to first target
    lb.on_connect("10.0.0.1:1081");
    lb.on_connect("10.0.0.1:1081");

    // Update targets (same addresses)
    lb.update_targets(make_targets(2));

    // Connection count should be preserved - second target should be preferred
    let selected = lb.select().unwrap();
    assert_eq!(selected, "10.0.0.2:1081");
}

#[test]
fn test_status_reports_least_conn_connections() {
    let lb = LeastConnBalancer::new();
    lb.update_targets(make_targets(2));

    lb.on_connect("10.0.0.1:1081");
    lb.on_connect("10.0.0.1:1081");

    let statuses = lb.get_statuses();
    let first = statuses
        .iter()
        .find(|status| status.addr == "10.0.0.1:1081")
        .unwrap();
    let second = statuses
        .iter()
        .find(|status| status.addr == "10.0.0.2:1081")
        .unwrap();

    assert_eq!(first.connections, 2);
    assert_eq!(second.connections, 0);
}
