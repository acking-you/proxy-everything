//! Memory-bounded metrics storage with DashMap sharding.
//!
//! Provides time-bucketed aggregation and top-N tracking for proxy metrics.
//!
//! # Data Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Metrics Data Flow                                │
//! │                                                                         │
//! │  Connection ──► record_connection() ──┬──► shard[hash(dest_host)]      │
//! │   Completed                           │         │                       │
//! │                                       │         ├──► recent_visits      │
//! │                                       │         ├──► current_minute     │
//! │                                       │         ├──► top_ips            │
//! │                                       │         └──► top_hosts          │
//! │                                       │                                 │
//! │  Query ──────► get_*() ──────────────►│ merge all shards               │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Memory Bounds
//!
//! - Recent visits: FIFO eviction per shard (default 10,000 total)
//! - Minute buckets: Rolling window per shard (default 60 minutes)
//! - Hour buckets: Rolling window per shard (default 24 hours)
//! - Day buckets: Rolling window per shard (default 7 days)
//! - Top-N entries: Trimmed when exceeding 2x limit per shard

mod shard;
mod types;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;
use shard::ShardData;
use types::shard_index;
pub use types::{
    ConnectionRecord, Granularity, MetricsConfig, RealtimeSnapshot, RealtimeStats, SiteVisit,
    SystemStats, TimeBucket, TopCategory, TrafficStats, current_time_ms,
};

/// Memory-bounded metrics storage with DashMap sharding.
pub struct MetricsStore {
    config: MetricsConfig,
    /// Shards indexed by hash(dest_host) % shard_count.
    shards: DashMap<usize, RwLock<ShardData>>,
    /// Global visit count for eviction trigger.
    total_visits: AtomicUsize,
    /// Realtime stats (global, lock-free).
    pub realtime: RealtimeStats,
}

impl MetricsStore {
    pub fn new(config: MetricsConfig) -> Self {
        let shards = DashMap::with_capacity(config.shard_count);
        // Pre-create all shards
        for i in 0..config.shard_count {
            shards.insert(i, RwLock::new(ShardData::default()));
        }
        Self {
            config,
            shards,
            total_visits: AtomicUsize::new(0),
            realtime: RealtimeStats::default(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(MetricsConfig::default())
    }

    /// Initialize realtime stats (call on startup).
    pub fn init_realtime(&self) {
        self.realtime
            .started_at_ms
            .store(current_time_ms() as u64, Ordering::Relaxed);
    }

    /// Record a completed connection.
    pub fn record_connection(&self, record: ConnectionRecord) {
        let now_ms = current_time_ms();
        let minute_ts = (now_ms / 60_000) * 60_000;
        let shard_idx = shard_index(&record.dest_host, self.config.shard_count);
        let dest_host: Arc<str> = record.dest_host.clone().into();
        let visit = record.to_site_visit();

        if let Some(shard_ref) = self.shards.get(&shard_idx) {
            let mut shard = shard_ref.write();

            // Check minute rotation
            shard.maybe_rotate_minute(
                minute_ts as u64,
                self.config.max_minute_buckets,
                self.config.max_hour_buckets,
                self.config.max_day_buckets,
            );

            // Record visit
            shard.record_visit(dest_host, visit);

            // Trim top-N if needed
            shard.trim_top_n(self.config.max_top_entries);
        }

        // Update global count and maybe evict
        let prev = self.total_visits.fetch_add(1, Ordering::Relaxed);
        if prev + 1 > self.config.max_recent_visits {
            self.evict();
        }
    }

    /// Evict oldest visits across shards.
    fn evict(&self) {
        let target = self.config.max_recent_visits * 9 / 10;

        loop {
            let current = self.total_visits.load(Ordering::Relaxed);
            if current <= target {
                break;
            }

            let mut evicted_this_round = 0;

            for shard_ref in self.shards.iter() {
                let mut shard = shard_ref.value().write();
                let evicted = shard.evict(self.config.evict_per_shard);
                evicted_this_round += evicted;
                self.total_visits.fetch_sub(evicted, Ordering::Relaxed);
            }

            if evicted_this_round == 0 {
                break;
            }
        }
    }

    /// Get recent connections (merged from all shards).
    pub fn get_recent_connections(&self, limit: usize) -> Vec<ConnectionRecord> {
        let mut all_visits: Vec<(Arc<str>, SiteVisit)> = Vec::new();

        for shard_ref in self.shards.iter() {
            let shard = shard_ref.value().read();
            for (host, visits) in shard.recent_visits.iter() {
                for visit in visits.iter() {
                    all_visits.push((host.clone(), visit.clone()));
                }
            }
        }

        // Sort by ended_at_ms descending
        all_visits.sort_by_key(|b| std::cmp::Reverse(b.1.ended_at_ms));
        all_visits.truncate(limit);

        // Convert to ConnectionRecord
        all_visits
            .into_iter()
            .enumerate()
            .map(|(idx, (host, v))| ConnectionRecord {
                id: idx as u64,
                client_ip: v.client_ip,
                dest_host: host.to_string(),
                dest_port: v.dest_port,
                bytes_up: v.bytes_up,
                bytes_down: v.bytes_down,
                latency_ms: v.latency_ms,
                duration_ms: v.duration_ms,
                started_at_ms: v.started_at_ms,
                ended_at_ms: v.ended_at_ms,
                error: v.error,
            })
            .collect()
    }

    /// Get time buckets by granularity (merged from all shards).
    pub fn get_time_buckets(&self, granularity: Granularity, count: usize) -> Vec<TimeBucket> {
        use std::collections::HashMap;

        let mut merged: HashMap<i64, TimeBucket> = HashMap::new();

        for shard_ref in self.shards.iter() {
            let shard = shard_ref.value().read();
            let buckets = match granularity {
                Granularity::Minute => &shard.minute_buckets,
                Granularity::Hour => &shard.hour_buckets,
                Granularity::Day => &shard.day_buckets,
            };

            for bucket in buckets.iter() {
                merged
                    .entry(bucket.timestamp_ms)
                    .or_insert_with(|| TimeBucket {
                        timestamp_ms: bucket.timestamp_ms,
                        ..Default::default()
                    })
                    .merge(bucket);
            }
        }

        let mut result: Vec<_> = merged.into_values().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.timestamp_ms));
        result.truncate(count);
        result
    }

    /// Get top-N entries (merged from all shards).
    pub fn get_top_n(&self, category: TopCategory, limit: usize) -> Vec<(String, TrafficStats)> {
        use std::collections::HashMap;

        let mut merged: HashMap<String, TrafficStats> = HashMap::new();

        for shard_ref in self.shards.iter() {
            let shard = shard_ref.value().read();
            let map = match category {
                TopCategory::Ips => &shard.top_ips,
                TopCategory::Hosts => &shard.top_hosts,
            };

            for (key, stats) in map.iter() {
                let entry = merged.entry(key.clone()).or_default();
                entry.connections += stats.connections;
                entry.bytes_up += stats.bytes_up;
                entry.bytes_down += stats.bytes_down;
                if stats.last_seen_ms > entry.last_seen_ms {
                    entry.last_seen_ms = stats.last_seen_ms;
                }
            }
        }

        let mut entries: Vec<_> = merged.into_iter().collect();
        entries.sort_by(|a, b| {
            let a_total = a.1.bytes_up + a.1.bytes_down;
            let b_total = b.1.bytes_up + b.1.bytes_down;
            b_total.cmp(&a_total)
        });
        entries.truncate(limit);
        entries
    }

    /// Get realtime stats snapshot.
    pub fn get_realtime_snapshot(&self) -> RealtimeSnapshot {
        RealtimeSnapshot::from(&self.realtime)
    }

    /// Update process-level stats (call periodically).
    pub fn update_process_stats(&self, cpu_percent: f32, memory_bytes: u64) {
        self.realtime
            .cpu_percent_x1000
            .store((cpu_percent * 1000.0) as u32, Ordering::Relaxed);
        self.realtime
            .memory_bytes
            .store(memory_bytes, Ordering::Relaxed);
    }

    /// Update system-level stats (call periodically).
    pub fn update_system_stats(&self, stats: SystemStats) {
        self.realtime
            .sys_cpu_percent_x1000
            .store((stats.cpu_percent * 1000.0) as u32, Ordering::Relaxed);
        self.realtime
            .sys_memory_used
            .store(stats.memory_used, Ordering::Relaxed);
        self.realtime
            .sys_memory_total
            .store(stats.memory_total, Ordering::Relaxed);
        self.realtime
            .sys_net_recv_bytes
            .store(stats.net_recv_bytes, Ordering::Relaxed);
        self.realtime
            .sys_net_sent_bytes
            .store(stats.net_sent_bytes, Ordering::Relaxed);
        self.realtime
            .sys_net_recv_rate
            .store(stats.net_recv_rate, Ordering::Relaxed);
        self.realtime
            .sys_net_sent_rate
            .store(stats.net_sent_rate, Ordering::Relaxed);
        self.realtime
            .sys_disk_used
            .store(stats.disk_used, Ordering::Relaxed);
        self.realtime
            .sys_disk_total
            .store(stats.disk_total, Ordering::Relaxed);
    }

    /// Increment active connections.
    pub fn inc_active(&self) {
        self.realtime
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections.
    pub fn dec_active(&self) {
        self.realtime
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_connection() {
        let store = MetricsStore::with_default_config();
        store.init_realtime();

        let record = ConnectionRecord {
            id: 0,
            client_ip: "192.168.1.1".to_string(),
            dest_host: "example.com".to_string(),
            dest_port: 443,
            bytes_up: 1000,
            bytes_down: 5000,
            latency_ms: Some(50),
            duration_ms: 100,
            started_at_ms: current_time_ms(),
            ended_at_ms: current_time_ms(),
            error: None,
        };

        store.record_connection(record);

        let recent = store.get_recent_connections(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].client_ip, "192.168.1.1");
    }

    #[test]
    fn test_sharding() {
        let store = MetricsStore::with_default_config();

        // Record connections to different hosts
        for i in 0..100 {
            let record = ConnectionRecord {
                id: 0,
                client_ip: format!("192.168.1.{}", i % 256),
                dest_host: format!("host{}.com", i),
                dest_port: 443,
                bytes_up: 100,
                bytes_down: 200,
                latency_ms: Some(10),
                duration_ms: 50,
                started_at_ms: current_time_ms(),
                ended_at_ms: current_time_ms(),
                error: None,
            };
            store.record_connection(record);
        }

        let recent = store.get_recent_connections(100);
        assert_eq!(recent.len(), 100);
    }

    #[test]
    fn test_eviction() {
        let config = MetricsConfig {
            max_recent_visits: 10,
            evict_per_shard: 2,
            ..Default::default()
        };
        let store = MetricsStore::new(config);

        // Record more than max
        for i in 0..20 {
            let record = ConnectionRecord {
                id: 0,
                client_ip: "192.168.1.1".to_string(),
                dest_host: format!("host{}.com", i),
                dest_port: 443,
                bytes_up: 100,
                bytes_down: 200,
                latency_ms: None,
                duration_ms: 50,
                started_at_ms: current_time_ms(),
                ended_at_ms: current_time_ms(),
                error: None,
            };
            store.record_connection(record);
        }

        // Should have evicted to ~90% of max
        let total = store.total_visits.load(Ordering::Relaxed);
        assert!(total <= 10, "Expected <= 10, got {}", total);
    }
}
