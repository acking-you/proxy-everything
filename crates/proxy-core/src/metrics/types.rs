//! Type definitions for metrics module.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Site visit record (without global ID).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteVisit {
    pub client_ip: String,
    pub dest_port: u16,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub latency_ms: Option<u64>,
    pub duration_ms: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub error: Option<String>,
}

/// Connection record for API compatibility.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionRecord {
    pub id: u64,
    pub client_ip: String,
    pub dest_host: String,
    pub dest_port: u16,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub latency_ms: Option<u64>,
    pub duration_ms: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub error: Option<String>,
}

impl ConnectionRecord {
    /// Convert to SiteVisit (drops id and dest_host).
    pub fn to_site_visit(&self) -> SiteVisit {
        SiteVisit {
            client_ip: self.client_ip.clone(),
            dest_port: self.dest_port,
            bytes_up: self.bytes_up,
            bytes_down: self.bytes_down,
            latency_ms: self.latency_ms,
            duration_ms: self.duration_ms,
            started_at_ms: self.started_at_ms,
            ended_at_ms: self.ended_at_ms,
            error: self.error.clone(),
        }
    }
}

/// System-level statistics for update.
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub net_recv_bytes: u64,
    pub net_sent_bytes: u64,
    pub net_recv_rate: u64,
    pub net_sent_rate: u64,
    pub disk_used: u64,
    pub disk_total: u64,
}

/// Time bucket for aggregated metrics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TimeBucket {
    pub timestamp_ms: i64,
    pub total_connections: u64,
    pub total_bytes_up: u64,
    pub total_bytes_down: u64,
    pub total_latency_ms: u64,
    pub latency_count: u64,
    pub error_count: u64,
}

impl TimeBucket {
    pub fn avg_latency_ms(&self) -> Option<f64> {
        if self.latency_count > 0 {
            Some(self.total_latency_ms as f64 / self.latency_count as f64)
        } else {
            None
        }
    }

    pub fn merge(&mut self, other: &TimeBucket) {
        self.total_connections += other.total_connections;
        self.total_bytes_up += other.total_bytes_up;
        self.total_bytes_down += other.total_bytes_down;
        self.total_latency_ms += other.total_latency_ms;
        self.latency_count += other.latency_count;
        self.error_count += other.error_count;
    }
}

/// Traffic statistics for top-N tracking.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TrafficStats {
    pub connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_seen_ms: i64,
}

/// Realtime statistics (lock-free).
#[derive(Debug, Default)]
pub struct RealtimeStats {
    pub active_connections: AtomicU64,
    pub cpu_percent_x1000: AtomicU32,
    pub memory_bytes: AtomicU64,
    pub started_at_ms: AtomicU64,
    pub sys_cpu_percent_x1000: AtomicU32,
    pub sys_memory_used: AtomicU64,
    pub sys_memory_total: AtomicU64,
    pub sys_net_recv_bytes: AtomicU64,
    pub sys_net_sent_bytes: AtomicU64,
    pub sys_net_recv_rate: AtomicU64,
    pub sys_net_sent_rate: AtomicU64,
    pub sys_disk_used: AtomicU64,
    pub sys_disk_total: AtomicU64,
}

impl RealtimeStats {
    pub fn cpu_percent(&self) -> f32 {
        self.cpu_percent_x1000.load(Ordering::Relaxed) as f32 / 1000.0
    }

    pub fn sys_cpu_percent(&self) -> f32 {
        self.sys_cpu_percent_x1000.load(Ordering::Relaxed) as f32 / 1000.0
    }

    pub fn uptime_secs(&self) -> u64 {
        let started = self.started_at_ms.load(Ordering::Relaxed);
        let now = current_time_ms() as u64;
        now.saturating_sub(started) / 1000
    }
}

/// Snapshot of realtime stats for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RealtimeSnapshot {
    pub active_connections: u64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub uptime_secs: u64,
    #[serde(default)]
    pub sys_cpu_percent: f32,
    #[serde(default)]
    pub sys_memory_used: u64,
    #[serde(default)]
    pub sys_memory_total: u64,
    #[serde(default)]
    pub sys_net_recv_bytes: u64,
    #[serde(default)]
    pub sys_net_sent_bytes: u64,
    #[serde(default)]
    pub sys_net_recv_rate: u64,
    #[serde(default)]
    pub sys_net_sent_rate: u64,
    #[serde(default)]
    pub sys_disk_used: u64,
    #[serde(default)]
    pub sys_disk_total: u64,
}

impl From<&RealtimeStats> for RealtimeSnapshot {
    fn from(stats: &RealtimeStats) -> Self {
        Self {
            active_connections: stats.active_connections.load(Ordering::Relaxed),
            cpu_percent: stats.cpu_percent(),
            memory_bytes: stats.memory_bytes.load(Ordering::Relaxed),
            uptime_secs: stats.uptime_secs(),
            sys_cpu_percent: stats.sys_cpu_percent(),
            sys_memory_used: stats.sys_memory_used.load(Ordering::Relaxed),
            sys_memory_total: stats.sys_memory_total.load(Ordering::Relaxed),
            sys_net_recv_bytes: stats.sys_net_recv_bytes.load(Ordering::Relaxed),
            sys_net_sent_bytes: stats.sys_net_sent_bytes.load(Ordering::Relaxed),
            sys_net_recv_rate: stats.sys_net_recv_rate.load(Ordering::Relaxed),
            sys_net_sent_rate: stats.sys_net_sent_rate.load(Ordering::Relaxed),
            sys_disk_used: stats.sys_disk_used.load(Ordering::Relaxed),
            sys_disk_total: stats.sys_disk_total.load(Ordering::Relaxed),
        }
    }
}

/// Time granularity for bucket queries.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    Minute,
    Hour,
    Day,
}

/// Category for top-N queries.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopCategory {
    Ips,
    Hosts,
}

/// Configuration for metrics store.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub shard_count: usize,
    pub max_recent_visits: usize,
    pub max_minute_buckets: usize,
    pub max_hour_buckets: usize,
    pub max_day_buckets: usize,
    pub max_top_entries: usize,
    pub evict_per_shard: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            shard_count: 16,
            max_recent_visits: 10000,
            max_minute_buckets: 60,
            max_hour_buckets: 24,
            max_day_buckets: 7,
            max_top_entries: 100,
            evict_per_shard: 3,
        }
    }
}

pub fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Compute shard index from dest_host.
pub fn shard_index(dest_host: &str, shard_count: usize) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dest_host.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}
