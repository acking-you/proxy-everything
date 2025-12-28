//! Memory-bounded metrics storage with LRU eviction.
//!
//! Provides time-bucketed aggregation and top-N tracking for proxy metrics.
//!
//! # Data Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Metrics Data Flow                                │
//! │                                                                         │
//! │  Connection ──► record_connection() ──┬──► recent_connections (LRU)    │
//! │   Completed                           │                                 │
//! │                                       ├──► current_minute bucket        │
//! │                                       │         │                       │
//! │                                       │         ▼ (rotate every minute) │
//! │                                       │    minute_buckets (60)          │
//! │                                       │         │                       │
//! │                                       │         ▼ (aggregate to hour)   │
//! │                                       │    hour_buckets (24)            │
//! │                                       │         │                       │
//! │                                       │         ▼ (aggregate to day)    │
//! │                                       │    day_buckets (7)              │
//! │                                       │                                 │
//! │                                       ├──► top_ips (HashMap + trim)     │
//! │                                       │                                 │
//! │                                       └──► top_hosts (HashMap + trim)   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Memory Bounds
//!
//! - Recent connections: LRU cache (default 10,000 entries)
//! - Minute buckets: Rolling window (default 60 minutes)
//! - Hour buckets: Rolling window (default 24 hours)
//! - Day buckets: Rolling window (default 7 days)
//! - Top-N entries: Trimmed when exceeding 2x limit

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use lru::LruCache;
use std::num::NonZeroUsize;

/// Connection record stored in memory.
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

/// System-level statistics for update.
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
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

    fn merge(&mut self, other: &TimeBucket) {
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
    // Process-level stats
    pub cpu_percent_x100: AtomicU32,
    pub memory_bytes: AtomicU64,
    pub started_at_ms: AtomicU64,
    // System-level stats
    pub sys_cpu_percent_x100: AtomicU32,
    pub sys_memory_used: AtomicU64,
    pub sys_memory_total: AtomicU64,
    pub sys_disk_read_bytes: AtomicU64,
    pub sys_disk_write_bytes: AtomicU64,
    pub sys_disk_used: AtomicU64,
    pub sys_disk_total: AtomicU64,
}

impl RealtimeStats {
    pub fn cpu_percent(&self) -> f32 {
        self.cpu_percent_x100.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn sys_cpu_percent(&self) -> f32 {
        self.sys_cpu_percent_x100.load(Ordering::Relaxed) as f32 / 100.0
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
    // System-level stats
    #[serde(default)]
    pub sys_cpu_percent: f32,
    #[serde(default)]
    pub sys_memory_used: u64,
    #[serde(default)]
    pub sys_memory_total: u64,
    #[serde(default)]
    pub sys_disk_read_bytes: u64,
    #[serde(default)]
    pub sys_disk_write_bytes: u64,
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
            sys_disk_read_bytes: stats.sys_disk_read_bytes.load(Ordering::Relaxed),
            sys_disk_write_bytes: stats.sys_disk_write_bytes.load(Ordering::Relaxed),
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
    pub max_recent_connections: usize,
    pub max_minute_buckets: usize,
    pub max_hour_buckets: usize,
    pub max_day_buckets: usize,
    pub max_top_entries: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            max_recent_connections: 10000,
            max_minute_buckets: 60,
            max_hour_buckets: 24,
            max_day_buckets: 7,
            max_top_entries: 100,
        }
    }
}

/// Memory-bounded metrics storage.
pub struct MetricsStore {
    config: MetricsConfig,
    next_id: AtomicU64,
    recent_connections: RwLock<LruCache<u64, ConnectionRecord>>,
    minute_buckets: RwLock<VecDeque<TimeBucket>>,
    hour_buckets: RwLock<VecDeque<TimeBucket>>,
    day_buckets: RwLock<VecDeque<TimeBucket>>,
    top_ips: RwLock<HashMap<String, TrafficStats>>,
    top_hosts: RwLock<HashMap<String, TrafficStats>>,
    pub realtime: RealtimeStats,
    current_minute: RwLock<TimeBucket>,
    last_minute_ts: AtomicU64,
}

impl MetricsStore {
    pub fn new(config: MetricsConfig) -> Self {
        // Ensure max_recent_connections is at least 1 to avoid panic
        let cap = NonZeroUsize::new(config.max_recent_connections.max(1)).unwrap();
        Self {
            config,
            next_id: AtomicU64::new(1),
            recent_connections: RwLock::new(LruCache::new(cap)),
            minute_buckets: RwLock::new(VecDeque::new()),
            hour_buckets: RwLock::new(VecDeque::new()),
            day_buckets: RwLock::new(VecDeque::new()),
            top_ips: RwLock::new(HashMap::new()),
            top_hosts: RwLock::new(HashMap::new()),
            realtime: RealtimeStats::default(),
            current_minute: RwLock::new(TimeBucket::default()),
            last_minute_ts: AtomicU64::new(0),
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
    ///
    /// Updates: current_minute bucket, top_ips, top_hosts, recent_connections.
    /// Lock acquisition order: current_minute -> top_ips -> top_hosts -> recent_connections
    pub fn record_connection(&self, record: ConnectionRecord) {
        let now_ms = current_time_ms();
        let minute_ts = (now_ms / 60_000) * 60_000;

        // Check if we need to rotate minute bucket
        self.maybe_rotate_minute(minute_ts as u64);

        // Prepare data for top-N updates (minimize lock hold time)
        let client_ip = record.client_ip.clone();
        let dest_host = record.dest_host.clone();
        let bytes_up = record.bytes_up;
        let bytes_down = record.bytes_down;
        let latency_ms = record.latency_ms;
        let has_error = record.error.is_some();

        // Update current minute bucket
        {
            let mut bucket = self.current_minute.write().unwrap();
            bucket.total_connections += 1;
            bucket.total_bytes_up += bytes_up;
            bucket.total_bytes_down += bytes_down;
            if let Some(lat) = latency_ms {
                bucket.total_latency_ms += lat;
                bucket.latency_count += 1;
            }
            if has_error {
                bucket.error_count += 1;
            }
        }

        // Update top-N (separate lock scopes)
        self.update_top_entry(&self.top_ips, &client_ip, bytes_up, bytes_down, now_ms);
        self.update_top_entry(&self.top_hosts, &dest_host, bytes_up, bytes_down, now_ms);

        // Store in recent connections
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut record = record;
        record.id = id;
        self.recent_connections.write().unwrap().put(id, record);
    }

    fn update_top_entry(
        &self,
        map: &RwLock<HashMap<String, TrafficStats>>,
        key: &str,
        bytes_up: u64,
        bytes_down: u64,
        now_ms: i64,
    ) {
        let mut top = map.write().unwrap();
        let entry = top.entry(key.to_string()).or_default();
        entry.connections += 1;
        entry.bytes_up += bytes_up;
        entry.bytes_down += bytes_down;
        entry.last_seen_ms = now_ms;
        self.trim_top_n(&mut top);
    }

    fn trim_top_n(&self, map: &mut HashMap<String, TrafficStats>) {
        if map.len() > self.config.max_top_entries * 2 {
            // Sort by total bytes and keep top N
            let mut entries: Vec<_> = map.drain().collect();
            entries.sort_by(|a, b| {
                let a_total = a.1.bytes_up + a.1.bytes_down;
                let b_total = b.1.bytes_up + b.1.bytes_down;
                b_total.cmp(&a_total)
            });
            entries.truncate(self.config.max_top_entries);
            map.extend(entries);
        }
    }

    fn maybe_rotate_minute(&self, current_minute_ts: u64) {
        let last = self.last_minute_ts.load(Ordering::Relaxed);
        if last == 0 {
            self.last_minute_ts
                .store(current_minute_ts, Ordering::Relaxed);
            return;
        }

        if current_minute_ts > last {
            // Rotate minute bucket
            let mut bucket = self.current_minute.write().unwrap();
            if bucket.total_connections > 0 {
                bucket.timestamp_ms = last as i64;
                let completed = std::mem::take(&mut *bucket);

                let mut minutes = self.minute_buckets.write().unwrap();
                minutes.push_back(completed.clone());
                while minutes.len() > self.config.max_minute_buckets {
                    if let Some(old) = minutes.pop_front() {
                        self.aggregate_to_hour(old);
                    }
                }
            }
            self.last_minute_ts
                .store(current_minute_ts, Ordering::Relaxed);
        }
    }

    fn aggregate_to_hour(&self, minute_bucket: TimeBucket) {
        let hour_ts = (minute_bucket.timestamp_ms / 3_600_000) * 3_600_000;
        let mut hours = self.hour_buckets.write().unwrap();

        if let Some(last) = hours.back_mut() {
            if last.timestamp_ms == hour_ts {
                last.merge(&minute_bucket);
                return;
            }
        }

        // New hour bucket
        let mut new_bucket = minute_bucket;
        new_bucket.timestamp_ms = hour_ts;
        hours.push_back(new_bucket);

        while hours.len() > self.config.max_hour_buckets {
            if let Some(old) = hours.pop_front() {
                self.aggregate_to_day(old);
            }
        }
    }

    fn aggregate_to_day(&self, hour_bucket: TimeBucket) {
        let day_ts = (hour_bucket.timestamp_ms / 86_400_000) * 86_400_000;
        let mut days = self.day_buckets.write().unwrap();

        if let Some(last) = days.back_mut() {
            if last.timestamp_ms == day_ts {
                last.merge(&hour_bucket);
                return;
            }
        }

        let mut new_bucket = hour_bucket;
        new_bucket.timestamp_ms = day_ts;
        days.push_back(new_bucket);

        while days.len() > self.config.max_day_buckets {
            days.pop_front();
        }
    }

    /// Get recent connections.
    pub fn get_recent_connections(&self, limit: usize) -> Vec<ConnectionRecord> {
        let cache = self.recent_connections.read().unwrap();
        cache.iter().rev().take(limit).map(|(_, v)| v.clone()).collect()
    }

    /// Get time buckets by granularity.
    pub fn get_time_buckets(&self, granularity: Granularity, count: usize) -> Vec<TimeBucket> {
        match granularity {
            Granularity::Minute => {
                let buckets = self.minute_buckets.read().unwrap();
                buckets.iter().rev().take(count).cloned().collect()
            }
            Granularity::Hour => {
                let buckets = self.hour_buckets.read().unwrap();
                buckets.iter().rev().take(count).cloned().collect()
            }
            Granularity::Day => {
                let buckets = self.day_buckets.read().unwrap();
                buckets.iter().rev().take(count).cloned().collect()
            }
        }
    }

    /// Get top-N entries.
    pub fn get_top_n(&self, category: TopCategory, limit: usize) -> Vec<(String, TrafficStats)> {
        let map = match category {
            TopCategory::Ips => self.top_ips.read().unwrap(),
            TopCategory::Hosts => self.top_hosts.read().unwrap(),
        };
        let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
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
            .cpu_percent_x100
            .store((cpu_percent * 100.0) as u32, Ordering::Relaxed);
        self.realtime
            .memory_bytes
            .store(memory_bytes, Ordering::Relaxed);
    }

    /// Update system-level stats (call periodically).
    pub fn update_system_stats(&self, stats: SystemStats) {
        self.realtime
            .sys_cpu_percent_x100
            .store((stats.cpu_percent * 100.0) as u32, Ordering::Relaxed);
        self.realtime
            .sys_memory_used
            .store(stats.memory_used, Ordering::Relaxed);
        self.realtime
            .sys_memory_total
            .store(stats.memory_total, Ordering::Relaxed);
        self.realtime
            .sys_disk_read_bytes
            .store(stats.disk_read_bytes, Ordering::Relaxed);
        self.realtime
            .sys_disk_write_bytes
            .store(stats.disk_write_bytes, Ordering::Relaxed);
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

pub fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
}
