//! Shard data structure for metrics storage.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use indexmap::IndexMap;

use super::types::{SiteVisit, TimeBucket, TrafficStats, current_time_ms};

/// Data stored in each shard.
pub struct ShardData {
    /// Recent visits indexed by dest_host, FIFO order within IndexMap.
    pub recent_visits: IndexMap<Arc<str>, Vec<SiteVisit>>,
    /// Total visit count in this shard.
    pub total_visits: usize,

    /// Current minute accumulator.
    pub current_minute: TimeBucket,
    /// Historical minute buckets.
    pub minute_buckets: VecDeque<TimeBucket>,
    /// Historical hour buckets.
    pub hour_buckets: VecDeque<TimeBucket>,
    /// Historical day buckets.
    pub day_buckets: VecDeque<TimeBucket>,
    /// Last minute timestamp for rotation.
    pub last_minute_ts: u64,

    /// Top IPs by traffic.
    pub top_ips: HashMap<String, TrafficStats>,
    /// Top hosts by traffic.
    pub top_hosts: HashMap<String, TrafficStats>,
}

impl Default for ShardData {
    fn default() -> Self {
        Self {
            recent_visits: IndexMap::new(),
            total_visits: 0,
            current_minute: TimeBucket::default(),
            minute_buckets: VecDeque::new(),
            hour_buckets: VecDeque::new(),
            day_buckets: VecDeque::new(),
            last_minute_ts: 0,
            top_ips: HashMap::new(),
            top_hosts: HashMap::new(),
        }
    }
}

impl ShardData {
    /// Record a site visit.
    pub fn record_visit(&mut self, dest_host: Arc<str>, visit: SiteVisit) {
        let now_ms = current_time_ms();
        let bytes_up = visit.bytes_up;
        let bytes_down = visit.bytes_down;
        let latency_ms = visit.latency_ms;
        let has_error = visit.error.is_some();
        let client_ip = visit.client_ip.clone();

        // Update current minute bucket
        self.current_minute.total_connections += 1;
        self.current_minute.total_bytes_up += bytes_up;
        self.current_minute.total_bytes_down += bytes_down;
        if let Some(lat) = latency_ms {
            self.current_minute.total_latency_ms += lat;
            self.current_minute.latency_count += 1;
        }
        if has_error {
            self.current_minute.error_count += 1;
        }

        // Update top-N
        Self::update_top_entry(&mut self.top_ips, &client_ip, bytes_up, bytes_down, now_ms);
        Self::update_top_entry(
            &mut self.top_hosts,
            dest_host.as_ref(),
            bytes_up,
            bytes_down,
            now_ms,
        );

        // Store visit
        self.recent_visits.entry(dest_host).or_default().push(visit);
        self.total_visits += 1;
    }

    fn update_top_entry(
        map: &mut HashMap<String, TrafficStats>,
        key: &str,
        bytes_up: u64,
        bytes_down: u64,
        now_ms: i64,
    ) {
        let entry = map.entry(key.to_string()).or_default();
        entry.connections += 1;
        entry.bytes_up += bytes_up;
        entry.bytes_down += bytes_down;
        entry.last_seen_ms = now_ms;
    }

    /// Trim top-N maps if they exceed threshold.
    pub fn trim_top_n(&mut self, max_entries: usize) {
        Self::trim_map(&mut self.top_ips, max_entries);
        Self::trim_map(&mut self.top_hosts, max_entries);
    }

    fn trim_map(map: &mut HashMap<String, TrafficStats>, max_entries: usize) {
        if map.len() > max_entries * 2 {
            let mut entries: Vec<_> = map.drain().collect();
            entries.sort_by(|a, b| {
                let a_total = a.1.bytes_up + a.1.bytes_down;
                let b_total = b.1.bytes_up + b.1.bytes_down;
                b_total.cmp(&a_total)
            });
            entries.truncate(max_entries);
            map.extend(entries);
        }
    }

    /// Check and rotate minute bucket if needed.
    pub fn maybe_rotate_minute(
        &mut self,
        current_minute_ts: u64,
        max_minute_buckets: usize,
        max_hour_buckets: usize,
        max_day_buckets: usize,
    ) {
        if self.last_minute_ts == 0 {
            self.last_minute_ts = current_minute_ts;
            return;
        }

        if current_minute_ts > self.last_minute_ts {
            if self.current_minute.total_connections > 0 {
                self.current_minute.timestamp_ms = self.last_minute_ts as i64;
                let completed = std::mem::take(&mut self.current_minute);
                self.minute_buckets.push_back(completed);

                while self.minute_buckets.len() > max_minute_buckets {
                    if let Some(old) = self.minute_buckets.pop_front() {
                        self.aggregate_to_hour(old, max_hour_buckets, max_day_buckets);
                    }
                }
            }
            self.last_minute_ts = current_minute_ts;
        }
    }

    fn aggregate_to_hour(
        &mut self,
        minute_bucket: TimeBucket,
        max_hour_buckets: usize,
        max_day_buckets: usize,
    ) {
        let hour_ts = (minute_bucket.timestamp_ms / 3_600_000) * 3_600_000;

        if let Some(last) = self.hour_buckets.back_mut()
            && last.timestamp_ms == hour_ts
        {
            last.merge(&minute_bucket);
            return;
        }

        let mut new_bucket = minute_bucket;
        new_bucket.timestamp_ms = hour_ts;
        self.hour_buckets.push_back(new_bucket);

        while self.hour_buckets.len() > max_hour_buckets {
            if let Some(old) = self.hour_buckets.pop_front() {
                self.aggregate_to_day(old, max_day_buckets);
            }
        }
    }

    fn aggregate_to_day(&mut self, hour_bucket: TimeBucket, max_day_buckets: usize) {
        let day_ts = (hour_bucket.timestamp_ms / 86_400_000) * 86_400_000;

        if let Some(last) = self.day_buckets.back_mut()
            && last.timestamp_ms == day_ts
        {
            last.merge(&hour_bucket);
            return;
        }

        let mut new_bucket = hour_bucket;
        new_bucket.timestamp_ms = day_ts;
        self.day_buckets.push_back(new_bucket);

        while self.day_buckets.len() > max_day_buckets {
            self.day_buckets.pop_front();
        }
    }

    /// Evict oldest visits from this shard, returns number evicted.
    pub fn evict(&mut self, max_evict: usize) -> usize {
        let mut evicted = 0;

        while evicted < max_evict && !self.recent_visits.is_empty() {
            // Get first (oldest) entry
            if let Some((_, visits)) = self.recent_visits.first_mut() {
                if !visits.is_empty() {
                    visits.remove(0);
                    self.total_visits -= 1;
                    evicted += 1;
                }
                if visits.is_empty() {
                    self.recent_visits.shift_remove_index(0);
                }
            } else {
                break;
            }
        }

        evicted
    }
}
