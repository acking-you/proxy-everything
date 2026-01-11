//! Automatic proxy decision based on IP geolocation.
//!
//! This module provides geo-based routing decisions by querying ip-api.com
//! to determine whether traffic should be proxied or connected directly.
//!
//! # Decision Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Auto-Proxy Decision Flow                             │
//! │                                                                         │
//! │  Host Request ──► Check Local Cache ──► Cache Hit? ──► Return Result   │
//! │                          │                   │                          │
//! │                          │ No                │ Yes                      │
//! │                          ▼                   │                          │
//! │                   Query ip-api.com ◄─────────┘                         │
//! │                          │                                              │
//! │                          ▼                                              │
//! │                   Parse Country Code                                    │
//! │                          │                                              │
//! │              ┌───────────┴───────────┐                                 │
//! │              ▼                       ▼                                  │
//! │         CN (China)            US/SG/TW/HK/JP/IN                        │
//! │              │                       │                                  │
//! │              ▼                       ▼                                  │
//! │         Direct Connect          Use Proxy                              │
//! │              │                       │                                  │
//! │              └───────────┬───────────┘                                 │
//! │                          ▼                                              │
//! │                   Update Cache File                                     │
//! │                   (WAL for persistence)                                 │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Concurrency Control
//!
//! When multiple requests arrive for the same host simultaneously, only one
//! HTTP request is made to ip-api.com. Other requests wait for the result
//! via broadcast channel, preventing duplicate API calls.
//!
//! # Cache Files
//!
//! Cache files are stored in `~/http-proxy-cli-config/` directory:
//! - `proxy-cache.txt`: Hosts that should use proxy
//! - `non-proxy-cache.txt`: Hosts that should connect directly

use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use kanal::{AsyncReceiver, AsyncSender};
use snafu::{OptionExt, ResultExt, Snafu};

/// Global cache for fast-path lookup (fine-grained locking with DashMap).
/// - true = needs proxy
/// - false = direct connection
pub static PROXY_CACHE: LazyLock<DashMap<String, bool>> = LazyLock::new(DashMap::new);

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Geo query failed: {source}"))]
    GeoQuery { source: crate::geo::GeoError },
    #[snafu(display("Cannot find user home! You must set `{var}` to your home path"))]
    NotFindHome { var: &'static str },
    #[snafu(display("Open proxy or non proxy file to `read|append|create` error!"))]
    OpenFile { source: std::io::Error },
    #[snafu(display("Read file to string error!"))]
    ReadFile { source: std::io::Error },
    #[snafu(display("Write ahead log not successful!"))]
    WAL { source: std::io::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStrategy {
    Proxy,
    Direct,
}

use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::info;

use crate::config::runtime;
use crate::geo::query_geo_single;
use crate::util::{QueryIpTaskId, TaskId, TaskIdGenerator};

/// Query country code and convert to proxy strategy.
pub async fn get_country_code(host: impl AsRef<str>) -> Result<ProxyStrategy> {
    let country_code = query_geo_single(host.as_ref())
        .await
        .context(GeoQuerySnafu)?;
    tracing::info!("Host({}) country code: {}", host.as_ref(), country_code);
    match country_code.as_str() {
        "CN" => Ok(ProxyStrategy::Direct),
        "SG" | "US" | "TW" | "HK" | "MO" | "JP" | "IN" => Ok(ProxyStrategy::Proxy),
        _ => Ok(ProxyStrategy::Proxy),
    }
}

/// Apply reverse logic if REVERSE_GEO_PROXY is enabled.
#[inline]
fn apply_reverse(strategy: ProxyStrategy) -> ProxyStrategy {
    if runtime::reverse_geo() {
        match strategy {
            ProxyStrategy::Proxy => ProxyStrategy::Direct,
            ProxyStrategy::Direct => ProxyStrategy::Proxy,
        }
    } else {
        strategy
    }
}

pub type IpAddress = String;
pub type SendItem = (IpAddress, AsyncSender<bool>);
pub type SenderChan = AsyncSender<SendItem>;
pub type ReceiverChan = AsyncReceiver<SendItem>;

/// Data directory name for storing cache files.
/// All cache files are stored in ~/http-proxy-cli-config/ to consolidate
/// configuration and cache data in a single location.
const DATA_DIR_NAME: &str = "http-proxy-cli-config";

/// Cache file for hosts that should connect directly (no proxy).
const NON_PROXY_FILE_NAME: &str = "non-proxy-cache.txt";
/// Cache file for hosts that should use proxy.
const PROXY_FILE_NAME: &str = "proxy-cache.txt";

/// Manages cache files and global PROXY_CACHE synchronization.
struct CacheManager {
    proxy_file: Arc<Mutex<tokio::fs::File>>,
    non_proxy_file: Arc<Mutex<tokio::fs::File>>,
}

impl CacheManager {
    /// Load cache files and populate global PROXY_CACHE.
    async fn load(cache_dir: Option<&Path>) -> Result<Self> {
        let non_proxy_file = Self::load_file(NON_PROXY_FILE_NAME, cache_dir, false).await?;
        let proxy_file = Self::load_file(PROXY_FILE_NAME, cache_dir, true).await?;

        Ok(Self {
            proxy_file: Arc::new(Mutex::new(proxy_file)),
            non_proxy_file: Arc::new(Mutex::new(non_proxy_file)),
        })
    }

    /// Load a single cache file and populate global PROXY_CACHE.
    async fn load_file(
        name: &str,
        custom_dir: Option<&Path>,
        need_proxy: bool,
    ) -> Result<tokio::fs::File> {
        let data_dir = if let Some(dir) = custom_dir {
            dir.to_path_buf()
        } else {
            let home_dir = if cfg!(windows) {
                env::var_os("USERPROFILE").context(NotFindHomeSnafu { var: "USERPROFILE" })?
            } else {
                env::var_os("HOME").context(NotFindHomeSnafu { var: "HOME" })?
            };
            Path::new(&home_dir).join(DATA_DIR_NAME)
        };

        if !data_dir.exists() {
            tokio::fs::create_dir_all(&data_dir)
                .await
                .context(OpenFileSnafu)?;
        }

        let path = data_dir.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .await
            .context(OpenFileSnafu)?;

        let mut content = String::new();
        file.read_to_string(&mut content)
            .await
            .context(ReadFileSnafu)?;

        // Load hosts into global cache
        let hosts: Vec<_> = content.lines().filter(|l| !l.is_empty()).collect();
        info!(
            "Loading {} hosts from {} (need_proxy={})",
            hosts.len(),
            name,
            need_proxy
        );
        for host in hosts {
            PROXY_CACHE.insert(host.to_string(), need_proxy);
        }

        Ok(file)
    }

    /// Update cache: insert into global PROXY_CACHE and append to file (WAL).
    async fn update(&self, host: String, need_proxy: bool) {
        // Update global cache
        PROXY_CACHE.insert(host.clone(), need_proxy);

        // WAL: append to file
        let file = if need_proxy {
            &self.proxy_file
        } else {
            &self.non_proxy_file
        };

        let mut file = file.lock().await;
        if let Err(e) = file
            .write_all(format!("{}\n", host).as_bytes())
            .await
            .context(WALSnafu)
        {
            tracing::error!(host, need_proxy, wal_error = ?e);
        } else if let Err(e) = file.flush().await.context(WALSnafu) {
            tracing::error!(host, need_proxy, flush_error = ?e);
        }
    }
}

type TaskMap = Arc<DashMap<String, (TaskId, async_broadcast::Receiver<bool>)>>;

struct TaskContext {
    task_id: TaskId,
    cache_manager: Arc<CacheManager>,
    host: String,
    notifier: AsyncSender<bool>,
    tasks: TaskMap,
}

#[tracing::instrument(skip_all)]
pub async fn run_auto_proxy_by_country(receiver: ReceiverChan, cache_dir: Option<PathBuf>) {
    let cache_dir_ref = cache_dir.as_deref();

    // Load cache files and populate global PROXY_CACHE
    let cache_manager = match CacheManager::load(cache_dir_ref).await {
        Ok(mgr) => Arc::new(mgr),
        Err(e) => {
            tracing::error!("Failed to load cache: {}", snafu::Report::from_error(e));
            return;
        }
    };

    let tasks = Arc::new(DashMap::new());
    let mut query_task_id = QueryIpTaskId::new();
    let mut batch_buffer = Vec::new();

    loop {
        // Drain all available messages into buffer (non-blocking)
        batch_buffer.clear();
        match receiver.drain_into_blocking(&mut batch_buffer).await {
            Ok(count) if count > 0 => {
                tracing::debug!("Drained {} requests from channel", count);
            }
            Ok(_) => {
                // No messages available, wait for at least one
                match receiver.recv().await {
                    Ok(item) => batch_buffer.push(item),
                    Err(e) => {
                        tracing::error!(channel_msg_error = ?e);
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::error!(drain_error = ?e);
                return;
            }
        }

        // Process all messages in batch
        for (host, notifier) in batch_buffer.drain(..) {
            // Check global cache (already checked in mod.rs, but double-check for safety)
            if let Some(entry) = PROXY_CACHE.get(&host) {
                let need_proxy = *entry;
                cached_send(notifier, need_proxy, &host).await;
                continue;
            }

            // Cache miss: spawn task to query geo API
            tokio::spawn(check_proxy(TaskContext {
                task_id: query_task_id.r#gen(),
                cache_manager: cache_manager.clone(),
                host: host.clone(),
                notifier,
                tasks: tasks.clone(),
            }));
        }
    }
}

async fn cached_send(notifier: AsyncSender<bool>, need_proxy: bool, host: &str) {
    if let Err(e) = notifier.send(need_proxy).await {
        tracing::error!(cached_proxy = need_proxy,proxy_host=host ,notifier_send_error = ?e);
    } else {
        tracing::info!(cached_proxy = need_proxy, proxy_host = host);
    }
}

async fn cache_miss_send(notifier: AsyncSender<bool>, need_proxy: bool, host: &str) {
    if let Err(e) = notifier.send(need_proxy).await {
        tracing::error!(cache_miss = need_proxy,proxy_host = host,notifier_send_error = ?e);
    } else {
        tracing::info!(cached_proxy = need_proxy, proxy_host = host);
    }
}

enum ChannelContext {
    Sender(async_broadcast::Sender<bool>),
    Receiver(async_broadcast::Receiver<bool>),
}

#[tracing::instrument(skip_all, fields(task_id, host))]
async fn check_proxy(context: TaskContext) {
    let TaskContext {
        task_id,
        cache_manager,
        host,
        notifier,
        tasks,
    } = context;
    // register task or waiting exist task
    let channel = match tasks.entry(host.clone()) {
        dashmap::mapref::entry::Entry::Occupied(o) => {
            // Don't use await in this scope!!! it lead to deadlock!!!
            let (exist_task_id, receiver) = o.get();
            tracing::info!(task_id, exist_task_id, host, info = "waiting exist task");
            ChannelContext::Receiver(receiver.clone())
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            tracing::info!(register_task_id = task_id, host);
            let (tx, rx) = async_broadcast::broadcast(1);
            v.insert((task_id, rx));
            ChannelContext::Sender(tx)
        }
    };

    //  get result by http api
    let tx = match channel {
        ChannelContext::Receiver(mut rx) => {
            match rx.recv().await {
                Ok(r) => {
                    tracing::info!(task_id, host, result = r, info = "waiting task finished!");
                    cache_miss_send(notifier, r, &host).await;
                }
                Err(e) => {
                    tracing::error!(task_id, host, receive_exist_task_error = ?e);
                    // On error: proxy in normal mode, direct in reverse mode
                    cache_miss_send(notifier, !runtime::reverse_geo(), &host).await;
                }
            }
            return;
        }
        ChannelContext::Sender(tx) => tx,
    };

    tracing::info!(task_id, host, info = "start to query ip-api");
    let need_proxy = match get_country_code(host.as_str()).await {
        Ok(c) => apply_reverse(c) == ProxyStrategy::Proxy,
        Err(e) => {
            tracing::error!(task_id,host,get_country_code_error = ?snafu::Report::from_error(e));
            // On error: proxy in normal mode, direct in reverse mode
            !runtime::reverse_geo()
        }
    };
    cache_miss_send(notifier, need_proxy, &host).await;
    // broadcast result & update cache
    match tx.broadcast(need_proxy).await {
        Ok(_) => tracing::info!(task_id, host, info = "broadcast ok!"),
        Err(e) => tracing::error!(task_id, host, broadcast_error= ?e),
    }

    // Update cache (global PROXY_CACHE + WAL)
    tracing::info!(task_id, host, need_proxy, info = "updating cache");
    cache_manager.update(host.clone(), need_proxy).await;

    tasks.remove(&host);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_broadcast::broadcast;
    use tokio::time::{self};
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::*;

    #[tokio::test]
    async fn test_get_country_code() {
        unsafe {
            env::set_var("USE_LOCAL_GEOIP", "yes");
        }
        println!("{:?}", get_country_code("google.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_broadcast() {
        let (s, r) = broadcast(2);
        let mut joins = Vec::new();

        let j = tokio::spawn(async move {
            // Send 2 messages from two different senders.
            s.broadcast(7).await.unwrap();
            s.broadcast(8).await.unwrap();
        });
        joins.push(j);

        for _ in 1..5 {
            let mut r1 = r.clone();
            let j = tokio::spawn(async move {
                assert_eq!(r1.recv().await.unwrap(), 7);
                assert_eq!(r1.recv().await.unwrap(), 8);
            });
            joins.push(j);
        }
        futures::future::join_all(joins).await;
    }

    async fn background_task(num: u64) -> i64 {
        for i in 0..10 {
            time::sleep(Duration::from_millis(100 * num)).await;
            println!("Background task {} in iteration {}.", num, i);
        }
        10
    }

    #[tokio::test]
    async fn test_shutdown() {
        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        for i in 0..10 {
            let token = token.clone();
            tracker.spawn(async move {
                // Use a `tokio::select!` to kill the background task if the token is
                // cancelled.
                tokio::select! {
                    _ = background_task(i) => {
                        println!("Task {} exiting normally.", i);
                    },
                    () = token.cancelled() => {
                        // Do some cleanup before we really exit.
                        time::sleep(Duration::from_millis(50)).await;
                        println!("Task {} finished cleanup.", i);
                    },
                }
            });
        }

        // Spawn a background task that will send the shutdown signal.
        {
            let tracker = tracker.clone();
            tokio::spawn(async move {
                // Normally you would use something like ctrl-c instead of
                // sleeping.
                time::sleep(Duration::from_secs(2)).await;
                tracker.close();
                token.cancel();
            });
        }

        // Wait for all tasks to exit.
        tracker.wait().await;

        println!("All tasks have exited now.");
    }
}
