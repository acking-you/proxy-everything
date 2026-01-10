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
use std::sync::Arc;

use dashmap::DashMap;
use hashbrown::HashSet;
use kanal::{AsyncReceiver, AsyncSender};
use snafu::{OptionExt, ResultExt, Snafu};

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
use tokio::sync::{Mutex, RwLock};
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

/// Load or create a cache file and return its contents as a HashSet.
/// Creates the data directory if it doesn't exist.
async fn get_data_set_and_file(
    name: impl AsRef<str>,
    custom_dir: Option<&Path>,
) -> Result<(HashSet<String>, tokio::fs::File)> {
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
    // Create data directory if not exists
    if !data_dir.exists() {
        tokio::fs::create_dir_all(&data_dir)
            .await
            .context(OpenFileSnafu)?;
    }
    let path = data_dir.join(name.as_ref());
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
    Ok((content.lines().map(|l| l.to_string()).collect(), file))
}

/// Cache file for hosts that should connect directly (no proxy).
const NON_PROXY_FILE_NAME: &str = "non-proxy-cache.txt";
/// Cache file for hosts that should use proxy.
const PROXY_FILE_NAME: &str = "proxy-cache.txt";

type RwSharedSet = Arc<RwLock<HashSet<String>>>;
type SharedFile = Arc<Mutex<tokio::fs::File>>;
type TaskMap = Arc<DashMap<String, (TaskId, async_broadcast::Receiver<bool>)>>;

struct TaskContext {
    task_id: TaskId,
    proxy_set: RwSharedSet,
    non_proxy_set: RwSharedSet,
    proxy_file: SharedFile,
    non_proxy_file: SharedFile,
    host: String,
    notifier: AsyncSender<bool>,
    tasks: TaskMap,
}

#[tracing::instrument(skip_all)]
pub async fn run_auto_proxy_by_country(receiver: ReceiverChan, cache_dir: Option<PathBuf>) {
    let cache_dir_ref = cache_dir.as_deref();
    let (non_proxy_set, non_proxy_file) =
        match get_data_set_and_file(NON_PROXY_FILE_NAME, cache_dir_ref).await {
            Ok(v) => {
                info!("`non_proxy_set`:{:?}", v.0);
                v
            }
            Err(e) => {
                tracing::error!(
                    "init `non_proxy_file` error: detail:{}",
                    snafu::Report::from_error(e)
                );
                return;
            }
        };
    let (proxy_set, proxy_file) = match get_data_set_and_file(PROXY_FILE_NAME, cache_dir_ref).await
    {
        Ok(v) => {
            info!("`proxy_set`:{:?}", v.0);
            v
        }
        Err(e) => {
            tracing::error!(
                "init `proxy_file` error: detail:{}",
                snafu::Report::from_error(e)
            );
            return;
        }
    };

    let non_proxy_set = Arc::new(RwLock::new(non_proxy_set));
    let proxy_set = Arc::new(RwLock::new(proxy_set));
    let proxy_file = Arc::new(Mutex::new(proxy_file));
    let non_proxy_file = Arc::new(Mutex::new(non_proxy_file));
    let tasks = Arc::new(DashMap::new());
    let mut query_task_id = QueryIpTaskId::new();
    loop {
        let (host, notifier) = match receiver.recv().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(channel_msg_error = ?e);
                return;
            }
        };
        // FIXME Maybe add regex handle?
        // check by cache
        {
            let non_proxy_set = non_proxy_set.read().await;
            if non_proxy_set.contains(&host) {
                cached_send(notifier, false, &host).await;
                continue;
            }
        }
        {
            let proxy_set = proxy_set.read().await;
            if proxy_set.contains(&host) {
                cached_send(notifier, true, &host).await;
                continue;
            }
        }
        // A [`host`] will only correspond to one task to execute the HTTP request, and the rest
        // will wait for the task to complete.
        tokio::spawn(check_proxy(TaskContext {
            task_id: query_task_id.r#gen(),
            proxy_set: proxy_set.clone(),
            non_proxy_set: non_proxy_set.clone(),
            proxy_file: proxy_file.clone(),
            non_proxy_file: non_proxy_file.clone(),
            host: host.clone(),
            notifier,
            tasks: tasks.clone(),
        }));
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
        proxy_set,
        non_proxy_set,
        proxy_file,
        non_proxy_file,
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
    // broadcast result & update cache & config file
    match tx.broadcast(need_proxy).await {
        Ok(_) => tracing::info!(task_id, host, info = "broadcast ok!"),
        Err(e) => tracing::error!(task_id, host, broadcast_error= ?e),
    }
    if need_proxy {
        let mut proxy_set = proxy_set.write().await;
        let mut proxy_file = proxy_file.lock().await;
        tracing::info!(task_id, host, info = "add host to proxy set");
        wal_tracing(&mut proxy_file, host.as_str()).await;
        wal_tracing(&mut proxy_file, "\n").await;
        let _ = proxy_file.flush().await;
        proxy_set.insert(host.clone());
    } else {
        let mut non_proxy_set = non_proxy_set.write().await;
        let mut non_proxy_file = non_proxy_file.lock().await;
        tracing::info!(task_id, host, info = "add host to no proxy set");
        wal_tracing(&mut non_proxy_file, host.as_str()).await;
        wal_tracing(&mut non_proxy_file, "\n").await;
        let _ = non_proxy_file.flush().await;
        non_proxy_set.insert(host.clone());
    }
    tasks.remove(&host);
}

async fn wal_tracing(file: &mut tokio::fs::File, text: impl AsRef<str>) {
    if let Err(e) = file
        .write_all(text.as_ref().as_bytes())
        .await
        .context(WALSnafu)
    {
        tracing::error!(wal_error = ?snafu::Report::from_error(e));
    }
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
