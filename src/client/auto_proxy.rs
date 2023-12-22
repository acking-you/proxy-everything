use std::env;
use std::num::ParseIntError;
use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use flume::{Receiver, Sender};
use hashbrown::HashSet;
use snafu::{OptionExt, ResultExt, Snafu};
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Connect ip-api.com fails"))]
    ConnectIpAPI { source: std::io::Error },
    #[snafu(display("Write ip-api.com fails"))]
    WriteIpAPI { source: std::io::Error },
    #[snafu(display("Read ip-api.com response and parse fails"))]
    ReadIpAPI { source: std::io::Error },
    #[snafu(display("Serde ip info response to utf8 fails"))]
    SerdeUtf8 { source: std::string::FromUtf8Error },
    #[snafu(display("Ip api return fails!"))]
    IpAPINotWork,
    #[snafu(display("Cannot find user home! You must set `{var}` to your home path"))]
    NotFindHome { var: &'static str },
    #[snafu(display("Open proxy or non proxy file to `read|append|create` error!"))]
    OpenFile { source: std::io::Error },
    #[snafu(display("Read file to string error!"))]
    ReadFile { source: std::io::Error },
    #[snafu(display("Read until error in parse http response"))]
    ReadUntil { source: std::io::Error },
    #[snafu(display("Read http response header error!"))]
    ReadHttpHeader,
    #[snafu(display("Read http response key error!"))]
    ReadHttpKeyWithIO { source: std::io::Error },
    #[snafu(display("Read http response key error!"))]
    ReadHttpKey,
    #[snafu(display("Read http response value error!"))]
    ReadHttpValue,
    #[snafu(display("Read http response body error! detail:{detail}"))]
    ReadHttpBody { detail: &'static str },
    #[snafu(display("Read http response body error!"))]
    ReadHttpBodyWithIO { source: std::io::Error },
    #[snafu(display("Get content length error when parse http response"))]
    ContentLength { source: ParseIntError },
    #[snafu(display("Write ahead log not successful!"))]
    WAL { source: std::io::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountryCode {
    Cn,
    Us,
    Sg,
    Other,
}

use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

async fn get_http_body(stream: TcpStream) -> Result<String> {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    // read header
    reader
        .read_until(b'\n', &mut buf)
        .await
        .context(ReadUntilSnafu)?;
    if *buf.last().context(ReadHttpHeaderSnafu)? != b'\n' {
        ReadHttpHeaderSnafu {}.fail()?;
    }
    buf.clear();
    let mut body_length = None;
    // read key
    let is_eof = loop {
        let n = reader
            .read_until(b'\n', &mut buf)
            .await
            .context(ReadUntilSnafu)?;
        if n == 0 {
            break true;
        }
        if *buf.last().context(ReadHttpKeySnafu)? != b'\n' {
            ReadHttpKeySnafu {}.fail()?;
        }
        if buf.len() == 2 && buf[0] == b'\r' && buf[1] == b'\n' {
            break false;
        }
        let (idx, _) = buf
            .iter()
            .enumerate()
            .find(|(_, &c)| c == b':')
            .context(ReadHttpKeySnafu)?;
        let key = unsafe { std::str::from_utf8_unchecked(&buf[..idx]) }.trim();
        if idx + 1 >= buf.len() {
            ReadHttpValueSnafu {}.fail()?;
        }
        let value = unsafe { std::str::from_utf8_unchecked(&buf[idx + 1..]) }.trim();
        if key == "Content-Length" || key == "content-length" {
            body_length = Some(value.parse::<usize>().context(ContentLengthSnafu)?);
        }
        buf.clear();
    };
    // read body
    if is_eof {
        ReadHttpBodySnafu {
            detail: "Body not received but EOF",
        }
        .fail()?;
    }
    if body_length.is_none() {
        ReadHttpBodySnafu {
            detail: "Content-Length not received,",
        }
        .fail()?;
    }
    buf.resize(body_length.expect("checked by `body_length.is_none()`"), 0);
    reader
        .read_exact(&mut buf)
        .await
        .context(ReadHttpBodyWithIOSnafu)?;
    Ok(unsafe { String::from_utf8_unchecked(buf) })
}

pub async fn get_country_code(host: impl AsRef<str>) -> Result<CountryCode> {
    let mut stream = TcpStream::connect(("ip-api.com", 80))
        .await
        .context(ConnectIpAPISnafu)?;
    let req = format!(
        "GET /line/{} HTTP/1.1\r\nHost: ip-api.com\r\n\r\n",
        host.as_ref()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .context(WriteIpAPISnafu)?;
    let text = get_http_body(stream).await?;
    tracing::info!("Host({}) ipapi body info:{}", host.as_ref(), text);
    let mut lines = text.lines();
    if !lines.any(|line| line == "success") {
        IpAPINotWorkSnafu {}.fail()?;
    }
    for line in lines {
        match line {
            "CN" | "HK" | "TW" => return Ok(CountryCode::Cn),
            "SG" => return Ok(CountryCode::Sg),
            "US" => return Ok(CountryCode::Us),
            _ => {}
        }
    }
    Ok(CountryCode::Other)
}

pub type IpAddress = String;
pub type SendItem = (IpAddress, Sender<bool>);
pub type SenderChan = Sender<SendItem>;
pub type ReceiverChan = Receiver<SendItem>;

async fn get_data_set_and_file(
    name: impl AsRef<str>,
) -> Result<(HashSet<String>, tokio::fs::File)> {
    let home_dir = if cfg!(windows) {
        env::var_os("USERPROFILE").context(NotFindHomeSnafu { var: "USERPROFILE" })?
    } else {
        env::var_os("HOME").context(NotFindHomeSnafu { var: "HOME" })?
    };
    let path = Path::new(&home_dir).join(name.as_ref());
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
const NON_PROXY_FILE_NAME: &str = ".http2-config-non-proxy.txt";
const PROXY_FILE_NAME: &str = ".http2-config-proxy.txt";

type RwSharedSet = Arc<RwLock<HashSet<String>>>;
type SharedFile = Arc<Mutex<tokio::fs::File>>;
type TaskId = u64;
type TaskMap = Arc<DashMap<String, (TaskId, async_broadcast::Receiver<bool>)>>;

struct TaskContext {
    task_id: TaskId,
    proxy_set: RwSharedSet,
    non_proxy_set: RwSharedSet,
    proxy_file: SharedFile,
    non_proxy_file: SharedFile,
    host: String,
    notifier: Sender<bool>,
    tasks: TaskMap,
}

pub async fn run_auto_proxy_by_country(receiver: ReceiverChan) {
    let (non_proxy_set, non_proxy_file) = match get_data_set_and_file(NON_PROXY_FILE_NAME).await {
        Ok(v) => {
            info!("Init non_proxy_set:{:?}", v.0);
            v
        }
        Err(e) => {
            tracing::error!(
                "Get non proxy data set and file error! Stop auto proxy. detail:{}",
                snafu::Report::from_error(e)
            );
            return;
        }
    };
    let (proxy_set, proxy_file) = match get_data_set_and_file(PROXY_FILE_NAME).await {
        Ok(v) => {
            info!("Init proxy_set:{:?}", v.0);
            v
        }
        Err(e) => {
            tracing::error!(
                "Get proxy data set and file error! Stop auto proxy. detail:{}",
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
    let mut task_id: TaskId = 0;
    loop {
        let (host, notifier) = match receiver.recv_async().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("get msg error:{}", e);
                continue;
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
        // A [`host`] will only correspond to one task to execute the HTTP request, and the rest will wait for the task to complete.
        tokio::spawn(check_proxy(TaskContext {
            task_id,
            proxy_set: proxy_set.clone(),
            non_proxy_set: non_proxy_set.clone(),
            proxy_file: proxy_file.clone(),
            non_proxy_file: non_proxy_file.clone(),
            host: host.clone(),
            notifier,
            tasks: tasks.clone(),
        }));
        task_id += 1;
    }
}

async fn cached_send(notifier: Sender<bool>, need_proxy: bool, host: &str) {
    if let Err(e) = notifier.send_async(need_proxy).await {
        tracing::error!(
            "(Cached) Notify error with {host}:this host will be proxy({need_proxy}),detail:{e}"
        );
    } else {
        tracing::info!("Hit cache({host}) need_proxy({need_proxy:?})");
    }
}

async fn cache_miss_send(notifier: Sender<bool>, need_proxy: bool, host: &str) {
    if let Err(e) = notifier.send_async(need_proxy).await {
        tracing::error!("(Cache miss) Notify error with {host}:this host will be proxy({need_proxy}),detail:{e}");
    } else {
        tracing::info!("Cached({host})  need_proxy({need_proxy:?})");
    }
}

enum ChannelContext {
    Sender(async_broadcast::Sender<bool>),
    Receiver(async_broadcast::Receiver<bool>),
}

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
    tracing::info!("Start check proxy TaskId:{task_id} Host:{host}");
    // register task or waiting exist task
    let channel = match tasks.entry(host.clone()) {
        dashmap::mapref::entry::Entry::Occupied(o) => {
            // Don't use await in this scope!!! it lead to deadlock!!!
            let (exist_task_id, receiver) = o.get();
            tracing::info!("TaskID:{task_id} ExistTaskId:{exist_task_id} Host:{host}  Info:start to waiting task finish");
            ChannelContext::Receiver(receiver.clone())
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            tracing::info!("Register Task:{task_id} Host({host})");
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
                    tracing::info!(
                        "TaskId:{task_id} Host({host}) ProxyResult({r}) Info:waiting task ok!"
                    );
                    cache_miss_send(notifier, r, &host).await;
                }
                Err(e) => {
                    tracing::error!("Task:{task_id} Host({host}) Recevie task result error,we will send true. detail{e}");
                    cache_miss_send(notifier, true, &host).await;
                }
            }
            return;
        }
        ChannelContext::Sender(tx) => tx,
    };

    tracing::info!("TaskID:{task_id} Host({host}) info:start to query by http");
    let need_proxy = match get_country_code(host.as_str()).await {
        Ok(c) => c != CountryCode::Cn,
        Err(e) => {
            tracing::error!(
                "Get country code error:host:{host} we will try to proxy. detail:{}",
                snafu::Report::from_error(e)
            );
            true
        }
    };
    cache_miss_send(notifier, need_proxy, &host).await;
    // broadcast result & update cache & config file
    match tx.broadcast(need_proxy).await {
        Ok(_) => tracing::info!("Broadcast ok! Task({task_id}) Host({host})"),
        Err(e) => tracing::error!("Broadcast error! Task({task_id}) Host({host}) detail:{e}"),
    }
    if need_proxy {
        let mut proxy_set = proxy_set.write().await;
        let mut proxy_file = proxy_file.lock().await;
        tracing::info!("Add host:{host} to proxy set");
        wal_tracing(&mut proxy_file, host.as_str()).await;
        wal_tracing(&mut proxy_file, "\n").await;
        proxy_set.insert(host);
    } else {
        let mut non_proxy_set = non_proxy_set.write().await;
        let mut non_proxy_file = non_proxy_file.lock().await;
        tracing::info!("Add host:{host} to no proxy set");
        wal_tracing(&mut non_proxy_file, host.as_str()).await;
        wal_tracing(&mut non_proxy_file, "\n").await;
        non_proxy_set.insert(host);
    }
}

async fn wal_tracing(file: &mut tokio::fs::File, text: impl AsRef<str>) {
    if let Err(e) = file
        .write_all(text.as_ref().as_bytes())
        .await
        .context(WALSnafu)
    {
        tracing::error!("{}", snafu::Report::from_error(e));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_broadcast::broadcast;
    use tokio::time::{self};
    use tokio_util::{sync::CancellationToken, task::TaskTracker};

    use super::*;

    #[tokio::test]
    async fn test_get_country_code() {
        println!("{:?}", get_country_code("test.ustc.edu.cn").await.unwrap());
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
