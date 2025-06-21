use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use regex::Regex;
use reqwest::Client;

use crate::config::GITHUB_PROXY;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    public_group_list: PublicGroupList,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicGroupList(Vec<Group>);

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    monitor_list: Vec<MonitorItem>,
    name: String,
}

#[allow(unused)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MonitorItem {
    id: u32,
    url: String,
    cert_expiry_days_remaining: Int32OrString,
    valid_cert: bool,
}

#[allow(unused)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
enum Int32OrString {
    Str(String),
    Int(i32),
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]

struct HeartbeatInfo {
    /// map monitor id to ping info list
    heartbeat_list: HashMap<String, PingInfoList>,
}

#[derive(Debug, serde::Deserialize)]
struct PingInfoList(Vec<PingInfo>);

#[derive(Debug, serde::Deserialize)]
struct PingInfo {
    #[allow(unused)]
    status: u32,
    #[allow(unused)]
    time: String,
    #[allow(unused)]
    msg: String,
    ping: Option<u32>,
}

#[tracing::instrument(skip(html))]
fn extract_links(html: &str) -> Option<Config> {
    static RE_LINKS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?s)<script id="preload-data".*?>([^<]+)</script>"#).unwrap());

    let cap = RE_LINKS.captures(html).unwrap();
    if cap.len() < 2 {
        tracing::warn!("No preload data found in the HTML!");
        return None;
    }
    let v = &cap[1];
    let start_idx = v.find('{').unwrap();
    let end_idx = v.rfind('}').unwrap();
    let v = &v[start_idx..end_idx + 1];

    match json_five::from_str(&v) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!("Failed to parse preload data: {}", e);
            None
        }
    }
}

pub static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    reqwest::ClientBuilder::new()
        .no_proxy()
        .build()
        .expect("build client nerver fails")
});

#[tracing::instrument]
async fn get_heartbeat_info() -> Option<HeartbeatInfo> {
    let resp = HTTP_CLIENT
        .get("https://uptime.akams.cn/api/status-page/heartbeat/philanthropy")
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch heartbeat info: {}", e);
            return None;
        }
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to read response text: {}", e);
            return None;
        }
    };
    match serde_json::from_str::<HeartbeatInfo>(&text) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!("Failed to parse heartbeat info: {}", e);
            None
        }
    }
}

#[derive(Debug)]
struct ProxyServer {
    github_servers: Vec<MonitorItem>,
    dockerhub_servers: Vec<MonitorItem>,
    huggingface_servers: Vec<MonitorItem>,
}

#[tracing::instrument]
async fn get_proxy_server() -> Option<ProxyServer> {
    let resp = HTTP_CLIENT
        .get("https://uptime.akams.cn/status/philanthropy")
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch links HTML: {}", e);
            return None;
        }
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to read response text: {}", e);
            return None;
        }
    };
    let config = match extract_links(&text) {
        Some(c) => c,
        None => {
            tracing::error!("Failed to extract links from HTML");
            return None;
        }
    };
    let mut ret = ProxyServer {
        github_servers: vec![],
        dockerhub_servers: vec![],
        huggingface_servers: vec![],
    };
    config.public_group_list.0.into_iter().for_each(|group| {
        if group.name.to_lowercase().contains("github") {
            ret.github_servers = group.monitor_list;
        } else if group.name.to_lowercase().contains("docker") {
            ret.dockerhub_servers = group.monitor_list;
        } else if group.name.to_lowercase().contains("hugging") {
            ret.huggingface_servers = group.monitor_list;
        }
    });
    Some(ret)
}

#[derive(Debug)]
struct MonitorItemWithPing {
    item: MonitorItem,
    ping: u32,
}

#[derive(Debug)]
struct ServerQueue {
    github: Vec<MonitorItemWithPing>,
    dockerhub: Vec<MonitorItemWithPing>,
    huggingface: Vec<MonitorItemWithPing>,
}

async fn get_proxy_server_queue() -> Option<ServerQueue> {
    let mut priority_server_queue = ServerQueue {
        github: Vec::new(),
        dockerhub: Vec::new(),
        huggingface: Vec::new(),
    };
    let proxy_server = get_proxy_server().await?;
    let heartbeat_info = get_heartbeat_info().await?;

    let append_to_queue = |servers: Vec<MonitorItem>, out: &mut Vec<MonitorItemWithPing>| {
        for server in servers.into_iter() {
            let id = server.id.to_string();
            let ping = heartbeat_info
                .heartbeat_list
                .get(&id)
                .map(|v| match v.0.last() {
                    Some(p) => p.ping,
                    None => None,
                });
            if let Some(Some(ping)) = ping {
                out.push(MonitorItemWithPing { item: server, ping });
            }
        }
    };

    append_to_queue(
        proxy_server.github_servers,
        &mut priority_server_queue.github,
    );
    append_to_queue(
        proxy_server.dockerhub_servers,
        &mut priority_server_queue.dockerhub,
    );
    append_to_queue(
        proxy_server.huggingface_servers,
        &mut priority_server_queue.huggingface,
    );
    priority_server_queue.github.sort_by_key(|k| k.ping);
    priority_server_queue.dockerhub.sort_by_key(|k| k.ping);
    priority_server_queue.huggingface.sort_by_key(|k| k.ping);
    Some(priority_server_queue)
}

/// TODO: Regularly update the list of proxy servers
static PROXY_SERVER_QUEUE: LazyLock<parking_lot::RwLock<Arc<Option<ServerQueue>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(Arc::new(None)));

#[tracing::instrument]
pub async fn update_proxy_server_queue() {
    let queue = get_proxy_server_queue().await;
    let mut server_queue = PROXY_SERVER_QUEUE.write();
    *server_queue = Arc::new(queue);
    tracing::info!("Updated proxy server queue: {:?}", server_queue);
}

pub fn replace_url_if_needed(raw_url: String) -> String {
    if !*GITHUB_PROXY {
        return raw_url;
    }

    if !raw_url.contains("github.com") {
        return raw_url;
    }

    let server_queue_snapshot = { Arc::clone(&PROXY_SERVER_QUEUE.read()) };
    if let Some(server_queue) = server_queue_snapshot.as_ref() {
        if let Some(item) = server_queue.github.choose(&mut rand::thread_rng()) {
            tracing::error!("Item: {:?}  GithubProxyserver:{}", item, item.item.url);
        }
    }

    raw_url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_heartbeat_info() {
        let v = get_heartbeat_info().await;
        println!("v:{v:?}")
    }

    #[tokio::test]
    async fn test_get_proxy_server() {
        let v = get_proxy_server().await;
        println!("v:{v:?}")
    }

    #[tokio::test]
    async fn test_get_proxy_server_queue() {
        let v = get_proxy_server_queue().await;
        println!("v:{v:?}")
    }
}
