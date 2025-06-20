use std::collections::HashMap;
use std::time::Instant;

use regex::Regex;

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
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MonitorItem {
    id: u32,
    url: String,
    cert_expiry_days_remaining: Int32OrString,
    valid_cert: bool,
}

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
    heartbeat_list: HashMap<String, PingInfoList>,
}

#[derive(Debug, serde::Deserialize)]
struct PingInfoList(Vec<PingInfo>);

#[derive(Debug, serde::Deserialize)]
struct PingInfo {
    status: u32,
    time: String,
    msg: String,
    ping: Option<u32>,
}
