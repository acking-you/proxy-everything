//! Blocking control operations run on the shared native worker pool, without
//! creating a Dart isolate (and copying its object graph) for each request.
use std::collections::HashSet;
use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::handle::ProxyHandle;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Request {
    Start {
        config: StartConfig,
    },
    SwitchUpstream {
        server_host: String,
        server_port: u16,
    },
    StartTun {
        processes: Vec<String>,
    },
    StartAndroidTun {
        tun_fd: i32,
        mtu: u16,
    },
    StopTun,
    Stop,
    Destroy,
    Latency {
        test_url: Option<String>,
        timeout_ms: u32,
    },
    Nodes {
        server_host: String,
        server_port: u16,
        session_key: Option<String>,
        timeout_ms: u32,
    },
    Groups {
        server_host: String,
        server_port: u16,
        session_key: Option<String>,
        timeout_ms: u32,
    },
    Socks5Endpoint {
        server_host: String,
        server_port: u16,
        session_key: Option<String>,
        timeout_ms: u32,
    },
    HttpLatency {
        proxy_port: u16,
        test_url: String,
        timeout_ms: u32,
    },
    ConfigureLogs {
        directory: std::path::PathBuf,
    },
    FlushLogs,
    StartSubscription {
        port: u16,
        config: proxy_ui_services::subscription::Config,
    },
    StopSubscription {
        id: u64,
    },
    Processes,
    #[cfg(all(
        any(target_os = "macos", target_os = "windows"),
        not(feature = "mac-app-store")
    ))]
    AppProxies(crate::app_proxies::Request),
}

#[derive(Deserialize)]
struct StartConfig {
    server_host: String,
    server_port: u16,
    local_port: u16,
    session_key: Option<String>,
    cache_directory: String,
    auto_proxy: bool,
    udp_enabled: bool,
    udp_direct_fallback: bool,
    tun_enabled: bool,
    tun_fake_ip: bool,
    tun_dns_server: String,
    tun_bypass_processes: Vec<String>,
    reverse_geo: bool,
    secure_transport: bool,
    set_system_proxy: bool,
    allow_lan: bool,
}

impl Request {
    fn borrows_handle(&self) -> bool {
        #[cfg(all(
            any(target_os = "macos", target_os = "windows"),
            not(feature = "mac-app-store")
        ))]
        if matches!(self, Self::AppProxies(_)) {
            return false;
        }
        !matches!(
            self,
            Self::Nodes { .. }
                | Self::Groups { .. }
                | Self::Socks5Endpoint { .. }
                | Self::HttpLatency { .. }
                | Self::ConfigureLogs { .. }
                | Self::FlushLogs
                | Self::StartSubscription { .. }
                | Self::StopSubscription { .. }
                | Self::Processes
        )
    }
}

#[derive(Default)]
struct Active {
    jobs: usize,
    handles: HashSet<usize>,
}
fn active() -> &'static Mutex<Active> {
    static ACTIVE: OnceLock<Mutex<Active>> = OnceLock::new();
    ACTIVE.get_or_init(Mutex::default)
}

type Callback = extern "C" fn(u64, *mut c_char);

/// Start a control operation; returns zero if malformed, busy or unavailable.
/// Every accepted request returns one JSON callback, freed by proxy_free_string.
///
/// # Safety
/// `request` must be a NUL-terminated UTF-8 string during this call. If the
/// operation borrows a handle, it must remain alive and exclusively borrowed
/// until the callback (Destroy consumes it). Getters also must not race this
/// borrow. The callback must accept calls from a native worker thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proxy_operation_start_v1(
    handle: *mut ProxyHandle,
    request: *const c_char,
    callback: Option<Callback>,
) -> u64 {
    let handle_address = handle as usize;
    std::panic::catch_unwind(|| {
        let Some(callback) = callback else { return 0 };
        if request.is_null() {
            return 0;
        }
        let bytes = unsafe { CStr::from_ptr(request) }.to_bytes();
        if bytes.len() > 1024 * 1024 {
            return 0;
        }
        let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
            return 0;
        };
        let address = if request.borrows_handle() {
            if handle_address == 0 {
                return 0;
            }
            handle_address
        } else {
            0
        };
        let Some(runtime) = crate::runtime::control() else {
            return 0;
        };
        let Ok(mut state) = active().lock() else {
            return 0;
        };
        if state.jobs >= 32 || (address != 0 && !state.handles.insert(address)) {
            return 0;
        }
        state.jobs += 1;
        drop(state);
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        runtime.spawn_blocking(move || {
            let result = std::panic::catch_unwind(|| execute(address as *mut ProxyHandle, request));
            let response = match result {
                Ok(Ok(data)) => json!({"type": "complete", "data": data}),
                Ok(Err(error)) => json!({"type": "failed", "message": error}),
                Err(_) => json!({"type": "failed", "message": "Native control operation failed"}),
            };
            let mut state = active().lock().unwrap_or_else(|error| error.into_inner());
            state.jobs -= 1;
            state.handles.remove(&address);
            drop(state);
            let message = CString::new(response.to_string()).expect("JSON contains no NUL");
            callback(id, message.into_raw());
        });
        id
    })
    .unwrap_or(0)
}

fn string(value: String) -> Result<CString, String> {
    CString::new(value).map_err(|_| "Embedded NUL in control request".into())
}
fn optional(value: Option<String>) -> Result<Option<CString>, String> {
    value.map(string).transpose()
}
fn pointer(value: &Option<CString>) -> *const c_char {
    value
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr())
}
fn text(pointer: *const c_char) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // Only used with strings owned by our synchronous FFI return values.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

fn execute(handle: *mut ProxyHandle, request: Request) -> Result<Value, String> {
    // SAFETY: start copies arguments and retains the caller's exclusive borrow
    // until this function finishes. The caller cannot destroy it concurrently.
    let code = unsafe {
        match request {
            Request::Start { config } => {
                let host = string(config.server_host)?;
                let key = optional(config.session_key)?;
                let directory = string(config.cache_directory)?;
                let processes =
                    string(serde_json::to_string(&config.tun_bypass_processes).unwrap())?;
                let dns = string(config.tun_dns_server)?;
                let result = crate::proxy_set_tun_dns_server(handle, dns.as_ptr());
                if result != crate::ProxyResult::Ok {
                    return Ok(json!({"code": result as i32}));
                }
                let ffi = crate::types::ProxyConfigV8 {
                    base: crate::types::ProxyConfigV7 {
                        base: crate::types::ProxyConfigV5 {
                            server_host: host.as_ptr(),
                            server_port: config.server_port,
                            local_port: config.local_port,
                            session_key: pointer(&key),
                            auto_proxy: config.auto_proxy.into(),
                            reverse_geo: config.reverse_geo.into(),
                            cache_dir: directory.as_ptr(),
                            need_codec_ips: std::ptr::null(),
                            force_codec: 1,
                            set_system_proxy: config.set_system_proxy.into(),
                            enable_udp: config.udp_enabled.into(),
                            enable_tun: config.tun_enabled.into(),
                            tun_bypass_processes: processes.as_ptr(),
                            tun_udp_direct_fallback: config.udp_direct_fallback.into(),
                            allow_lan: config.allow_lan.into(),
                        },
                        wire_protocol: if config.secure_transport { 3 } else { 0 },
                    },
                    tun_fake_ip: config.tun_fake_ip.into(),
                };
                crate::proxy_start_v8(handle, &ffi)
            }
            Request::SwitchUpstream {
                server_host,
                server_port,
            } => crate::proxy_switch_upstream(handle, string(server_host)?.as_ptr(), server_port),
            Request::StartTun { processes } => crate::proxy_start_tun(
                handle,
                string(serde_json::to_string(&processes).unwrap())?.as_ptr(),
            ),
            Request::StartAndroidTun { tun_fd, mtu } => {
                #[cfg(target_os = "android")]
                {
                    crate::proxy_start_android_tun(handle, tun_fd, mtu)
                }
                #[cfg(not(target_os = "android"))]
                {
                    let _ = (tun_fd, mtu);
                    return Err("Android TUN is unavailable on this platform".into());
                }
            }
            Request::StopTun => crate::proxy_stop_tun(handle),
            Request::Stop => crate::proxy_stop(handle),
            Request::Destroy => {
                crate::proxy_destroy(handle);
                crate::ProxyResult::Ok
            }
            Request::Latency {
                test_url,
                timeout_ms,
            } => {
                let result =
                    crate::proxy_test_latency(handle, pointer(&optional(test_url)?), timeout_ms);
                let response = json!({"success": result.success == 1, "latencyMs": result.latency_ms, "error": text(result.error)});
                crate::proxy_free_string(result.error);
                return Ok(response);
            }
            Request::Nodes {
                server_host,
                server_port,
                session_key,
                timeout_ms,
            } => {
                let mut result = crate::proxy_get_server_nodes(
                    string(server_host)?.as_ptr(),
                    server_port,
                    pointer(&optional(session_key)?),
                    timeout_ms,
                );
                let nodes = (0..result.count).map(|index| {
                let node = &*result.nodes.add(index);
                json!({"nodeId": text(node.node_id), "addr": text(node.addr), "lastSeenMs": node.last_seen_ms,
                    "country": text(node.country), "region": text(node.region)})
            }).collect::<Vec<_>>();
                let response = json!({"success": result.success == 1, "nodes": nodes, "error": text(result.error)});
                crate::proxy_free_nodes_result(&mut result);
                return Ok(response);
            }
            Request::Groups {
                server_host,
                server_port,
                session_key,
                timeout_ms,
            } => {
                let mut result = crate::proxy_get_server_groups(
                    string(server_host)?.as_ptr(),
                    server_port,
                    pointer(&optional(session_key)?),
                    timeout_ms,
                );
                let groups = (0..result.count).map(|index| {
                let group = &*result.groups.add(index);
                let ids = (0..group.node_ids_count).map(|index| text(*group.node_ids.add(index))).collect::<Vec<_>>();
                json!({"groupId": text(group.group_id), "name": text(group.name), "nodeIds": ids, "createdAtMs": group.created_at_ms})
            }).collect::<Vec<_>>();
                let response = json!({"success": result.success == 1, "groups": groups, "error": text(result.error)});
                crate::proxy_free_groups_result(&mut result);
                return Ok(response);
            }
            Request::Socks5Endpoint {
                server_host,
                server_port,
                session_key,
                timeout_ms,
            } => {
                return crate::runtime::control()
                    .ok_or("Native runtime unavailable")?
                    .block_on(socks5_endpoint(
                        server_host,
                        server_port,
                        session_key,
                        timeout_ms,
                    ));
            }
            Request::HttpLatency {
                proxy_port,
                test_url,
                timeout_ms,
            } => {
                let result = crate::runtime::control()
                    .ok_or("Native runtime unavailable")?
                    .block_on(async {
                        let client = proxy_core::util::http_client_builder()
                            .no_proxy()
                            .proxy(
                                reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))
                                    .map_err(|error| error.to_string())?,
                            )
                            .timeout(std::time::Duration::from_millis(
                                timeout_ms.clamp(1, 60_000) as u64,
                            ))
                            .build()
                            .map_err(|error| error.to_string())?;
                        let started = std::time::Instant::now();
                        let mut response = client
                            .get(test_url)
                            .send()
                            .await
                            .map_err(|error| error.without_url().to_string())?
                            .error_for_status()
                            .map_err(|error| error.without_url().to_string())?;
                        while response
                            .chunk()
                            .await
                            .map_err(|error| error.without_url().to_string())?
                            .is_some()
                        {}
                        Ok::<_, String>(started.elapsed().as_millis() as u64)
                    });
                return result.map(|latency| json!({"latencyMs": latency}));
            }
            Request::ConfigureLogs { directory } => {
                crate::disk_log::configure(&directory).map_err(|error| error.to_string())?;
                return Ok(json!({}));
            }
            Request::FlushLogs => {
                crate::disk_log::flush_result().map_err(|error| error.to_string())?;
                return Ok(json!({}));
            }
            Request::StartSubscription { port, config } => {
                let mut servers = subscriptions()
                    .lock()
                    .map_err(|_| "Subscription registry unavailable")?;
                if servers.len() >= 8 {
                    return Err("Too many subscription servers".into());
                }
                let server = crate::runtime::control()
                    .ok_or("Native runtime unavailable")?
                    .block_on(proxy_ui_services::subscription::Server::start(
                        ([0, 0, 0, 0], port).into(),
                        config,
                    ))
                    .map_err(|error| error.to_string())?;
                let port = server.address().port();
                static NEXT: AtomicU64 = AtomicU64::new(1);
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                servers.insert(id, server);
                return Ok(json!({"id": id, "port": port}));
            }
            Request::StopSubscription { id } => {
                let server = subscriptions()
                    .lock()
                    .map_err(|_| "Subscription registry unavailable")?
                    .remove(&id);
                if let Some(server) = server {
                    crate::runtime::control()
                        .ok_or("Native runtime unavailable")?
                        .block_on(server.stop());
                }
                return Ok(json!({}));
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "windows"),
                not(feature = "mac-app-store")
            ))]
            Request::AppProxies(request) => return crate::app_proxies::execute(request),
            Request::Processes => {
                if cfg!(feature = "network-extension") {
                    return Ok(json!({"processes": []}));
                }
                crate::init_process_policy();
                // Icons can make this snapshot large. Do not serialize through
                // the legacy C-string API only to parse and serialize it again.
                return Ok(json!({"processes": proxy_client::client::tun::running_processes()}));
            }
        }
    };
    Ok(json!({"code": code as i32}))
}

/// A node's SOCKS5 link, read with the same key as its node catalogue.
/// `available` is false while the node is not serving SOCKS5.
async fn socks5_endpoint(
    host: String,
    port: u16,
    session_key: Option<String>,
    timeout_ms: u32,
) -> Result<Value, String> {
    let key = session_key
        .filter(|key| !key.is_empty())
        .unwrap_or_else(|| proxy_core::config::DEFAULT_SECRET_KEY.to_string());
    let timeout = std::time::Duration::from_millis(u64::from(if timeout_ms == 0 {
        crate::latency::DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    }));
    let endpoint = tokio::time::timeout(timeout, async {
        let mut client =
            proxy_core::control::ControlClient::connect(&host, port, Some(key)).await?;
        client.get_socks5_endpoint().await
    })
    .await
    .map_err(|_| "Connection timeout".to_string())?
    .map_err(|error| proxy_core::util::error_report(&error))?;
    Ok(match endpoint {
        Some(endpoint) => json!({
            "available": true,
            "url": endpoint.url(&host),
            "username": endpoint.username,
            "host": endpoint.host.as_deref().unwrap_or(&host),
            "port": endpoint.port,
            "udp": endpoint.udp,
        }),
        None => json!({"available": false}),
    })
}

fn subscriptions()
-> &'static Mutex<std::collections::HashMap<u64, proxy_ui_services::subscription::Server>> {
    static SERVERS: OnceLock<
        Mutex<std::collections::HashMap<u64, proxy_ui_services::subscription::Server>>,
    > = OnceLock::new();
    SERVERS.get_or_init(Mutex::default)
}

#[cfg(test)]
#[cfg(all(
    any(target_os = "macos", target_os = "windows"),
    not(feature = "mac-app-store")
))]
mod tests {
    use super::*;

    #[test]
    fn ui_requests_reach_the_app_proxy_service_without_a_handle() {
        let request: super::Request = serde_json::from_value(json!({
            "operation": "app_proxies",
            "action": "save",
            "entry": {
                "name": "Codex Proxy Launcher",
                "appPath": "/Applications/Codex.app",
                "mode": "chromium",
                "port": 10801,
                "bypassRules": ["*oa*"],
                "applicationId": "com.openai.codex",
            },
        }))
        .unwrap();
        assert!(!request.borrows_handle());
        let super::Request::AppProxies(crate::app_proxies::Request::Save { entry }) = request
        else {
            panic!("not an app proxy save");
        };
        assert_eq!(entry.port, 10801);
        assert!(
            serde_json::from_value::<super::Request>(json!({
                "operation": "app_proxies",
                "action": "delete_everything",
            }))
            .is_err()
        );
    }
}
