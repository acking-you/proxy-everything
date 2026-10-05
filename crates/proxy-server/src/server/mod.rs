//! Server-side proxy implementation.
//!
//! This module provides the server-side proxy functionality. The server receives
//! encrypted connections from clients, decrypts the proxy header, and forwards
//! traffic to the destination.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Server Architecture                              │
//! │                                                                         │
//! │  Client ──► [encrypted] ──► Server (1081) ──► Destination              │
//! │                                  │                                      │
//! │                                  ▼                                      │
//! │                         ┌─────────────────┐                            │
//! │                         │ Decrypt Header  │                            │
//! │                         │ (AES-256-GCM)   │                            │
//! │                         └─────────────────┘                            │
//! │                                  │                                      │
//! │                                  ▼                                      │
//! │                         ┌─────────────────┐                            │
//! │                         │ Parse ProxyHeader│                           │
//! │                         │ {host, port, key}│                           │
//! │                         └─────────────────┘                            │
//! │                                  │                                      │
//! │                    ┌─────────────┴─────────────┐                       │
//! │                    ▼                           ▼                        │
//! │            With Session Key            Without Key                     │
//! │            (encrypted stream)          (plain stream)                  │
//! │                    │                           │                        │
//! │                    └───────────┬───────────────┘                       │
//! │                                ▼                                        │
//! │                    ┌─────────────────────┐                             │
//! │                    │  Bidirectional      │                             │
//! │                    │  Forwarding         │                             │
//! │                    │  (with metrics)     │                             │
//! │                    └─────────────────────┘                             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Control Plane
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Control Plane Integration                           │
//! │                                                                         │
//! │  ProxyHeader{host:"__control__", port:0} triggers control mode:        │
//! │                                                                         │
//! │  ┌──────────┐    ┌──────────────┐    ┌─────────────────────────────┐   │
//! │  │  Client  │───►│ Control      │───►│ Operations:                 │   │
//! │  │  (TUI)   │◄───│ Session      │◄───│ - Ping/Pong                 │   │
//! │  └──────────┘    └──────────────┘    │ - ListNodes/SyncNodes       │   │
//! │                                      │ - GetRealtimeStats          │   │
//! │                                      │ - GetRecentConnections      │   │
//! │                                      │ - GetTimeBuckets            │   │
//! │                                      │ - GetTopN (hosts/ips)       │   │
//! │                                      │ - Relay config management   │   │
//! │                                      └─────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Transparent Proxy Chain
//!
//! When `TURELY_PROXY_SERVER` is configured or relay is enabled, the server
//! acts as a transparent relay, forwarding all traffic to another proxy server.

mod advertise;
mod connection;
mod control;
mod discovery;
mod icmp;
mod relay;
mod udp;

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use advertise::{
    auto_advertise_addr, control_session_key_fallback, detect_local_ip, detect_public_ip,
    format_ip_addr, parse_addr_list,
};
use proxy_core::config::{
    CONTROL_ADMIN_TOKEN, CONTROL_REQUIRE_ENCRYPTION, CONTROL_SESSION_KEY, NODE_ADVERTISE_ADDR,
    NODE_ID, TURELY_PROXY_SERVER,
};
use proxy_core::metrics::MetricsStore;
use proxy_core::nodes::NodeStore;
pub use relay::RelayManager;
use snafu::Snafu;
use sysinfo::{
    CpuRefreshKind, DiskRefreshKind, Disks, MemoryRefreshKind, Networks, Pid, ProcessRefreshKind,
    ProcessesToUpdate, RefreshKind, System,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Debug, Snafu)]
pub enum ServerError {
    #[snafu(display("Io Error occur: {detail}"))]
    Io {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Decryption Error occur!,detail:{detail}"))]
    Decryption { detail: String },
    #[snafu(display("SerdeJson Error occur!"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("Server read header fail:{source}"))]
    ReadHeader { source: proxy_core::ProxyError },
    #[snafu(display(
        "Exceeded the maximum supported header length({MAX_HEADER_SIZE}). size:{size}"
    ))]
    HeaderSize { size: DataSize },
    #[snafu(display("Proxy error happen!"))]
    Proxy { source: proxy_core::ProxyError },
    #[snafu(display("Transport error: {source}"))]
    Transport {
        source: proxy_core::transport::TransportError,
    },
    #[snafu(display("UDP proxy error: {source}"))]
    Datagram { source: proxy_core::ProxyError },
    #[snafu(display("Control error: {source}"))]
    Control {
        source: proxy_core::control::ControlError,
    },
}

use connection::handle_connect;
use proxy_core::DataSize;
use proxy_core::util::{GracefulShutdownManager, GracefulShutdownManagerImpl, error_report};

type Result<T> = std::result::Result<T, ServerError>;

pub const MAX_HEADER_SIZE: DataSize = 8 * 128;

struct ServerContext {
    metrics: Arc<MetricsStore>,
    nodes: Arc<NodeStore>,
    relay: Arc<RelayManager>,
    admin_token: Option<String>,
    require_control_encryption: bool,
    require_secure_transport: bool,
    control_session_key: Option<String>,
    self_node_id: Option<String>,
    /// Monotonic trace id seed used to tag logs for each connection.
    trace_id_seed: AtomicU64,
}

impl ServerContext {
    /// Allocate a per-connection tracing id.
    ///
    /// The id is monotonically increasing for easier correlation across logs
    /// and metrics snapshots.
    fn allocate_trace_id(&self) -> u64 {
        self.trace_id_seed.fetch_add(1, Ordering::Relaxed)
    }
}

/// Server configuration for testing.
#[derive(Clone)]
pub struct ServerConfig {
    pub metrics: Arc<MetricsStore>,
    pub nodes: Arc<NodeStore>,
    pub relay: Arc<RelayManager>,
    pub admin_token: Option<String>,
    pub require_control_encryption: bool,
    pub require_secure_transport: bool,
    pub control_session_key: Option<String>,
    pub self_node_id: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let nodes = Arc::new(NodeStore::with_default_path());
        Self {
            metrics: Arc::new(MetricsStore::with_default_config()),
            relay: Arc::new(RelayManager::with_default_path(nodes.clone())),
            nodes,
            admin_token: None,
            require_control_encryption: false,
            require_secure_transport: false,
            control_session_key: None,
            self_node_id: None,
        }
    }
}

/// Minimal sysinfo state and refresh configuration for the metrics loop.
///
/// This intentionally avoids `System::new_all()` and full process/task
/// enumeration. Enumerating all processes (and their tasks on Linux) causes
/// extra allocations that can stay resident for the lifetime of the process,
/// which shows up as "memory goes up and doesn't drop" under long-lived load.
struct SysinfoMetrics {
    sys: System,
    cpu_refresh: CpuRefreshKind,
    memory_refresh: MemoryRefreshKind,
    process_refresh: ProcessRefreshKind,
    pid_list: [Pid; 1],
}

impl SysinfoMetrics {
    /// Build a constrained sysinfo collector for the current process.
    ///
    /// We only refresh:
    /// - CPU usage (for host CPU utilization)
    /// - RAM usage (total/used)
    /// - The current process' CPU + memory stats (without tasks)
    fn new(pid: Pid) -> Self {
        let cpu_refresh = CpuRefreshKind::nothing().with_cpu_usage();
        let memory_refresh = MemoryRefreshKind::nothing().with_ram();
        let process_refresh = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .without_tasks();

        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(cpu_refresh)
                .with_memory(memory_refresh),
        );
        let pid_list = [pid];
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&pid_list), true, process_refresh);

        Self {
            sys,
            cpu_refresh,
            memory_refresh,
            process_refresh,
            pid_list,
        }
    }
}

/// Run server with a pre-bound listener and cancellation token.
///
/// This is the core server loop. Use `start_server` for production with
/// graceful shutdown, or call this directly for testing/custom setups.
///
/// If `tracker` is provided, tasks are spawned through it for graceful shutdown.
/// Otherwise, tasks are spawned directly with `tokio::spawn`.
pub async fn run_server_with_listener(
    listener: TcpListener,
    config: ServerConfig,
    cancel_token: CancellationToken,
    tracker: Option<TaskTracker>,
) {
    config.metrics.init_realtime();

    // Spawn system stats collector (every 5s) with cancellation support
    let metrics_for_stats = config.metrics.clone();
    let stats_cancel = cancel_token.clone();
    tokio::spawn(async move {
        use proxy_core::metrics::SystemStats;
        let pid = Pid::from_u32(std::process::id());
        let mut sysinfo_metrics = SysinfoMetrics::new(pid);
        let mut disks =
            Disks::new_with_refreshed_list_specifics(DiskRefreshKind::nothing().with_storage());
        let mut networks = Networks::new_with_refreshed_list();
        // Initial refresh for CPU baseline
        sysinfo_metrics
            .sys
            .refresh_cpu_specifics(sysinfo_metrics.cpu_refresh);
        sysinfo_metrics.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&sysinfo_metrics.pid_list),
            true,
            sysinfo_metrics.process_refresh,
        );

        // Track previous network bytes for rate calculation
        let mut prev_net_recv: u64 = 0;
        let mut prev_net_sent: u64 = 0;
        let interval_secs: u64 = 5;

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {
                    // Refresh process stats
                    sysinfo_metrics.sys.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&sysinfo_metrics.pid_list),
                        true,
                        sysinfo_metrics.process_refresh,
                    );
                    if let Some(proc) = sysinfo_metrics.sys.process(pid) {
                        metrics_for_stats.update_process_stats(proc.cpu_usage(), proc.memory());
                    }

                    // Refresh system stats
                    sysinfo_metrics
                        .sys
                        .refresh_cpu_specifics(sysinfo_metrics.cpu_refresh);
                    sysinfo_metrics
                        .sys
                        .refresh_memory_specifics(sysinfo_metrics.memory_refresh);
                    disks.refresh_specifics(true, DiskRefreshKind::nothing().with_storage());
                    networks.refresh(true);

                    // Calculate system CPU (average of all cores)
                    let cpu_percent = sysinfo_metrics
                        .sys
                        .cpus()
                        .iter()
                        .map(|c| c.cpu_usage())
                        .sum::<f32>()
                        / sysinfo_metrics.sys.cpus().len().max(1) as f32;

                    // Disk stats (sum of all disks)
                    let (disk_used, disk_total) = disks.iter().fold((0u64, 0u64), |(used, total), d| {
                        (used + d.total_space() - d.available_space(), total + d.total_space())
                    });

                    // Network IO (sum of all interfaces)
                    let (net_recv, net_sent) = networks.iter().fold((0u64, 0u64), |(recv, sent), (_, data)| {
                        (recv + data.total_received(), sent + data.total_transmitted())
                    });

                    // Calculate rates (bytes/sec)
                    let recv_rate = if prev_net_recv > 0 {
                        net_recv.saturating_sub(prev_net_recv) / interval_secs
                    } else {
                        0
                    };
                    let sent_rate = if prev_net_sent > 0 {
                        net_sent.saturating_sub(prev_net_sent) / interval_secs
                    } else {
                        0
                    };
                    prev_net_recv = net_recv;
                    prev_net_sent = net_sent;

                    metrics_for_stats.update_system_stats(SystemStats {
                        cpu_percent,
                        memory_used: sysinfo_metrics.sys.used_memory(),
                        memory_total: sysinfo_metrics.sys.total_memory(),
                        net_recv_bytes: net_recv,
                        net_sent_bytes: net_sent,
                        net_recv_rate: recv_rate,
                        net_sent_rate: sent_rate,
                        disk_used,
                        disk_total,
                    });
                }
                _ = stats_cancel.cancelled() => {
                    break;
                }
            }
        }
    });

    let ctx = Arc::new(ServerContext {
        metrics: config.metrics,
        nodes: config.nodes,
        relay: config.relay,
        admin_token: config.admin_token,
        require_control_encryption: config.require_control_encryption,
        require_secure_transport: config.require_secure_transport,
        control_session_key: config.control_session_key,
        self_node_id: config.self_node_id,
        trace_id_seed: AtomicU64::new(1),
    });

    // Background relay health checks.
    let relay_for_health = ctx.relay.clone();
    let relay_cancel = cancel_token.clone();
    tokio::spawn(async move {
        relay_for_health.run_health_checks(relay_cancel).await;
    });

    // Node sync is change-driven; no periodic background sync.

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, peer_addr)) => {
                        let ctx = ctx.clone();
                        let token = cancel_token.clone();
                        let task = async move {
                            let _ = handle_connect(socket, peer_addr, ctx).await;
                        };
                        let wrapped_task = async move {
                            tokio::select! {
                                _ = token.cancelled() => {}
                                _ = task => {}
                            }
                        };
                        if let Some(ref t) = tracker {
                            t.spawn(wrapped_task);
                        } else {
                            tokio::spawn(wrapped_task);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("accept error: {}", error_report(&e));
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                break;
            }
        }
    }
}

#[tracing::instrument]
pub async fn start_server(host: impl AsRef<str> + Debug, port: u16) {
    let nodes = Arc::new(NodeStore::with_default_path());
    if let Err(err) = nodes.load() {
        tracing::warn!("load nodes failed: {}", error_report(&err));
    }

    let metrics = Arc::new(MetricsStore::with_default_config());

    let control_session_key = if *CONTROL_REQUIRE_ENCRYPTION {
        let (key, is_default) = control_session_key_fallback();
        if is_default {
            tracing::warn!(
                "CONTROL_REQUIRE_ENCRYPTION is enabled but using DEFAULT_KEY - this is insecure!"
            );
        }
        key
    } else {
        (*CONTROL_SESSION_KEY).clone()
    };
    if *CONTROL_REQUIRE_ENCRYPTION && control_session_key.is_none() {
        tracing::warn!(
            "CONTROL_REQUIRE_ENCRYPTION is enabled but no control session key available"
        );
    }

    let mut self_addrs = Vec::new();
    if let Some(raw) = NODE_ADVERTISE_ADDR.as_ref() {
        self_addrs.extend(parse_addr_list(raw));
    }
    if let Some(addr) = auto_advertise_addr(host.as_ref(), port) {
        // An explicit listen address is already the most accurate advertisement
        // and avoids blocking startup on public-IP HTTP services.
        self_addrs.push(addr);
    } else if let Some(ip) = detect_public_ip() {
        // Wildcard listeners still need a concrete address for node discovery.
        tracing::info!("Detected public IP: {}", ip);
        self_addrs.push(format_ip_addr(ip, port));
    } else if let Some(ip) = detect_local_ip() {
        tracing::warn!("Failed to detect public IP, using local IP: {}", ip);
        self_addrs.push(format_ip_addr(ip, port));
    }
    let mut unique = Vec::new();
    for addr in self_addrs {
        if unique.iter().any(|v| v == &addr) {
            continue;
        }
        unique.push(addr);
    }

    let self_node_id = if let Some(primary_addr) = unique.first().cloned() {
        let node_id = (*NODE_ID).clone().unwrap_or_else(|| primary_addr.clone());
        nodes.set_self(node_id.clone(), primary_addr);
        nodes.set_self_addrs(unique);
        if let Err(err) = nodes.save() {
            tracing::warn!("save nodes failed: {}", error_report(&err));
        }
        if NODE_ADVERTISE_ADDR.is_none() {
            tracing::warn!("NODE_ADVERTISE_ADDR not set, using detected addresses for node sync");
        }
        Some(node_id)
    } else {
        None
    };

    let relay = Arc::new(RelayManager::with_default_path(nodes.clone()));

    // If TURELY_PROXY_SERVER is set, add it as initial relay target and enable relay
    if let Some(upstream) = TURELY_PROXY_SERVER.as_ref() {
        // Only add if relay is not already configured (respect persisted config)
        if relay.get_config().targets.is_empty() {
            tracing::info!(
                "TURELY_PROXY_SERVER={} detected, adding as initial relay target",
                upstream
            );
            relay.add_target(proxy_core::relay::UpstreamTarget::node(upstream));
            relay.set_enabled(true);
        } else {
            tracing::info!(
                "TURELY_PROXY_SERVER set but relay already configured, using persisted config"
            );
        }
    }

    let config = ServerConfig {
        require_secure_transport: std::env::var("PROXY_REQUIRE_V3").is_ok_and(|v| v == "1"),
        metrics,
        nodes,
        relay,
        admin_token: (*CONTROL_ADMIN_TOKEN).clone(),
        require_control_encryption: *CONTROL_REQUIRE_ENCRYPTION,
        control_session_key,
        self_node_id,
    };

    let listener = TcpListener::bind((host.as_ref(), port))
        .await
        .expect("start listener never fails");
    tracing::info!("Server listening on {}:{}", host.as_ref(), port);

    let mut manager = GracefulShutdownManagerImpl::new();
    if !manager.spawn_graceful_signals() {
        return;
    }
    let cancel_token = manager.cancellation_token();
    let tracker = manager.tracker().clone();

    run_server_with_listener(listener, config, cancel_token, Some(tracker)).await;

    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
}
