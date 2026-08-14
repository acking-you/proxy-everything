//! TUN-mode integration backed by `tun2proxy`.
//!
//! TUN packets are forwarded to the client's already-bound SOCKS5 listener on
//! `127.0.0.1`. The current executable is always process-bypassed, and every
//! resolved remote proxy address receives an explicit physical route before
//! the catch-all TUN routes are installed. Both protections are required: a
//! best-effort socket-to-process lookup alone is not a sufficient loop barrier.

use std::collections::BTreeSet as IpSet;
#[cfg(target_os = "windows")]
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
#[cfg(target_os = "android")]
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::fd::{IntoRawFd, OwnedFd};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
pub use tun2proxy::VirtualDnsState as TunVirtualDnsState;
use tun2proxy::{ArgDns, ArgProxy, ArgUdpStrategy, Args, ProcessBypass};

// Desktop browsers and Android applications can create hundreds of concurrent
// TCP and QUIC flows. Keep tun2proxy's standalone default conservative while
// giving the embedded client enough headroom for a full-device workload.
const EMBEDDED_TUN_MAX_SESSIONS: usize = 1024;

// Halved from ipstack's 16 KiB default. Every admitted session holds one for
// its whole life, and `tcp_timeout` deliberately keeps idle sessions around for
// ten minutes, so this buffer multiplies by the concurrent session count rather
// than by the active one. A relay hands data straight to the upstream socket,
// so it does not need a large receive window of its own.
const EMBEDDED_TUN_TCP_READ_BUFFER: usize = 8 * 1024;

#[cfg(target_os = "android")]
const ANDROID_VIRTUAL_DNS_PORTAL: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2));

struct TunLogBridge;

static TUN_LOG_BRIDGE: TunLogBridge = TunLogBridge;

impl log::Log for TunLogBridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        // ipstack emits multiple trace records for every packet. Never bridge
        // those into Flutter: a multicast or retransmit storm can otherwise
        // enqueue millions of cross-isolate callbacks and starve forwarding.
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let target = record.target();
        match record.level() {
            log::Level::Error => tracing::error!(log_target = target, "{}", record.args()),
            log::Level::Warn => tracing::warn!(log_target = target, "{}", record.args()),
            log::Level::Info => tracing::info!(log_target = target, "{}", record.args()),
            log::Level::Debug => tracing::debug!(log_target = target, "{}", record.args()),
            log::Level::Trace => tracing::trace!(log_target = target, "{}", record.args()),
        }
    }

    fn flush(&self) {}
}

fn install_tun_log_bridge() {
    // `tun2proxy` uses the `log` facade while proxy-everything uses tracing.
    // Installing this once preserves its detailed device, routing, session,
    // and error logs in both the CLI console and Flutter's FFI log callback.
    if log::set_logger(&TUN_LOG_BRIDGE).is_ok() {
        // Debug includes routing and process-matching decisions without the
        // per-packet volume reserved for trace-level diagnostics.
        log::set_max_level(log::LevelFilter::Debug);
    }
}

/// Runtime controller for the process-bypass policy of an active TUN session.
///
/// Clones share the same underlying list. Updating one clone changes the
/// routing decision for new TCP and UDP sessions without restarting the TUN
/// device. Established sessions whose decision changes are closed by
/// `tun2proxy`, causing the application to reconnect on the selected route.
#[derive(Clone, Debug)]
pub struct TunBypassController {
    processes: ProcessBypass,
    self_process: String,
}

impl TunBypassController {
    /// Build a controller and enforce the current executable in the initial
    /// effective bypass list.
    pub fn new(user_processes: impl IntoIterator<Item = String>) -> io::Result<Self> {
        let self_process = current_process_name()?;
        let controller = Self {
            processes: ProcessBypass::default(),
            self_process,
        };
        controller.set_user_processes(user_processes);
        Ok(controller)
    }

    /// Replace the user-controlled part of the bypass list.
    ///
    /// The current executable is appended after replacement and therefore
    /// cannot be removed by CLI, FFI, or UI callers.
    pub fn set_user_processes(&self, user_processes: impl IntoIterator<Item = String>) {
        let mut effective = user_processes.into_iter().collect::<Vec<_>>();
        effective.push(self.self_process.clone());
        self.processes.set_names(effective);
        tracing::info!(
            self_process = %self.self_process,
            bypass_processes = ?self.processes.names(),
            "TUN process bypass policy updated"
        );
    }

    /// Normalized process names currently used by the TUN matcher, including
    /// the mandatory current executable.
    pub fn effective_processes(&self) -> Vec<String> {
        self.processes.names()
    }

    pub(crate) fn process_bypass(&self) -> ProcessBypass {
        self.processes.clone()
    }
}

/// Settings for routing local device traffic through the client SOCKS5 port.
#[derive(Clone, Debug)]
pub struct TunConfig {
    pub bypass: TunBypassController,
    /// Fake-IP allocations shared by every route generation of this logical
    /// TUN session. Reusing them is required for application DNS caches to
    /// remain valid during an upstream hot switch.
    pub virtual_dns_state: TunVirtualDnsState,
    pub ipv6_enabled: bool,
    pub mtu: u16,
    /// Require a successful end-to-end SOCKS5 UDP readiness check before
    /// changing system routes.
    pub udp_enabled: bool,
    /// Relay non-DNS UDP directly when SOCKS5 UDP is disabled. When false,
    /// captured non-DNS UDP is blocked instead.
    pub udp_direct_fallback: bool,
    /// Remote proxy endpoint whose resolved addresses must never enter TUN.
    pub remote_endpoint: Option<(String, u16)>,
    /// Directory for virtual-DNS persistence. Only used when the TUN session
    /// runs outside this process and therefore cannot inherit
    /// `virtual_dns_state`.
    pub cache_dir: Option<std::path::PathBuf>,
}

impl TunConfig {
    pub fn new(user_processes: impl IntoIterator<Item = String>) -> io::Result<Self> {
        Ok(Self {
            bypass: TunBypassController::new(user_processes)?,
            virtual_dns_state: TunVirtualDnsState::default(),
            ipv6_enabled: false,
            mtu: tun2proxy::DEFAULT_MTU,
            udp_enabled: true,
            udp_direct_fallback: true,
            remote_endpoint: None,
            cache_dir: None,
        })
    }

    /// Add the proxy-everything server endpoint as a route-level bypass.
    ///
    /// The local SOCKS5 listener opens its own connection to this endpoint. If
    /// that connection is captured, it returns to the same listener and loops.
    pub fn with_remote_endpoint(mut self, host: impl Into<String>, port: u16) -> Self {
        self.remote_endpoint = Some((host.into(), port));
        self
    }

    /// Reuse fake-IP allocations owned by the surrounding client handle.
    pub fn with_virtual_dns_state(mut self, state: TunVirtualDnsState) -> Self {
        self.virtual_dns_state = state;
        self
    }

    /// Proxy non-DNS UDP through SOCKS5 when enabled. When disabled, keep DNS
    /// inside the virtual resolver and relay other captured UDP directly.
    pub fn with_udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Choose whether disabling SOCKS5 UDP falls back to direct UDP or blocks
    /// captured non-DNS UDP entirely.
    pub fn with_udp_direct_fallback(mut self, enabled: bool) -> Self {
        self.udp_direct_fallback = enabled;
        self
    }

    /// Enable or disable IPv6 forwarding in the userspace network stack.
    pub fn with_ipv6_enabled(mut self, enabled: bool) -> Self {
        self.ipv6_enabled = enabled;
        self
    }

    /// Override the TUN MTU supplied by the platform interface owner.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Directory an out-of-process TUN session persists its fake-IP mappings in.
    pub fn with_cache_dir(mut self, directory: impl Into<std::path::PathBuf>) -> Self {
        self.cache_dir = Some(directory.into());
        self
    }
}

#[cfg(unix)]
type PlatformTunFd = Option<OwnedFd>;
#[cfg(not(unix))]
type PlatformTunFd = Option<()>;

/// Return the current executable's file name in the same normalized form used
/// by `tun2proxy` process matching.
pub fn current_process_name() -> io::Result<String> {
    let executable = std::env::current_exe()?;
    let file_name = executable.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "current executable has no file name: {}",
                executable.display()
            ),
        )
    })?;
    let name = tun2proxy::normalize_process_name(&file_name.to_string_lossy());
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current executable has an empty process name",
        ));
    }
    Ok(name)
}

/// One grouped executable row for the Windows application picker.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RunningProcessInfo {
    /// Normalized executable basename used by the TUN policy.
    pub name: String,
    /// Original-cased executable basename presented by the process picker.
    pub display_name: String,
    /// Installed-app names that can also be used to find this executable.
    pub aliases: Vec<String>,
    /// Whether Windows app registration or a Start Menu shortcut advertises it.
    pub installed: bool,
    /// All live PIDs with this executable basename.
    pub pids: Vec<u32>,
    /// Distinct executable paths visible to the current security token.
    pub executable_paths: Vec<String>,
    /// Per-PID parent relationship used to render Task Manager-style trees.
    pub instances: Vec<RunningProcessInstance>,
    /// Base64-encoded 32x32 PNG extracted from the executable by Windows Shell.
    pub icon_png_base64: Option<String>,
}

/// One live process instance within an executable-name group.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RunningProcessInstance {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub executable_path: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct RunningProcessGroup {
    display_name: String,
    aliases: BTreeSet<String>,
    installed: bool,
    pids: BTreeSet<u32>,
    executable_paths: BTreeSet<String>,
    instances: Vec<RunningProcessInstance>,
}

/// List live and registered executables with context for the Windows picker.
#[cfg(target_os = "windows")]
pub fn running_processes() -> Vec<RunningProcessInfo> {
    use base64::Engine;

    let system = sysinfo::System::new_all();
    let mut grouped = BTreeMap::<String, RunningProcessGroup>::new();
    for process in system.processes().values() {
        let raw_name = process.name().to_string_lossy();
        let name = tun2proxy::normalize_process_name(&raw_name);
        if name.is_empty() {
            continue;
        }
        let display_name = process_display_name(&raw_name);
        let pid = process.pid().as_u32();
        let executable_path = process
            .exe()
            .map(|path| path.to_string_lossy().into_owned());
        let group = grouped.entry(name).or_insert_with(|| RunningProcessGroup {
            display_name,
            ..RunningProcessGroup::default()
        });
        group.pids.insert(pid);
        if let Some(path) = &executable_path {
            group.executable_paths.insert(path.clone());
        }
        group.instances.push(RunningProcessInstance {
            pid,
            parent_pid: process.parent().map(|pid| pid.as_u32()),
            executable_path,
        });
    }
    if let Ok(current) = current_process_name() {
        let pid = std::process::id();
        let group = grouped
            .entry(current.clone())
            .or_insert_with(|| RunningProcessGroup {
                display_name: process_display_name(&current),
                ..RunningProcessGroup::default()
            });
        if group.display_name.is_empty() {
            group.display_name = current;
        }
        if group.pids.insert(pid) {
            let executable_path = std::env::current_exe()
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            if let Some(path) = &executable_path {
                group.executable_paths.insert(path.clone());
            }
            group.instances.push(RunningProcessInstance {
                pid,
                parent_pid: None,
                executable_path,
            });
        }
    }
    for installed in super::windows_apps::installed_processes() {
        let group = grouped
            .entry(installed.name)
            .or_insert_with(|| RunningProcessGroup {
                display_name: installed.display_name.clone(),
                ..RunningProcessGroup::default()
            });
        if group.display_name.is_empty() {
            group.display_name = installed.display_name;
        }
        group.aliases.extend(installed.aliases);
        group.executable_paths.extend(installed.executable_paths);
        group.installed = true;
    }
    grouped
        .into_iter()
        .map(|(name, mut group)| {
            group.instances.sort_by_key(|instance| instance.pid);
            let executable_paths = group.executable_paths.into_iter().collect::<Vec<_>>();
            // Avoid extracting hundreds of Shell icons eagerly for dormant
            // installed applications. Live rows retain their icons; dormant
            // rows are still searchable by name, alias, and executable path.
            let icon_png_base64 = (!group.pids.is_empty())
                .then(|| {
                    executable_paths.first().and_then(|path| {
                        super::windows_icon::executable_icon_png(std::path::Path::new(path))
                    })
                })
                .flatten()
                .map(|icon| base64::engine::general_purpose::STANDARD.encode(icon));
            RunningProcessInfo {
                name,
                display_name: group.display_name,
                aliases: group.aliases.into_iter().collect(),
                installed: group.installed,
                pids: group.pids.into_iter().collect(),
                executable_paths,
                instances: group.instances,
                icon_png_base64,
            }
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn process_display_name(name: &str) -> String {
    let trimmed = name.trim();
    trimmed
        .get(..trimmed.len().saturating_sub(4))
        .filter(|_| trimmed.to_ascii_lowercase().ends_with(".exe"))
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(not(target_os = "windows"))]
pub fn running_processes() -> Vec<RunningProcessInfo> {
    Vec::new()
}

/// List unique live and registered executable names for Windows process bypass.
///
/// Other platforms return an empty list because the UI currently exposes the
/// picker only on Windows. Manually configured process names remain valid on
/// Linux, where `tun2proxy` also supports process matching.
#[cfg(target_os = "windows")]
pub fn running_process_names() -> Vec<String> {
    running_processes()
        .into_iter()
        .map(|process| process.name)
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn running_process_names() -> Vec<String> {
    Vec::new()
}

/// Whether the current Windows process has the administrator token required
/// to create the adapter and change system routes.
#[cfg(target_os = "windows")]
pub fn is_elevated() -> io::Result<bool> {
    tun2proxy::windows_elevation::is_elevated()
}

/// Relaunch the current Windows GUI through UAC for a TUN handoff.
#[cfg(target_os = "windows")]
pub fn relaunch_elevated_for_tun() -> io::Result<()> {
    tun2proxy::windows_elevation::relaunch_gui_elevated(["--enable-tun".into()])
}

/// Start the TUN device and route it to the already-bound local SOCKS5 port.
pub async fn run(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
) -> io::Result<usize> {
    run_with_ready(local_port, config, shutdown_token, None).await
}

/// Start TUN capture and optionally report when adapter and route setup is
/// complete. The readiness signal is used by FFI/UI callers to avoid showing a
/// successful state while Windows setup is still pending or has already failed.
pub async fn run_with_ready(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    ready: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    run_with_ready_inner(local_port, config, shutdown_token, ready, None).await
}

/// Forward an Android/iOS TUN interface that was established by the platform
/// VPN API. The supplied descriptor is owned by this call and remains open for
/// the complete forwarding lifetime.
#[cfg(unix)]
pub async fn run_with_ready_on_fd(
    local_port: u16,
    config: TunConfig,
    tun_fd: OwnedFd,
    shutdown_token: CancellationToken,
    ready: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    run_with_ready_inner(local_port, config, shutdown_token, ready, Some(tun_fd)).await
}

async fn run_with_ready_inner(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    mut ready: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    tun_fd: PlatformTunFd,
) -> io::Result<usize> {
    install_tun_log_bridge();
    if cfg!(target_os = "macos") && !config.udp_enabled && config.udp_direct_fallback {
        tracing::warn!(
            "captured non-DNS UDP will be blocked rather than relayed directly: a direct relay on \
             macOS cannot be bound to the physical interface and would be recaptured by the TUN \
             routes"
        );
    }
    if cfg!(target_os = "macos")
        && let Some((host, port)) = &config.remote_endpoint
        && host.parse::<IpAddr>().is_err()
    {
        // Only the addresses resolved before setup receive a physical route.
        // Windows additionally keeps this process out of the tunnel by matching
        // its executable name, but that matcher is not built for macOS, so a
        // later lookup of the same name resolves to a virtual-DNS address and
        // the upstream connection loops back into the local listener.
        tracing::warn!(
            remote_host = %host,
            remote_port = port,
            "macOS TUN mode expects the remote proxy endpoint to be an IP address; a \
             hostname is only protected for the addresses it resolves to right now"
        );
    }
    if config.udp_enabled
        && let Err(error) = validate_local_socks5_udp(local_port).await
    {
        if let Some(ready) = ready.take() {
            let _ = ready.send(Err(error.to_string()));
        }
        return Err(error);
    }
    let proxy = ArgProxy::try_from(format!("socks5://127.0.0.1:{local_port}").as_str())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let platform_owned_tun = tun_fd.is_some();
    let mut args = Args {
        proxy,
        // Android's VpnService already owns addresses, routes, DNS, and the
        // per-application policy. Desktop platforms remain managed here.
        setup: !platform_owned_tun,
        // Fake-IP DNS keeps resolver traffic inside the TUN path and preserves
        // the queried domain for the local SOCKS5 listener. `Direct` would add
        // the resolver as another physical-route exception, contradicting the
        // all-traffic guarantee and leaking DNS outside the proxy.
        dns: ArgDns::Virtual,
        udp_strategy: tun_udp_strategy(config.udp_enabled, config.udp_direct_fallback),
        ipv6_enabled: config.ipv6_enabled,
        mtu: config.mtu,
        max_sessions: EMBEDDED_TUN_MAX_SESSIONS,
        tcp_read_buffer_size: EMBEDDED_TUN_TCP_READ_BUFFER,
        bypass_process: config.bypass.effective_processes(),
        ..Args::default()
    };

    // Keep synchronized with ProxyVpnService.VIRTUAL_DNS. Android probes each
    // VPN DNS address with opportunistic DNS-over-TLS; tun2proxy must fail that
    // private portal probe locally so netd immediately uses plain DNS.
    #[cfg(target_os = "android")]
    if platform_owned_tun {
        args.virtual_dns_portals.push(ANDROID_VIRTUAL_DNS_PORTAL);
    }

    let route_bypass = if platform_owned_tun {
        Vec::new()
    } else {
        resolve_remote_addresses(config.remote_endpoint.as_ref()).await?
    };
    for address in &route_bypass {
        args.bypass.push(
            address
                .to_string()
                .parse()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
    }

    #[cfg(unix)]
    if let Some(tun_fd) = tun_fd {
        args.tun_fd = Some(tun_fd.into_raw_fd());
        args.close_fd_on_drop = Some(true);
    }

    tracing::info!(
        local_port,
        tun_proxy = %format_args!("socks5://127.0.0.1:{local_port}"),
        mtu = config.mtu,
        ipv6_enabled = config.ipv6_enabled,
        udp_strategy = ?args.udp_strategy,
        virtual_dns_portals = ?args.virtual_dns_portals,
        route_bypass = ?route_bypass,
        bypass_processes = ?args.bypass_process,
        platform_owned_tun,
        "starting TUN traffic capture with mandatory loop prevention"
    );

    match ready {
        Some(ready) => {
            tun2proxy::general_run_async_with_process_bypass_and_ready_and_virtual_dns(
                args,
                config.mtu,
                cfg!(target_os = "macos"),
                shutdown_token,
                config.bypass.process_bypass(),
                ready,
                config.virtual_dns_state,
            )
            .await
        }
        None => {
            tun2proxy::general_run_async_with_process_bypass_and_virtual_dns(
                args,
                config.mtu,
                cfg!(target_os = "macos"),
                shutdown_token,
                config.bypass.process_bypass(),
                config.virtual_dns_state,
            )
            .await
        }
    }
}

/// Choose the UDP policy for a TUN session.
///
/// macOS never selects `Direct`. A direct relay must leave through the physical
/// interface, which `tun2proxy` arranges by binding the relay socket to it, and
/// that binding is only implemented for Windows and Linux. On macOS the relay
/// socket stays unbound, so the TUN catch-all route captures it again and the
/// datagram loops back into the tunnel. Blocking captured non-DNS UDP drops
/// that traffic instead, which is the lesser failure.
fn tun_udp_strategy(udp_enabled: bool, udp_direct_fallback: bool) -> ArgUdpStrategy {
    if udp_enabled {
        return ArgUdpStrategy::Proxy;
    }
    if udp_direct_fallback && !cfg!(target_os = "macos") {
        return ArgUdpStrategy::Direct;
    }
    ArgUdpStrategy::Block
}

/// Verify the complete TUN UDP path before Wintun changes the default route.
///
/// A successful SOCKS5 UDP ASSOCIATE reply means the local listener reached the
/// remote proxy server and received its readiness byte. No user datagram is
/// sent and closing the TCP control connection immediately releases the probe.
async fn validate_local_socks5_udp(local_port: u16) -> io::Result<()> {
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0_u8; 2];
        stream.read_exact(&mut method).await?;
        if method != [0x05, 0x00] {
            return Err(io::Error::other(format!(
                "local SOCKS5 listener rejected the TUN UDP preflight authentication: \
                 {method:02x?}"
            )));
        }

        // UDP ASSOCIATE for an unspecified endpoint lets the TUN relay pin the
        // first real datagram source later. The probe stops after the reply.
        stream
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let mut reply = [0_u8; 4];
        if let Err(error) = stream.read_exact(&mut reply).await {
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP preflight failed: the remote proxy closed the association before \
                     readiness. Upgrade and restart http-proxy-server with the same release as \
                     this client, or disable SOCKS5 UDP to use direct UDP fallback",
                ));
            }
            return Err(error);
        }
        if reply[0] != 0x05 {
            return Err(io::Error::other(format!(
                "UDP preflight received invalid SOCKS version {:#x}",
                reply[0]
            )));
        }
        if reply[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "UDP preflight was rejected with SOCKS5 status {:#x}; verify remote UDP \
                     support, firewall policy, and any upstream SOCKS5 UDP relay",
                    reply[1]
                ),
            ));
        }
        tracing::info!(
            local_port,
            "TUN UDP preflight confirmed end-to-end association readiness"
        );
        Ok(())
    };

    tokio::time::timeout(PROBE_TIMEOUT, probe)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "UDP preflight timed out before the remote proxy confirmed association readiness",
            )
        })?
}

async fn resolve_remote_addresses(endpoint: Option<&(String, u16)>) -> io::Result<Vec<IpAddr>> {
    let Some((host, port)) = endpoint else {
        return Ok(Vec::new());
    };
    let addresses = tokio::net::lookup_host((host.as_str(), *port))
        .await?
        .map(|address| address.ip())
        .filter(|address| !address.is_loopback() && !address.is_unspecified())
        .collect::<IpSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() && host.parse::<IpAddr>().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("remote proxy endpoint {host}:{port} resolved to no routable address"),
        ));
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_cannot_be_removed_from_bypass_policy() {
        let controller = TunBypassController::new(["browser.exe".to_string()]).unwrap();
        let current = current_process_name().unwrap();
        assert!(controller.effective_processes().contains(&current));

        controller.set_user_processes(["curl.exe".to_string()]);
        let updated = controller.effective_processes();
        assert!(updated.contains(&current));
        assert!(updated.contains(&"curl".to_string()));
        assert!(!updated.contains(&"browser".to_string()));
    }

    #[test]
    fn tun_udp_policy_selects_proxy_direct_or_block() {
        assert_eq!(tun_udp_strategy(true, true), ArgUdpStrategy::Proxy);
        assert_eq!(tun_udp_strategy(true, false), ArgUdpStrategy::Proxy);
        assert_eq!(tun_udp_strategy(false, false), ArgUdpStrategy::Block);

        // macOS has no interface-bound direct relay, so the fallback must not
        // silently loop captured UDP back through the tunnel.
        let expected = if cfg!(target_os = "macos") {
            ArgUdpStrategy::Block
        } else {
            ArgUdpStrategy::Direct
        };
        assert_eq!(tun_udp_strategy(false, true), expected);
    }

    #[test]
    fn tun_log_bridge_rejects_per_packet_trace_events() {
        use log::Log;

        let trace = log::Metadata::builder()
            .level(log::Level::Trace)
            .target("ipstack")
            .build();
        let debug = log::Metadata::builder()
            .level(log::Level::Debug)
            .target("tun2proxy")
            .build();

        assert!(!TUN_LOG_BRIDGE.enabled(&trace));
        assert!(TUN_LOG_BRIDGE.enabled(&debug));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn detailed_process_list_groups_the_current_executable_and_pid() {
        let current = current_process_name().unwrap();
        let process = running_processes()
            .into_iter()
            .find(|process| process.name == current)
            .expect("current executable must be listed");
        assert!(process.pids.contains(&std::process::id()));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn process_display_name_preserves_game_name_casing() {
        assert_eq!(
            process_display_name("League of Legends.EXE"),
            "League of Legends"
        );
        assert_eq!(
            process_display_name("RiotClientServices"),
            "RiotClientServices"
        );
    }

    #[tokio::test]
    async fn remote_proxy_ip_becomes_a_route_bypass() {
        let addresses = resolve_remote_addresses(Some(&("203.0.113.10".to_string(), 1081)))
            .await
            .unwrap();
        assert_eq!(addresses, vec!["203.0.113.10".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn udp_preflight_explains_a_legacy_remote_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0_u8; 3];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut associate = [0_u8; 10];
            stream.read_exact(&mut associate).await.unwrap();
            assert_eq!(associate[1], 0x03);
            // A pre-UDP proxy server closes here without a readiness-backed
            // SOCKS5 response, matching the failure seen against old servers.
        });

        let error = validate_local_socks5_udp(port).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error
                .to_string()
                .contains("Upgrade and restart http-proxy-server")
        );
        server.await.unwrap();
    }
}
