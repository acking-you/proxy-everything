//! TUN-mode integration backed by `tun2proxy`.
//!
//! TUN packets are forwarded to the client's already-bound SOCKS5 listener on
//! `127.0.0.1`. The current executable is always process-bypassed, and every
//! resolved remote proxy address receives an explicit physical route before
//! the catch-all TUN routes are installed. Both protections are required: a
//! best-effort socket-to-process lookup alone is not a sufficient loop barrier.

#[cfg(target_os = "windows")]
use std::collections::BTreeSet;
use std::collections::BTreeSet as IpSet;
use std::io;
use std::net::IpAddr;

use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgDns, ArgProxy, Args, ProcessBypass};

struct TunLogBridge;

static TUN_LOG_BRIDGE: TunLogBridge = TunLogBridge;

impl log::Log for TunLogBridge {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
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
/// routing decision for newly observed TCP and UDP sessions without restarting
/// the TUN device. Existing sessions keep the decision made when they started.
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
    pub ipv6_enabled: bool,
    pub mtu: u16,
    /// Remote proxy endpoint whose resolved addresses must never enter TUN.
    pub remote_endpoint: Option<(String, u16)>,
}

impl TunConfig {
    pub fn new(user_processes: impl IntoIterator<Item = String>) -> io::Result<Self> {
        Ok(Self {
            bypass: TunBypassController::new(user_processes)?,
            ipv6_enabled: false,
            mtu: tun2proxy::DEFAULT_MTU,
            remote_endpoint: None,
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
}

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

/// List unique running executable names available for Windows process bypass.
///
/// Other platforms return an empty list because the UI currently exposes the
/// picker only on Windows. Manually configured process names remain valid on
/// Linux, where `tun2proxy` also supports process matching.
#[cfg(target_os = "windows")]
pub fn running_process_names() -> Vec<String> {
    let system = sysinfo::System::new_all();
    let mut names = system
        .processes()
        .values()
        .map(|process| tun2proxy::normalize_process_name(&process.name().to_string_lossy()))
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    if let Ok(current) = current_process_name() {
        names.insert(current);
    }
    names.into_iter().collect()
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
    install_tun_log_bridge();
    let proxy = ArgProxy::try_from(format!("socks5://127.0.0.1:{local_port}").as_str())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let mut args = Args {
        proxy,
        setup: true,
        // Fake-IP DNS keeps resolver traffic inside the TUN path and preserves
        // the queried domain for the local SOCKS5 listener. `Direct` would add
        // the resolver as another physical-route exception, contradicting the
        // all-traffic guarantee and leaking DNS outside the proxy.
        dns: ArgDns::Virtual,
        ipv6_enabled: config.ipv6_enabled,
        mtu: config.mtu,
        bypass_process: config.bypass.effective_processes(),
        ..Args::default()
    };

    let route_bypass = resolve_remote_addresses(config.remote_endpoint.as_ref()).await?;
    for address in &route_bypass {
        args.bypass.push(
            address
                .to_string()
                .parse()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
    }

    tracing::info!(
        local_port,
        tun_proxy = %format_args!("socks5://127.0.0.1:{local_port}"),
        mtu = config.mtu,
        ipv6_enabled = config.ipv6_enabled,
        route_bypass = ?route_bypass,
        bypass_processes = ?args.bypass_process,
        "starting TUN traffic capture with mandatory loop prevention"
    );

    match ready {
        Some(ready) => {
            tun2proxy::general_run_async_with_process_bypass_and_ready(
                args,
                config.mtu,
                cfg!(target_os = "macos"),
                shutdown_token,
                config.bypass.process_bypass(),
                ready,
            )
            .await
        }
        None => {
            tun2proxy::general_run_async_with_process_bypass(
                args,
                config.mtu,
                cfg!(target_os = "macos"),
                shutdown_token,
                config.bypass.process_bypass(),
            )
            .await
        }
    }
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

    #[tokio::test]
    async fn remote_proxy_ip_becomes_a_route_bypass() {
        let addresses = resolve_remote_addresses(Some(&("203.0.113.10".to_string(), 1081)))
            .await
            .unwrap();
        assert_eq!(addresses, vec!["203.0.113.10".parse::<IpAddr>().unwrap()]);
    }
}
