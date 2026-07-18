//! TUN-mode integration backed by `tun2proxy`.
//!
//! The local proxy and TUN stack run in the same process. Consequently the
//! current executable must always bypass TUN interception: its outbound
//! connection to the remote proxy would otherwise be captured and fed back to
//! the local SOCKS5 listener indefinitely.

#[cfg(target_os = "windows")]
use std::collections::BTreeSet;
use std::io;

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
}

impl TunConfig {
    pub fn new(user_processes: impl IntoIterator<Item = String>) -> io::Result<Self> {
        Ok(Self {
            bypass: TunBypassController::new(user_processes)?,
            ipv6_enabled: false,
            mtu: tun2proxy::DEFAULT_MTU,
        })
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

/// Start the TUN device and route it to the already-bound local SOCKS5 port.
pub async fn run(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
) -> io::Result<usize> {
    install_tun_log_bridge();
    let proxy = ArgProxy::try_from(format!("socks5://127.0.0.1:{local_port}").as_str())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let args = Args {
        proxy,
        setup: true,
        dns: ArgDns::Direct,
        ipv6_enabled: config.ipv6_enabled,
        mtu: config.mtu,
        bypass_process: config.bypass.effective_processes(),
        ..Args::default()
    };

    tracing::info!(
        local_port,
        mtu = config.mtu,
        ipv6_enabled = config.ipv6_enabled,
        bypass_processes = ?args.bypass_process,
        "starting TUN traffic capture"
    );

    tun2proxy::general_run_async_with_process_bypass(
        args,
        config.mtu,
        cfg!(target_os = "macos"),
        shutdown_token,
        config.bypass.process_bypass(),
    )
    .await
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
}
