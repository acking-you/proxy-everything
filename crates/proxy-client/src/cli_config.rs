//! CLI configuration module for http-proxy-cli.
//!
//! Provides TOML config loading, path utilities, and system proxy RAII guard.

use std::path::PathBuf;

use anyhow::{Context, Result};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use proxy_core::util::error_report;
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use sysproxy::Sysproxy;

pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const DATA_DIR_NAME: &str = "http-proxy-cli-config";
/// Default config template embedded at compile time from config.template.toml
pub const DEFAULT_CONFIG_TEMPLATE: &str = include_str!("../config.template.toml");

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    pub server_host: Option<String>,
    pub server_port: Option<u16>,
    pub client_port: Option<u16>,
    /// Address bound by the local client listener. Missing values default to 0.0.0.0.
    pub listen_host: Option<String>,
    pub upstream_proxy: Option<String>,
    pub secret_key: Option<String>,
    /// Enable auto-proxy (true/false). When disabled, all traffic goes through proxy.
    pub auto_proxy: Option<bool>,
    /// Accept SOCKS5 UDP ASSOCIATE requests. Missing values default to enabled.
    pub udp: Option<bool>,
    /// Capture device traffic through a TUN interface. Missing values default to disabled.
    pub tun: Option<bool>,
    /// Send non-DNS UDP directly when SOCKS5 UDP is disabled. Defaults to true.
    pub tun_udp_direct_fallback: Option<bool>,
    /// Executable names routed outside the TUN. The client executable is always added.
    pub tun_bypass_processes: Option<Vec<String>>,
    pub nonproxy_keywords: Option<Vec<String>>,
    pub proxy_keywords: Option<Vec<String>>,
    pub need_codec_ip: Option<Vec<String>>,
    pub msg_key: Option<bool>,
    pub reverse_geo: Option<bool>,
    pub use_local_geoip: Option<bool>,
    pub set_system_proxy: Option<bool>,
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file '{}'", path.display()))
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file '{}'", path.display()))
    }
}

/// Get the directory where the executable is located
pub fn get_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|p| p.to_path_buf())
}

/// Get home directory
pub fn get_home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// Get data directory: ~/http-proxy-cli-config/
pub fn get_data_dir() -> Result<PathBuf> {
    let home = get_home_dir().context("Failed to get home directory")?;
    let data_dir = home.join(DATA_DIR_NAME);
    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data directory '{}'", data_dir.display()))?;
    }
    Ok(data_dir)
}

/// Find config file: exe dir > data dir
pub fn find_config() -> Option<PathBuf> {
    // 1. Check exe directory
    if let Some(exe_dir) = get_exe_dir() {
        let config_path = exe_dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            return Some(config_path);
        }
    }

    // 2. Check data directory ~/http-proxy-cli-config/
    if let Ok(data_dir) = get_data_dir() {
        let config_path = data_dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            return Some(config_path);
        }
    }

    None
}

/// Get default config path (data dir)
pub fn get_default_config_path() -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    Ok(data_dir.join(CONFIG_FILE_NAME))
}

/// Settings to put back once the proxy stops owning the system proxy.
///
/// Written to disk so that a process which never gets to run `Drop` — killed
/// from Task Manager, crashed, or cut short by a logoff — does not leave the
/// machine pointing at a listener that no longer exists.
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct SystemProxyRestorePoint {
    enable: bool,
    host: String,
    port: u16,
    bypass: String,
    #[cfg(target_os = "macos")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    macos: Option<MacosProxyRestorePoint>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct MacosProxySetting {
    enable: bool,
    host: String,
    port: u16,
}

#[cfg(target_os = "macos")]
impl From<Sysproxy> for MacosProxySetting {
    fn from(value: Sysproxy) -> Self {
        Self {
            enable: value.enable,
            host: value.host,
            port: value.port,
        }
    }
}

#[cfg(target_os = "macos")]
impl MacosProxySetting {
    fn proxy(&self) -> Sysproxy {
        Sysproxy {
            enable: self.enable,
            host: self.host.clone(),
            port: self.port,
            bypass: String::new(),
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct MacosProxyRestorePoint {
    service: String,
    http: MacosProxySetting,
    https: MacosProxySetting,
    socks: MacosProxySetting,
}

#[cfg(target_os = "macos")]
impl MacosProxyRestorePoint {
    fn capture() -> Result<Self, sysproxy::Error> {
        let service = Sysproxy::network_service()?;
        Ok(Self {
            http: Sysproxy::get_http(&service)?.into(),
            https: Sysproxy::get_https(&service)?.into(),
            socks: Sysproxy::get_socks(&service)?.into(),
            service,
        })
    }

    fn apply(&self, bypass: &str) -> Result<(), sysproxy::Error> {
        // Each protocol has independent state. Restore the recorded service,
        // even if TUN changed the route or the primary interface meanwhile.
        let results = [
            self.http.proxy().set_http(&self.service),
            self.https.proxy().set_https(&self.service),
            self.socks.proxy().set_socks(&self.service),
            Sysproxy {
                bypass: bypass.to_owned(),
                ..Sysproxy::default()
            }
            .set_bypass(&self.service),
        ];
        results.into_iter().collect()
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl SystemProxyRestorePoint {
    fn path() -> PathBuf {
        proxy_core::config::default_state_dir().join("system-proxy-restore.json")
    }

    fn capture(original: &Sysproxy) -> Result<Self, sysproxy::Error> {
        Ok(Self {
            enable: original.enable,
            host: original.host.clone(),
            port: original.port,
            bypass: original.bypass.clone(),
            #[cfg(target_os = "macos")]
            macos: Some(MacosProxyRestorePoint::capture()?),
        })
    }

    fn apply(&self) -> Result<(), sysproxy::Error> {
        #[cfg(target_os = "macos")]
        if let Some(macos) = &self.macos {
            return macos.apply(&self.bypass);
        }
        Sysproxy {
            enable: self.enable,
            host: self.host.clone(),
            port: self.port,
            bypass: self.bypass.clone(),
        }
        .set_system_proxy()
    }

    fn set_proxy(&self, proxy: &Sysproxy) -> Result<(), sysproxy::Error> {
        #[cfg(target_os = "macos")]
        if let Some(macos) = &self.macos {
            proxy.set_http(&macos.service)?;
            proxy.set_https(&macos.service)?;
            proxy.set_socks(&macos.service)?;
            return proxy.set_bypass(&macos.service);
        }
        proxy.set_system_proxy()
    }

    fn store(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!(
                "Failed to create the system proxy state dir: {}",
                error_report(&e)
            );
            return;
        }
        match serde_json::to_string(self) {
            Ok(contents) => {
                if let Err(e) = std::fs::write(&path, contents) {
                    tracing::warn!(
                        "Failed to record the system proxy restore point: {}",
                        error_report(&e)
                    );
                }
            }
            Err(e) => tracing::warn!(
                "Failed to encode the system proxy restore point: {}",
                error_report(&e)
            ),
        }
    }

    fn take() -> Option<Self> {
        let path = Self::path();
        let contents = std::fs::read_to_string(&path).ok()?;
        // Drop the record first: a restore point that cannot be applied must
        // not be retried on every launch.
        let _ = std::fs::remove_file(&path);
        match serde_json::from_str(&contents) {
            Ok(record) => Some(record),
            Err(e) => {
                tracing::warn!(
                    "Ignoring a damaged system proxy restore point: {}",
                    error_report(&e)
                );
                None
            }
        }
    }

    fn discard() {
        let _ = std::fs::remove_file(Self::path());
    }
}

/// Put back a system proxy that a previous run took over but never released.
///
/// Returns `true` when leftover settings were found and restored. Safe to call
/// when nothing was left behind, and safe to call more than once.
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub fn restore_orphaned_system_proxy() -> bool {
    let Some(record) = SystemProxyRestorePoint::take() else {
        return false;
    };
    if !Sysproxy::is_support() {
        return false;
    }
    match record.apply() {
        Ok(()) => {
            tracing::info!("Restored a system proxy left behind by a previous run");
            true
        }
        Err(e) => {
            tracing::error!(
                "Failed to restore the orphaned system proxy: {}",
                error_report(&e)
            );
            record.store();
            false
        }
    }
}

/// RAII guard for system proxy settings.
///
/// Sets system proxy on creation, restores the previous settings on drop.
/// This ensures proxy is always cleaned up, even on panic or signal.
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub struct SystemProxyGuard {
    original: SystemProxyRestorePoint,
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl SystemProxyGuard {
    /// Create a new guard that sets system proxy to 127.0.0.1:port.
    ///
    /// Returns `None` if platform doesn't support system proxy or setting fails.
    pub fn new(port: u16) -> Option<Self> {
        match Self::try_new(port) {
            Ok(guard) => Some(guard),
            Err(error) => {
                tracing::error!("Failed to configure system proxy: {}", error_report(&error));
                None
            }
        }
    }

    /// Set the system proxy, reporting failures to callers that require it.
    pub fn try_new(port: u16) -> Result<Self, sysproxy::Error> {
        if !Sysproxy::is_support() {
            return Err(sysproxy::Error::NotSupport);
        }
        let original = Sysproxy::get_system_proxy()?;
        let restore_point = SystemProxyRestorePoint::capture(&original)?;
        // Record before switching. A crash between the two leaves a redundant
        // restore point, which is harmless; the other order would lose it.
        restore_point.store();

        let new_proxy = Sysproxy {
            enable: true,
            host: "127.0.0.1".into(),
            port,
            bypass: original.bypass.clone(),
        };
        if let Err(e) = restore_point.set_proxy(&new_proxy) {
            tracing::error!("Failed to set system proxy: {}", error_report(&e));
            match restore_point.apply() {
                Ok(()) => SystemProxyRestorePoint::discard(),
                Err(error) => {
                    tracing::error!("Failed to roll back system proxy: {}", error_report(&error))
                }
            }
            return Err(e);
        }
        tracing::info!("System proxy set to 127.0.0.1:{port}");
        Ok(Self {
            original: restore_point,
        })
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        // Restore exactly what was configured before, rather than only turning
        // the proxy off: users who already had one deserve it back.
        if let Err(e) = self.original.apply() {
            tracing::error!("Failed to restore the system proxy: {}", error_report(&e));
        } else {
            tracing::info!("System proxy restored");
            SystemProxyRestorePoint::discard();
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod system_proxy_restore_tests {
    use super::*;

    #[test]
    fn legacy_restore_point_remains_readable() {
        let point: SystemProxyRestorePoint = serde_json::from_str(
            r#"{"enable":false,"host":"127.0.0.1","port":1080,"bypass":"localhost"}"#,
        )
        .unwrap();
        assert!(point.macos.is_none());
        assert!(!point.enable);
    }

    #[test]
    fn persisted_restore_keeps_independent_protocols_and_service() {
        let encoded = r#"{"enable":true,"host":"127.0.0.1","port":8080,"bypass":"localhost","macos":{"service":"Wi-Fi","http":{"enable":true,"host":"127.0.0.1","port":8080},"https":{"enable":false,"host":"127.0.0.2","port":8443},"socks":{"enable":true,"host":"127.0.0.3","port":1080}}}"#;
        let point: SystemProxyRestorePoint = serde_json::from_str(encoded).unwrap();
        let saved = serde_json::to_string(&point).unwrap();
        let restored: SystemProxyRestorePoint = serde_json::from_str(&saved).unwrap();
        let macos = restored.macos.unwrap();
        assert_eq!(macos.service, "Wi-Fi");
        assert!(macos.http.proxy().enable);
        assert_eq!(macos.http.proxy().port, 8080);
        assert!(!macos.https.proxy().enable);
        assert_eq!(macos.https.proxy().host, "127.0.0.2");
        assert_eq!(macos.socks.proxy().port, 1080);
    }
}
