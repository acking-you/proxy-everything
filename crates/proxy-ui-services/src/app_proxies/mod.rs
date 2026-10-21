//! Per-app proxies for the desktop UI, without TUN.
//!
//! Claude reads a proxy from its own settings; CipherRelay points it at a
//! loopback [router] that applies the app's host rules and forwards the rest
//! to the chosen local proxy. Other apps start through a generated launcher
//! that passes the proxy as Chromium flags and environment variables.
//!
//! The files keep the formats the first Dart/Swift/PowerShell version wrote,
//! so existing settings and launchers keep working.
pub mod apps;
pub mod claude;
pub mod launch;
mod launchers;
pub mod router;
pub mod rules;

use std::path::{Path, PathBuf};
use std::{fmt, io};

pub use apps::Application;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// Chromium/Electron flags plus proxy environment variables.
    Chromium,
    /// Proxy environment variables only.
    Environment,
    /// Claude's own proxy setting, routed through CipherRelay.
    ClaudeNative,
}

/// One app's settings as the UI shows and edits them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub app_path: String,
    pub mode: Mode,
    pub port: u16,
    pub bypass_rules: Vec<String>,
    #[serde(
        default,
        alias = "bundleIdentifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_path: Option<String>,
    /// Why native routing is not running; never persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl Entry {
    pub fn is_native(&self) -> bool {
        self.mode == Mode::ClaudeNative
    }

    fn validate(&self) -> Result<()> {
        if !rules::valid_name(&self.name) {
            return Err(Error::new("Invalid name."));
        }
        if self.port == 0 {
            return Err(Error::new("Invalid proxy port."));
        }
        if !rules::valid_rules(&self.bypass_rules) {
            return Err(Error::new("Invalid bypass rules."));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Where app proxies keep their state. Tests point these at a temporary
/// directory.
#[derive(Clone, Debug)]
pub struct Paths {
    /// CipherRelay's own state (`claude-native.json`).
    pub state: PathBuf,
    /// Claude's local configuration profiles.
    pub claude_library: PathBuf,
    /// Generated launchers.
    pub launchers: PathBuf,
    /// The launcher executable copied into each generated launcher.
    pub launcher_executable: PathBuf,
}

impl Paths {
    /// The current user's locations, next to the running CipherRelay.
    pub fn for_user() -> Option<Self> {
        let executable = std::env::current_exe().ok()?;
        let helper = executable
            .parent()?
            .join(launch::EXECUTABLE_NAME)
            .with_extension(std::env::consts::EXE_EXTENSION);
        #[cfg(target_os = "windows")]
        let (data, launchers) = {
            let local = dirs::data_local_dir()?;
            (
                local.clone(),
                local.join("CipherRelay").join("ProxyLaunchers"),
            )
        };
        #[cfg(not(target_os = "windows"))]
        let (data, launchers) = (
            dirs::data_dir()?,
            dirs::home_dir()?
                .join("Applications")
                .join("CipherRelay Launchers"),
        );
        Some(Self {
            state: data.join("CipherRelay").join("AppProxies"),
            claude_library: data.join("Claude-3p").join("configLibrary"),
            launchers,
            launcher_executable: helper,
        })
    }
}

/// Reads a JSON object. Links are refused so another program's settings can
/// never be redirected through them, and parse errors never echo the file,
/// which may hold credentials.
pub(crate) fn read_object(path: &Path) -> Result<Option<Map<String, Value>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || is_link(path.parent()) {
        return Err(Error::new(format!(
            "Expected a regular configuration file: {}",
            path.display()
        )));
    }
    match serde_json::from_slice(&std::fs::read(path)?) {
        Ok(Value::Object(object)) => Ok(Some(object)),
        Ok(_) => Err(Error::new("Configuration must be a JSON object.")),
        Err(_) => Err(Error::new(format!(
            "Invalid JSON in {}. Existing settings were preserved.",
            path.display()
        ))),
    }
}

/// Writes JSON beside the destination and renames it into place, readable
/// only by the user.
pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("Invalid configuration path."))?;
    if is_link(Some(parent)) || is_link(Some(path)) {
        return Err(Error::new("Configuration paths cannot be symbolic links."));
    }
    std::fs::create_dir_all(parent)?;
    let mut text = serde_json::to_string_pretty(value).map_err(|e| Error::new(e.to_string()))?;
    text.push('\n');
    let temporary = path.with_file_name(format!(
        "{}.cipherrelay-{:08x}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        rand::random::<u32>()
    ));
    let result = (|| {
        std::fs::write(&temporary, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    Ok(result?)
}

fn is_link(path: Option<&Path>) -> bool {
    path.and_then(|path| std::fs::symlink_metadata(path).ok())
        .is_some_and(|metadata| metadata.file_type().is_symlink())
}

/// A random RFC 4122 version 4 identifier, lower-case.
pub(crate) fn new_id() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

pub(crate) fn is_id(value: &str) -> bool {
    let groups = value.split('-').map(str::len).collect::<Vec<_>>();
    groups == [8, 4, 4, 4, 12]
        && value
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn setup_entry(app: Application, previous: Option<Entry>, port: u16, suffix: &str) -> Entry {
    match previous {
        Some(previous) => Entry {
            mode: app.mode,
            ..previous
        },
        None => Entry {
            id: None,
            name: if app.mode == Mode::ClaudeNative {
                app.name
            } else {
                format!("{} {suffix}", app.name)
            },
            app_path: app.path,
            mode: app.mode,
            port,
            bypass_rules: rules::DEFAULT_RULES.map(String::from).to_vec(),
            application_id: app.id,
            launcher_path: None,
            warning: None,
        },
    }
}

/// Everything the page does, serialized by the caller.
pub struct AppProxies {
    paths: Paths,
    claude: claude::ClaudeNative,
}

impl AppProxies {
    pub fn new(paths: Paths, runtime: tokio::runtime::Handle) -> Self {
        Self {
            claude: claude::ClaudeNative::new(
                paths.state.clone(),
                paths.claude_library.clone(),
                runtime,
            ),
            paths,
        }
    }

    /// Restores Claude's routing before Claude is opened from its own icon.
    pub fn initialize(&mut self) -> Result<()> {
        self.claude.initialize()
    }

    /// The native Claude entry first, then generated launchers, minus any
    /// Claude launcher the native entry replaced.
    pub fn list(&mut self) -> Result<Vec<Entry>> {
        let native = self.claude.configuration()?;
        let mut entries = native.clone().into_iter().collect::<Vec<_>>();
        entries.extend(
            launchers::list(&self.paths.launchers)?
                .into_iter()
                .filter(|entry| {
                    native
                        .as_ref()
                        .is_none_or(|native| entry.application_id != native.application_id)
                }),
        );
        Ok(entries)
    }

    pub fn discover(&self) -> Vec<Application> {
        apps::discover()
    }

    pub fn inspect(&self, path: &Path) -> Result<Application> {
        apps::inspect(path).ok_or_else(|| Error::new("Select an installed application."))
    }

    /// One click on a detected app: a previous entry for it keeps its port
    /// and rules, including when Claude moves from a launcher to native
    /// settings; otherwise the current proxy port and the default rules.
    pub fn set_up(&mut self, path: &Path, port: u16, suffix: &str) -> Result<Entry> {
        let app = self.inspect(path)?;
        let previous = self.list()?.into_iter().find(|entry| app.matches(entry));
        self.save(setup_entry(app, previous, port, suffix))
    }

    pub fn save(&mut self, entry: Entry) -> Result<Entry> {
        let entry = Entry {
            bypass_rules: rules::normalize(&entry.bypass_rules),
            warning: None,
            ..entry
        };
        entry.validate()?;
        if !entry.is_native() {
            return launchers::save(&self.paths, entry);
        }
        let current = self.current_claude(entry)?;
        apps::check_native_claude(Path::new(&current.app_path))?;
        let saved = self.claude.save(current)?;
        // The native entry replaces generated Claude launchers, while Codex
        // keeps its launcher path (and Dock entry). Trash is reversible.
        for old in launchers::list(&self.paths.launchers)? {
            if old.application_id.as_deref() == Some(apps::CLAUDE) {
                launchers::trash(&self.paths.launchers, old.id.as_deref().unwrap_or_default())?;
            }
        }
        Ok(saved)
    }

    /// Follows Claude when an update moved it, and drops the launcher suffix a
    /// migrated launcher's default name carried.
    fn current_claude(&self, entry: Entry) -> Result<Entry> {
        let installed = apps::discover().into_iter().find(|app| {
            app.id.as_deref() == entry.application_id.as_deref() && app.mode == Mode::ClaudeNative
        });
        let name = if ["Claude 代理启动器", "Claude Proxy Launcher"].contains(&entry.name.as_str())
        {
            "Claude".into()
        } else {
            entry.name.clone()
        };
        Ok(Entry {
            app_path: installed.map_or(entry.app_path.clone(), |app| app.path),
            name,
            ..entry
        })
    }

    pub fn remove(&mut self, entry: &Entry) -> Result<()> {
        if entry.is_native() {
            self.claude.remove()
        } else {
            launchers::trash(
                &self.paths.launchers,
                entry.id.as_deref().unwrap_or_default(),
            )
        }
    }

    pub fn open(&mut self, entry: &Entry) -> Result<()> {
        if entry.is_native() {
            let current = self.current_claude(entry.clone())?;
            apps::check_native_claude(Path::new(&current.app_path))?;
            return launch::open_path(Path::new(&current.app_path));
        }
        launch::open_path(&launchers::find(
            &self.paths.launchers,
            entry.id.as_deref(),
        )?)
    }

    pub fn reveal(&mut self, entry: &Entry) -> Result<()> {
        let path = if entry.is_native() {
            self.claude
                .configuration()?
                .and_then(|native| native.launcher_path)
                .map(PathBuf::from)
                .ok_or_else(|| Error::new("Missing configuration path."))?
        } else {
            launchers::find(&self.paths.launchers, entry.id.as_deref())?
        };
        launch::reveal(&path)
    }

    pub fn close(&mut self) {
        self.claude.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_click_setup_keeps_a_previous_entry_and_moves_claude_to_native() {
        let claude = Application {
            name: "Claude".into(),
            path: "/Applications/Claude.app".into(),
            mode: Mode::ClaudeNative,
            id: Some(apps::CLAUDE.into()),
            version: vec![2],
        };
        let legacy = Entry {
            id: Some(new_id()),
            name: "My Claude".into(),
            app_path: claude.path.clone(),
            mode: Mode::Chromium,
            port: 19765,
            bypass_rules: vec!["*internal*".into()],
            application_id: claude.id.clone(),
            launcher_path: None,
            warning: None,
        };
        assert!(claude.matches(&legacy));
        let migrated = setup_entry(claude.clone(), Some(legacy), 18765, "Proxy");
        assert_eq!((migrated.mode, migrated.port), (Mode::ClaudeNative, 19765));
        assert_eq!(migrated.bypass_rules, ["*internal*"]);
        let codex = Application {
            name: "Codex".into(),
            mode: Mode::Chromium,
            id: Some(apps::CODEX.into()),
            ..claude
        };
        let created = setup_entry(codex, None, 18765, "Proxy Launcher");
        assert_eq!(created.name, "Codex Proxy Launcher");
        assert_eq!(created.port, 18765);
        assert_eq!(created.bypass_rules, rules::DEFAULT_RULES);
    }
}
