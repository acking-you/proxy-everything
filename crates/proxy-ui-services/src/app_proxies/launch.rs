//! What a generated launcher does when clicked, plus opening and revealing
//! paths for the page.
//!
//! The proxy reaches the app as Chromium flags and environment variables, and
//! only the started process sees them. A running app cannot pick up new
//! settings, and the launcher never quits the user's work to apply them.
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Entry, Error, Mode, Result, apps, rules};

/// The launcher executable shipped beside CipherRelay.
pub const EXECUTABLE_NAME: &str = "cipherrelay-app-launcher";
pub const SETTINGS_FILE: &str = "launcher.json";

/// A launcher's own settings, in the format each platform's first version
/// wrote: macOS names the app identity `bundleIdentifier`, Windows
/// `applicationId`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub app_path: String,
    #[cfg_attr(
        target_os = "macos",
        serde(rename = "bundleIdentifier", alias = "applicationId")
    )]
    #[cfg_attr(not(target_os = "macos"), serde(alias = "bundleIdentifier"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    pub mode: Mode,
    pub port: u16,
    pub bypass_rules: Vec<String>,
    /// Windows only: the shortcut keeps its file name across renames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortcut_name: Option<String>,
}

impl Settings {
    pub fn read(path: &Path) -> Result<Self> {
        let object = super::read_object(path)?
            .ok_or_else(|| Error::new("Launcher settings are missing."))?;
        let settings: Self = serde_json::from_value(Value::Object(object))
            .map_err(|_| Error::new("Unsupported launcher configuration."))?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        super::write_json(path, self)
    }

    fn validate(&self) -> Result<()> {
        let extension = if cfg!(windows) { "exe" } else { "app" };
        let app = Path::new(&self.app_path);
        if self.schema_version != 1 || !super::is_id(&self.id) {
            return Err(Error::new("Unsupported launcher configuration."));
        }
        if !rules::valid_name(&self.name) {
            return Err(Error::new("Invalid launcher name."));
        }
        if !app.is_absolute()
            || !app
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
        {
            return Err(Error::new(
                "Select an installed application, not another proxy launcher.",
            ));
        }
        if self.mode == Mode::ClaudeNative || self.port == 0 {
            return Err(Error::new("Invalid launch mode or proxy port."));
        }
        // Rules reach command lines and environment variables, so they are
        // checked again here even though the page validated them.
        if !rules::valid_rules(&self.bypass_rules) {
            return Err(Error::new("Invalid bypass rules."));
        }
        Ok(())
    }

    pub fn entry(&self, launcher: &Path) -> Entry {
        Entry {
            id: Some(self.id.clone()),
            name: self.name.clone(),
            app_path: self.app_path.clone(),
            mode: self.mode,
            port: self.port,
            bypass_rules: self.bypass_rules.clone(),
            application_id: self.application_id.clone(),
            launcher_path: Some(launcher.to_string_lossy().into_owned()),
            warning: None,
        }
    }

    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn chromium_arguments(&self) -> Vec<String> {
        if self.mode != Mode::Chromium {
            return Vec::new();
        }
        vec![
            format!("--proxy-server={}", self.proxy_url()),
            format!(
                "--proxy-bypass-list={}",
                rules::chromium_bypass_list(&self.bypass_rules).join(";")
            ),
        ]
    }

    pub fn environment(&self) -> Vec<(&'static str, String)> {
        let proxy = self.proxy_url();
        let bypass = rules::environment_bypass_list(&self.bypass_rules).join(",");
        let mut variables = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
            .into_iter()
            .map(|key| (key, proxy.clone()))
            .collect::<Vec<_>>();
        variables.push(("NO_PROXY", bypass));
        if !cfg!(windows) {
            // Windows variable names are case-insensitive; elsewhere clients
            // read either spelling.
            let lower = variables
                .iter()
                .map(|(key, value)| (lowercase(key), value.clone()))
                .collect::<Vec<_>>();
            variables.extend(lower);
        }
        variables
    }

    /// Follows Claude and Codex when an update moved them.
    fn current(mut self) -> Self {
        if let Some(app) = self
            .application_id
            .as_deref()
            .filter(|id| [apps::CLAUDE, apps::CODEX].contains(id))
            && let Some(installed) = apps::discover()
                .into_iter()
                .find(|found| found.id.as_deref() == Some(app))
        {
            self.app_path = installed.path;
        }
        self
    }
}

fn lowercase(key: &'static str) -> &'static str {
    match key {
        "HTTP_PROXY" => "http_proxy",
        "HTTPS_PROXY" => "https_proxy",
        "ALL_PROXY" => "all_proxy",
        _ => "no_proxy",
    }
}

/// What a click on a launcher did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Launched,
    /// The app already runs with these settings and was brought forward.
    Activated,
    ProxyUnavailable,
    /// The app runs without these settings; the user must quit it first.
    QuitFirst,
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .is_ok()
}

fn checked(settings_path: &Path) -> Result<Settings> {
    let settings = Settings::read(settings_path)?.current();
    let installed = apps::inspect(Path::new(&settings.app_path));
    if installed.is_none_or(|app| cfg!(target_os = "macos") && app.id != settings.application_id) {
        return Err(Error::new(
            "The target application moved or changed. Select it again in CipherRelay.",
        ));
    }
    Ok(settings)
}

pub fn run(settings_path: &Path) -> Result<Outcome> {
    let settings = checked(settings_path)?;
    if !listening(settings.port) {
        return Ok(Outcome::ProxyUnavailable);
    }
    let running = platform::running(&settings);
    if !running.is_empty() {
        if running.iter().all(|&matches| matches) && platform::activate(&settings)? {
            return Ok(Outcome::Activated);
        }
        return Ok(Outcome::QuitFirst);
    }
    platform::launch(&settings)?;
    Ok(Outcome::Launched)
}

/// What a click would do, without doing it; for tests and diagnostics.
pub fn check(settings_path: &Path) -> Result<Value> {
    let settings = checked(settings_path)?;
    Ok(json!({
        "proxy": settings.proxy_url(),
        "proxyListening": listening(settings.port),
        "launchArguments": settings.chromium_arguments(),
        "environment": settings.environment().into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "running": platform::running(&settings),
    }))
}

/// Where a launcher's settings live relative to its executable.
pub fn settings_path(arguments: &[String]) -> Option<PathBuf> {
    if let Some(index) = arguments.iter().position(|argument| argument == "--config") {
        return arguments.get(index + 1).map(PathBuf::from);
    }
    let executable = std::env::current_exe().ok()?;
    if cfg!(target_os = "macos") {
        // <Name>.app/Contents/MacOS/ProxyLauncher -> Contents/Resources
        Some(
            executable
                .parent()?
                .parent()?
                .join("Resources")
                .join(SETTINGS_FILE),
        )
    } else {
        Some(executable.parent()?.join(SETTINGS_FILE))
    }
}

/// Opens an app, launcher or shortcut as a double-click would. On Windows the
/// desktop shell opens it, so an elevated CipherRelay does not elevate it.
pub fn open_path(path: &Path) -> Result<()> {
    platform::open(path, false)
}

/// Shows a file in Finder or Explorer.
pub fn reveal(path: &Path) -> Result<()> {
    platform::open(path, true)
}

pub fn chinese() -> bool {
    platform::chinese()
}

/// A message from a launcher, which has no window of its own.
pub fn message(title: &str, detail: &str) {
    platform::message(title, detail);
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    fn executable(settings: &Settings) -> Option<PathBuf> {
        let app = Path::new(&settings.app_path);
        let info = plist::Value::from_file(app.join("Contents/Info.plist"))
            .ok()?
            .into_dictionary()?;
        Some(
            app.join("Contents/MacOS")
                .join(info.get("CFBundleExecutable")?.as_string()?),
        )
    }

    /// One flag per running copy: whether it already has these settings.
    pub fn running(settings: &Settings) -> Vec<bool> {
        let Some(executable) = executable(settings) else {
            return Vec::new();
        };
        let executable = executable.to_string_lossy().into_owned();
        let Ok(output) = Command::new("/bin/ps").args(["-axo", "args="]).output() else {
            return Vec::new();
        };
        let expected = settings.chromium_arguments();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim_start)
            .filter(|line| {
                line.strip_prefix(executable.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
            })
            .map(|line| {
                let arguments = line.split_whitespace().collect::<Vec<_>>();
                settings.mode == Mode::Chromium
                    && expected
                        .iter()
                        .all(|flag| arguments.contains(&flag.as_str()))
            })
            .collect()
    }

    pub fn activate(settings: &Settings) -> Result<bool> {
        Ok(Command::new("/usr/bin/open")
            .arg("-a")
            .arg(&settings.app_path)
            .status()?
            .success())
    }

    pub fn launch(settings: &Settings) -> Result<()> {
        let mut command = Command::new("/usr/bin/open");
        command.arg("-a").arg(&settings.app_path);
        for (key, value) in settings.environment() {
            command.arg("--env").arg(format!("{key}={value}"));
        }
        let arguments = settings.chromium_arguments();
        if !arguments.is_empty() {
            command.arg("--args").args(arguments);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(Error::new(format!(
                "macOS could not launch the app: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    pub fn open(path: &Path, reveal: bool) -> Result<()> {
        let mut command = Command::new("/usr/bin/open");
        if reveal {
            command.arg("-R");
        }
        let output = command.arg(path).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::new(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    pub fn chinese() -> bool {
        Command::new("/usr/bin/defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .split('"')
                    .nth(1)
                    .map(|first| first.starts_with("zh"))
            })
            .unwrap_or(false)
    }

    pub fn message(title: &str, detail: &str) {
        // Text travels as arguments, never as AppleScript source.
        let _ = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "on run argv",
                "-e",
                "display alert (item 1 of argv) message (item 2 of argv)",
                "-e",
                "end run",
                title,
                detail,
            ])
            .status();
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::os::windows::process::CommandExt;

    use super::*;

    pub fn running(settings: &Settings) -> Vec<bool> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );
        let target = Path::new(&settings.app_path);
        system
            .processes()
            .values()
            .filter(|process| {
                process
                    .exe()
                    .is_some_and(|exe| exe.as_os_str().eq_ignore_ascii_case(target.as_os_str()))
            })
            // Even a copy with matching flags can hold a stale environment.
            .map(|_| false)
            .collect()
    }

    pub fn activate(_: &Settings) -> Result<bool> {
        Ok(false)
    }

    pub fn launch(settings: &Settings) -> Result<()> {
        let app = Path::new(&settings.app_path);
        Command::new(app)
            .args(settings.chromium_arguments())
            .envs(settings.environment())
            .current_dir(app.parent().unwrap_or(app))
            .spawn()?;
        Ok(())
    }

    pub fn open(path: &Path, reveal: bool) -> Result<()> {
        // Explorer parses `/select,"path"` itself; paths cannot contain quotes.
        let target = format!("\"{}\"", path.display());
        let argument = if reveal {
            format!("/select,{target}")
        } else {
            target
        };
        let explorer = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("explorer.exe"))
            .unwrap_or_else(|| PathBuf::from("explorer.exe"));
        Command::new(explorer).raw_arg(argument).spawn()?;
        Ok(())
    }

    pub fn chinese() -> bool {
        // SAFETY: no arguments; returns the user's UI language identifier.
        let language = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        language & 0x3ff == 0x04
    }

    pub fn message(title: &str, detail: &str) {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
        use windows::core::HSTRING;
        // SAFETY: both strings are owned HSTRINGs that outlive the call.
        unsafe {
            MessageBoxW(
                None,
                &HSTRING::from(format!("{title}\n\n{detail}")),
                &HSTRING::from("CipherRelay"),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: Mode) -> Settings {
        Settings {
            schema_version: 1,
            id: "0e3c8f8e-6b0a-4c5d-9a37-2f1e0f5b6c7d".into(),
            name: "App with spaces Proxy Launcher".into(),
            app_path: if cfg!(windows) {
                r"C:\Apps\App.exe"
            } else {
                "/Applications/App.app"
            }
            .into(),
            application_id: Some("com.example.app".into()),
            mode,
            port: 10801,
            bypass_rules: rules::DEFAULT_RULES.map(String::from).to_vec(),
            shortcut_name: None,
        }
    }

    #[test]
    fn launch_settings_round_trip_and_reject_injected_rules() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(SETTINGS_FILE);
        let chromium = settings(Mode::Chromium);
        chromium.write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(if cfg!(target_os = "macos") {
            "bundleIdentifier"
        } else {
            "applicationId"
        }));
        let read = Settings::read(&path).unwrap();
        assert_eq!(
            read.chromium_arguments(),
            [
                "--proxy-server=http://127.0.0.1:10801",
                "--proxy-bypass-list=localhost;127.0.0.1;[::1];*oa*;oa.com;*.oa.com;woa.com;*.woa.\
                 com",
            ]
        );
        let environment = read
            .environment()
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(environment["HTTPS_PROXY"], "http://127.0.0.1:10801");
        assert_eq!(
            environment["NO_PROXY"],
            "localhost,127.0.0.1,::1,.oa.com,.woa.com"
        );
        assert!(settings(Mode::Environment).chromium_arguments().is_empty());

        let mut injected = serde_json::to_value(&chromium).unwrap();
        injected["bypassRules"] = json!(["host;--proxy-server=evil"]);
        std::fs::write(&path, injected.to_string()).unwrap();
        assert!(Settings::read(&path).is_err());
    }
}
