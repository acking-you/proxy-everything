//! Installed applications: what a chosen app is, and where Claude and Codex
//! are installed. Only installed locations are searched, so a mounted
//! installer or a generated launcher never wins over the user's actual app.
use std::path::Path;

use serde::Serialize;

use super::{Error, Mode, Result};

pub const CLAUDE: &str = "com.anthropic.claudefordesktop";
pub const CODEX: &str = "com.openai.codex";
/// The first Claude release that reads `egressProxyUrl`.
const NATIVE_CLAUDE: [u64; 3] = [1, 44121, 1];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Application {
    pub name: String,
    #[serde(rename = "appPath")]
    pub path: String,
    pub mode: Mode,
    #[serde(rename = "applicationId", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip)]
    pub version: Vec<u64>,
}

impl Application {
    /// Whether `entry` is this app's, by identity or by path.
    pub fn matches(&self, entry: &super::Entry) -> bool {
        (self.id.is_some() && self.id == entry.application_id)
            || if cfg!(windows) {
                self.path.eq_ignore_ascii_case(&entry.app_path)
            } else {
                self.path == entry.app_path
            }
    }
}

fn known_name(id: &str) -> Option<&'static str> {
    match id {
        CODEX => Some("Codex"),
        CLAUDE => Some("Claude"),
        _ => None,
    }
}

/// Leading numeric components: "1.44121.1 (build)" is [1, 44121, 1].
#[cfg(target_os = "macos")]
fn parse_version(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or_default()
        .split('.')
        .map_while(|part| part.parse().ok())
        .collect()
}

fn mode(id: Option<&str>, version: &[u64], chromium: bool) -> Mode {
    let padded = |v: &[u64]| {
        (0..3)
            .map(|i| v.get(i).copied().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    if id == Some(CLAUDE) && padded(version) >= NATIVE_CLAUDE.to_vec() {
        Mode::ClaudeNative
    } else if chromium {
        Mode::Chromium
    } else {
        Mode::Environment
    }
}

/// Picks one installation per app: the running one, else the newest.
fn select(candidates: Vec<(Application, bool)>) -> Vec<Application> {
    let mut chosen: Vec<(Application, bool)> = Vec::new();
    for (app, running) in candidates {
        match chosen.iter_mut().find(|(other, _)| other.id == app.id) {
            Some(slot) => {
                if (running && !slot.1) || (running == slot.1 && app.version > slot.0.version) {
                    *slot = (app, running);
                }
            }
            None => chosen.push((app, running)),
        }
    }
    let mut apps = chosen.into_iter().map(|(app, _)| app).collect::<Vec<_>>();
    apps.sort_by(|a, b| a.name.cmp(&b.name));
    apps
}

pub fn inspect(path: &Path) -> Option<Application> {
    platform::inspect(path)
}

pub fn discover() -> Vec<Application> {
    platform::discover()
}

/// Refuses a Claude that cannot read a proxy setting, or one an
/// organization manages: its policy could override what CipherRelay writes.
pub fn check_native_claude(path: &Path) -> Result<()> {
    if inspect(path).is_none_or(|app| app.mode != Mode::ClaudeNative) {
        return Err(Error::new(
            "This Claude version does not support native proxy configuration.",
        ));
    }
    if platform::claude_is_managed() {
        return Err(Error::new(
            "Claude is managed by an organization. Local proxy settings may be overridden; no \
             settings were changed.",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::{Path, PathBuf};

    use super::*;

    fn info(bundle: &Path) -> Option<plist::Dictionary> {
        plist::Value::from_file(bundle.join("Contents/Info.plist"))
            .ok()?
            .into_dictionary()
    }

    fn string<'a>(info: &'a plist::Dictionary, key: &str) -> Option<&'a str> {
        info.get(key)?.as_string()
    }

    pub fn inspect(path: &Path) -> Option<Application> {
        use std::os::unix::fs::PermissionsExt;
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        {
            return None;
        }
        let path = path.canonicalize().ok()?;
        let info = info(&path)?;
        let id = string(&info, "CFBundleIdentifier")?.to_owned();
        let executable = path
            .join("Contents/MacOS")
            .join(string(&info, "CFBundleExecutable")?);
        let metadata = std::fs::metadata(&executable).ok()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
        let name = known_name(&id)
            .or_else(|| string(&info, "CFBundleDisplayName"))
            .or_else(|| string(&info, "CFBundleName"))
            .map(str::to_owned)
            .or_else(|| Some(path.file_stem()?.to_string_lossy().into_owned()))?;
        let version = parse_version(string(&info, "CFBundleShortVersionString").unwrap_or("0"));
        let chromium = known_name(&id).is_some()
            || std::fs::read_dir(path.join("Contents/Frameworks"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|entry| {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    [
                        "electron",
                        "chrome",
                        "chromium",
                        "microsoft edge",
                        "brave browser",
                        "codex framework",
                    ]
                    .iter()
                    .any(|marker| name.contains(marker))
                });
        Some(Application {
            mode: mode(Some(&id), &version, chromium),
            name,
            path: path.to_string_lossy().into_owned(),
            id: Some(id),
            version,
        })
    }

    /// Bundles of running processes, so the copy the user actually uses wins.
    fn running_bundles() -> Vec<PathBuf> {
        let Ok(output) = std::process::Command::new("/bin/ps")
            .args(["-axo", "comm="])
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                Some(PathBuf::from(
                    &line[..line.find(".app/Contents/MacOS/")? + 4],
                ))
            })
            .collect()
    }

    pub fn discover() -> Vec<Application> {
        let roots = [
            Some(PathBuf::from("/Applications")),
            dirs::home_dir().map(|home| home.join("Applications")),
        ];
        discover_in(
            &roots.into_iter().flatten().collect::<Vec<_>>(),
            &running_bundles(),
        )
    }

    /// Known apps installed under `roots`, preferring a `running` copy.
    pub(super) fn discover_in(roots: &[PathBuf], running: &[PathBuf]) -> Vec<Application> {
        let roots = roots
            .iter()
            .filter_map(|root| root.canonicalize().ok())
            .collect::<Vec<_>>();
        let running = running
            .iter()
            .filter_map(|path| path.canonicalize().ok())
            .collect::<Vec<_>>();
        let listed = roots
            .iter()
            .flat_map(|root| std::fs::read_dir(root).into_iter().flatten().flatten())
            .map(|entry| entry.path());
        let candidates = running
            .iter()
            .cloned()
            .chain(listed)
            .filter_map(|path| inspect(&path))
            .filter(|app| {
                app.id.as_deref().and_then(known_name).is_some()
                    && roots
                        .iter()
                        .any(|root| Path::new(&app.path).starts_with(root))
            })
            .map(|app| {
                let active = running.iter().any(|path| path == Path::new(&app.path));
                (app, active)
            })
            .collect();
        select(candidates)
    }

    pub fn claude_is_managed() -> bool {
        let user = std::env::var("USER").unwrap_or_default();
        [
            "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist".to_owned(),
            format!("/Library/Managed Preferences/{user}/com.anthropic.claudefordesktop.plist"),
        ]
        .iter()
        .filter(|path| Path::new(path).exists())
        .any(|path| {
            plist::Value::from_file(path)
                .ok()
                .and_then(plist::Value::into_dictionary)
                .is_none_or(|policy| !policy.is_empty())
        })
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
    };
    use windows::core::{HSTRING, PCWSTR};
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

    use super::*;

    struct VersionInfo {
        version: Vec<u64>,
        product: String,
    }

    fn version_info(path: &Path) -> Option<VersionInfo> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // SAFETY: `wide` is NUL terminated and outlives both calls; `data` is
        // sized by GetFileVersionInfoSizeW and VerQueryValueW pointers stay
        // inside it while it is alive.
        unsafe {
            let size = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None);
            if size == 0 {
                return None;
            }
            let mut data = vec![0u8; size as usize];
            GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, data.as_mut_ptr().cast())
                .ok()?;
            let mut pointer = std::ptr::null_mut();
            let mut length = 0u32;
            let mut version = Vec::new();
            if VerQueryValueW(
                data.as_ptr().cast(),
                &HSTRING::from("\\"),
                &mut pointer,
                &mut length,
            )
            .as_bool()
                && length as usize >= std::mem::size_of::<VS_FIXEDFILEINFO>()
            {
                let fixed = &*(pointer as *const VS_FIXEDFILEINFO);
                version = vec![
                    (fixed.dwFileVersionMS >> 16) as u64,
                    (fixed.dwFileVersionMS & 0xffff) as u64,
                    (fixed.dwFileVersionLS >> 16) as u64,
                    (fixed.dwFileVersionLS & 0xffff) as u64,
                ];
            }
            let mut product = String::new();
            if VerQueryValueW(
                data.as_ptr().cast(),
                &HSTRING::from("\\VarFileInfo\\Translation"),
                &mut pointer,
                &mut length,
            )
            .as_bool()
                && length >= 4
            {
                let language = *(pointer as *const u16);
                let codepage = *(pointer as *const u16).add(1);
                let key = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\ProductName");
                if VerQueryValueW(
                    data.as_ptr().cast(),
                    &HSTRING::from(key),
                    &mut pointer,
                    &mut length,
                )
                .as_bool()
                    && length > 0
                {
                    let text = std::slice::from_raw_parts(pointer as *const u16, length as usize);
                    product = String::from_utf16_lossy(text)
                        .trim_end_matches('\0')
                        .to_owned();
                }
            }
            Some(VersionInfo { version, product })
        }
    }

    pub fn inspect(path: &Path) -> Option<Application> {
        if !path.is_absolute()
            || !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            || !path.is_file()
        {
            return None;
        }
        let file = path.file_name()?.to_string_lossy().to_lowercase();
        let info = version_info(path);
        let (name, id) = match file.as_str() {
            "claude.exe" => (None, Some(CLAUDE)),
            "codex.exe" => (None, Some(CODEX)),
            "chatgpt.exe"
                if info
                    .as_ref()
                    .is_some_and(|info| info.product.contains("Codex"))
                    || path.to_string_lossy().contains("OpenAI.Codex_") =>
            {
                (None, Some(CODEX))
            }
            _ => (Some(path.file_stem()?.to_string_lossy().into_owned()), None),
        };
        let name = name.or_else(|| id.and_then(known_name).map(str::to_owned))?;
        let directory = path.parent()?;
        let chromium = id.is_some()
            || [
                "chrome.exe",
                "msedge.exe",
                "brave.exe",
                "opera.exe",
                "vivaldi.exe",
            ]
            .contains(&file.as_str())
            || directory.join("chrome_elf.dll").exists()
            || directory.join("resources").join("app.asar").exists();
        let version = info.map(|info| info.version).unwrap_or_default();
        Some(Application {
            mode: mode(id, &version, chromium),
            name,
            path: path.to_string_lossy().into_owned(),
            id: id.map(str::to_owned),
            version,
        })
    }

    struct Known {
        name: &'static str,
        id: &'static str,
        executables: &'static [&'static str],
    }

    const KNOWN: [Known; 2] = [
        Known {
            name: "Claude",
            id: CLAUDE,
            executables: &["Claude.exe"],
        },
        Known {
            name: "Codex",
            id: CODEX,
            executables: &["Codex.exe", "ChatGPT.exe"],
        },
    ];

    fn uninstall_locations(name: &str) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for (hive, path) in [
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ] {
            let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ) else {
                continue;
            };
            for key in root.enum_keys().flatten() {
                let Ok(entry) = root.open_subkey_with_flags(&key, KEY_READ) else {
                    continue;
                };
                let display: String = entry.get_value("DisplayName").unwrap_or_default();
                let location: String = entry.get_value("InstallLocation").unwrap_or_default();
                if (display == name || display == format!("{name} Desktop")) && !location.is_empty()
                {
                    found.push(PathBuf::from(location));
                }
            }
        }
        found
    }

    /// Store (MSIX) installs of the current user.
    fn package_locations(known: &Known) -> Vec<PathBuf> {
        use windows::Management::Deployment::PackageManager;
        let packages = PackageManager::new()
            .and_then(|manager| manager.FindPackagesByUserSecurityId(&HSTRING::new()));
        let Ok(packages) = packages else {
            return Vec::new();
        };
        packages
            .into_iter()
            .filter(|package| {
                let Ok(id) = package.Id() else { return false };
                let name = id.Name().map(|name| name.to_string()).unwrap_or_default();
                let publisher = id.Publisher().map(|p| p.to_string()).unwrap_or_default();
                if known.id == CODEX {
                    name == "OpenAI.Codex"
                } else {
                    name.contains("Claude") && publisher.contains("Anthropic")
                }
            })
            .filter_map(|package| package.InstalledPath().ok())
            .map(|path| PathBuf::from(path.to_string()))
            .collect()
    }

    pub fn discover() -> Vec<Application> {
        let bases = ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let mut candidates = Vec::new();
        for known in &KNOWN {
            let mut roots = bases
                .iter()
                .flat_map(|base| {
                    [
                        base.join(known.name),
                        base.join("Programs").join(known.name),
                    ]
                })
                .chain(uninstall_locations(known.name))
                .chain(package_locations(known))
                .collect::<Vec<_>>();
            roots.sort();
            roots.dedup();
            for root in roots.iter().filter(|root| root.is_dir()) {
                // Squirrel installs live in app-<version>; never search a drive.
                let mut directories = vec![root.clone(), root.join("app")];
                directories.extend(
                    std::fs::read_dir(root)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter(|entry| {
                            entry.file_name().to_string_lossy().starts_with("app-")
                                && entry.path().is_dir()
                        })
                        .map(|entry| entry.path()),
                );
                for directory in directories {
                    for executable in known.executables {
                        if let Some(app) = inspect(&directory.join(executable))
                            && app.id.as_deref() == Some(known.id)
                        {
                            candidates.push((app, false));
                        }
                    }
                }
            }
        }
        select(candidates)
    }

    pub fn claude_is_managed() -> bool {
        [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
            .into_iter()
            .any(|hive| {
                RegKey::predef(hive)
                    .open_subkey_with_flags(r"SOFTWARE\Policies\Claude", KEY_READ)
                    .ok()
                    .and_then(|key| key.query_info().ok())
                    .is_some_and(|info| info.values > 0)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, version: &[u64], path: &str) -> Application {
        Application {
            name: known_name(id).unwrap().into(),
            path: path.into(),
            mode: mode(Some(id), version, true),
            id: Some(id.into()),
            version: version.to_vec(),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_discovery_finds_known_bundles_and_prefers_the_running_copy() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("Applications");
        let bundle = |name: &str, id: &str, version: &str| {
            let app = root.join(format!("{name}.app"));
            std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
            let mut info = plist::Dictionary::new();
            for (key, value) in [
                ("CFBundleIdentifier", id),
                ("CFBundleExecutable", "App"),
                ("CFBundleShortVersionString", version),
                ("CFBundleName", name),
            ] {
                info.insert(key.into(), plist::Value::String(value.into()));
            }
            plist::Value::Dictionary(info)
                .to_file_xml(app.join("Contents/Info.plist"))
                .unwrap();
            let executable = app.join("Contents/MacOS/App");
            std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            app.canonicalize().unwrap()
        };
        let old_codex = bundle("Codex", CODEX, "1.9");
        let new_codex = bundle("ChatGPT", CODEX, "1.10");
        bundle("Claude", CLAUDE, "2.0");
        bundle("Codex Copy", "unrelated.application", "99.0");
        let found = platform::discover_in(std::slice::from_ref(&root), &[]);
        assert_eq!(found.len(), 2);
        let codex = found.iter().find(|app| app.name == "Codex").unwrap();
        assert_eq!(Path::new(&codex.path), new_codex);
        assert_eq!(codex.mode, Mode::Chromium);
        assert_eq!(
            found.iter().find(|app| app.name == "Claude").unwrap().mode,
            Mode::ClaudeNative
        );
        let running = platform::discover_in(
            std::slice::from_ref(&root),
            std::slice::from_ref(&old_codex),
        );
        let codex = running.iter().find(|app| app.name == "Codex").unwrap();
        assert_eq!(Path::new(&codex.path), old_codex);
        assert!(platform::discover_in(&[temporary.path().join("Missing")], &[]).is_empty());
    }

    #[test]
    fn native_claude_needs_its_proxy_release_and_running_installs_win() {
        #[cfg(target_os = "macos")]
        assert_eq!(parse_version("1.44121.1 (build 7)"), [1, 44121, 1]);
        assert_eq!(mode(Some(CLAUDE), &[1, 44121, 0], true), Mode::Chromium);
        assert_eq!(
            mode(Some(CLAUDE), &[1, 44121, 1, 0], true),
            Mode::ClaudeNative
        );
        assert_eq!(mode(Some(CLAUDE), &[2], true), Mode::ClaudeNative);
        assert_eq!(mode(None, &[9], false), Mode::Environment);
        let picked = select(vec![
            (app(CODEX, &[2, 0], "/new"), false),
            (app(CODEX, &[1, 0], "/running"), true),
            (app(CLAUDE, &[1, 0], "/old"), false),
            (app(CLAUDE, &[1, 1], "/newer"), false),
        ]);
        let paths = picked
            .iter()
            .map(|app| app.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/newer", "/running"]);
    }
}
