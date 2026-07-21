//! Installed Win32 application discovery for the TUN process picker.
//!
//! Windows does not expose one complete executable catalog. We combine the
//! Shell's Start Menu shortcuts with the documented App Paths and Uninstall
//! registry registrations, then scan only bounded application directories
//! advertised by those registrations.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tun2proxy::normalize_process_name;
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize, IPersistFile, STGM_READ,
};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_Programs, IShellLinkW, KNOWN_FOLDER_FLAG,
    SHGetKnownFolderPath, SLGP_RAWPATH, ShellLink,
};
use windows::core::{Interface, PCWSTR};
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
};
use winreg::{HKEY, RegKey};

const APP_PATHS: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
const CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_SHORTCUTS: usize = 2048;
const MAX_SCAN_DEPTH: usize = 5;
const MAX_SCAN_ENTRIES_PER_APP: usize = 4096;
const MAX_DISCOVERED_EXECUTABLES_PER_APP: usize = 1024;
const MAX_CATALOG_EXECUTABLES_PER_APP: usize = 8;

static INSTALLED_CACHE: LazyLock<Mutex<Option<InstalledProcessCache>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Debug)]
pub(super) struct InstalledProcessInfo {
    pub name: String,
    pub display_name: String,
    pub executable_paths: Vec<String>,
    pub aliases: Vec<String>,
}

struct InstalledProcessCache {
    created: Instant,
    processes: Vec<InstalledProcessInfo>,
}

#[derive(Default)]
struct CatalogEntry {
    display_name: String,
    executable_paths: BTreeSet<String>,
    aliases: BTreeSet<String>,
}

pub(super) fn installed_processes() -> Vec<InstalledProcessInfo> {
    let mut cache = INSTALLED_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = cache.as_ref()
        && cached.created.elapsed() < CACHE_TTL
    {
        return cached.processes.clone();
    }

    let processes = build_catalog();
    *cache = Some(InstalledProcessCache {
        created: Instant::now(),
        processes: processes.clone(),
    });
    processes
}

fn build_catalog() -> Vec<InstalledProcessInfo> {
    let mut catalog = BTreeMap::<String, CatalogEntry>::new();
    collect_app_paths(&mut catalog);
    collect_start_menu_shortcuts(&mut catalog);
    collect_uninstall_registrations(&mut catalog);

    catalog
        .into_iter()
        .map(|(name, entry)| InstalledProcessInfo {
            name,
            display_name: entry.display_name,
            executable_paths: entry.executable_paths.into_iter().collect(),
            aliases: entry.aliases.into_iter().collect(),
        })
        .collect()
}

fn collect_app_paths(catalog: &mut BTreeMap<String, CatalogEntry>) {
    for (hive, view) in registry_views() {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(APP_PATHS, KEY_READ | view)
        else {
            continue;
        };
        for subkey_name in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&subkey_name, KEY_READ) else {
                continue;
            };
            let path = key
                .get_value::<String, _>("")
                .ok()
                .and_then(|value| executable_path_from_command(&value))
                .unwrap_or_else(|| PathBuf::from(&subkey_name));
            add_executable(catalog, &path, None);
        }
    }
}

fn collect_uninstall_registrations(catalog: &mut BTreeMap<String, CatalogEntry>) {
    let mut scanned_roots = HashSet::<String>::new();
    for (hive, view) in registry_views() {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(UNINSTALL, KEY_READ | view)
        else {
            continue;
        };
        for subkey_name in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&subkey_name, KEY_READ) else {
                continue;
            };
            let display_name = key
                .get_value::<String, _>("DisplayName")
                .ok()
                .filter(|name| !name.trim().is_empty());
            let display_icon = key
                .get_value::<String, _>("DisplayIcon")
                .ok()
                .and_then(|value| executable_path_from_command(&value));
            let registered_executable = display_icon
                .as_deref()
                .is_some_and(|path| add_executable(catalog, path, display_name.as_deref()));
            if registered_executable {
                continue;
            }

            let install_location = key
                .get_value::<String, _>("InstallLocation")
                .ok()
                .map(|value| PathBuf::from(value.trim().trim_matches('"')))
                .filter(|path| !path.as_os_str().is_empty());
            let uninstall_parent = key
                .get_value::<String, _>("UninstallString")
                .ok()
                .and_then(|value| executable_path_from_command(&value))
                .and_then(|path| path.parent().map(Path::to_path_buf));
            let scan_root = install_location
                .or_else(|| display_icon.and_then(|path| path.parent().map(Path::to_path_buf)))
                .or(uninstall_parent);
            let Some(scan_root) = scan_root.filter(|path| is_safe_scan_root(path)) else {
                continue;
            };
            let key = scan_root.to_string_lossy().to_ascii_lowercase();
            if !scanned_roots.insert(key) {
                continue;
            }
            scan_application_directory(catalog, &scan_root, display_name.as_deref());
        }
    }
}

fn registry_views() -> [(HKEY, u32); 4] {
    [
        (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
        (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
        (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
    ]
}

fn collect_start_menu_shortcuts(catalog: &mut BTreeMap<String, CatalogEntry>) {
    let apartment = ComApartment::initialize();
    if apartment.is_none() {
        return;
    }

    let mut shortcuts = Vec::new();
    for folder_id in [&FOLDERID_Programs, &FOLDERID_CommonPrograms] {
        if let Some(path) = known_folder_path(folder_id) {
            collect_files_with_extension(&path, "lnk", MAX_SHORTCUTS, &mut shortcuts);
        }
    }
    shortcuts.truncate(MAX_SHORTCUTS);
    for shortcut in shortcuts {
        let Some(target) = resolve_shell_link(&shortcut) else {
            continue;
        };
        let alias = shortcut.file_stem().and_then(|name| name.to_str());
        add_executable(catalog, &target, alias);
    }
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn initialize() -> Option<Self> {
        // SAFETY: no reserved pointer is supplied. S_OK and S_FALSE both
        // require a matching CoUninitialize; RPC_E_CHANGED_MODE means the
        // caller already initialized COM with another apartment model.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if result.is_ok() {
            Some(Self { uninitialize: true })
        } else if result == RPC_E_CHANGED_MODE {
            Some(Self {
                uninitialize: false,
            })
        } else {
            None
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: paired with the successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

fn known_folder_path(folder_id: &windows::core::GUID) -> Option<PathBuf> {
    // SAFETY: Shell allocates the returned NUL-terminated path with the COM
    // allocator; it is copied before being released exactly once below.
    let pointer = unsafe { SHGetKnownFolderPath(folder_id, KNOWN_FOLDER_FLAG(0), None) }.ok()?;
    let path = unsafe { pointer.to_string() }.ok().map(PathBuf::from);
    unsafe { CoTaskMemFree(Some(pointer.0.cast())) };
    path
}

fn resolve_shell_link(shortcut: &Path) -> Option<PathBuf> {
    let wide = shortcut
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: COM is initialized by the caller, the persisted object and link
    // interfaces are reference counted, and all buffers remain live for each
    // call. Resolve is intentionally not called, avoiding UI and network I/O.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let persisted: IPersistFile = link.cast().ok()?;
        persisted.Load(PCWSTR(wide.as_ptr()), STGM_READ).ok()?;
        let mut target = vec![0_u16; 32_768];
        link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
            .ok()?;
        let length = target.iter().position(|unit| *unit == 0)?;
        (length > 0).then(|| PathBuf::from(OsString::from_wide(&target[..length])))
    }
}

fn scan_application_directory(
    catalog: &mut BTreeMap<String, CatalogEntry>,
    root: &Path,
    alias: Option<&str>,
) {
    // Breadth-first traversal finds application entry points in shallow Game,
    // Client, and Launcher directories before bounded scanning reaches deeply
    // nested assets or bundled runtimes.
    let mut directories = VecDeque::from([(root.to_path_buf(), 0_usize)]);
    let mut visited = 0_usize;
    let mut executables = Vec::<(i32, PathBuf)>::new();
    'scan: while let Some((directory, depth)) = directories.pop_front() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_SCAN_ENTRIES_PER_APP
                || executables.len() >= MAX_DISCOVERED_EXECUTABLES_PER_APP
            {
                break 'scan;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if depth < MAX_SCAN_DEPTH && !is_ignored_directory(&entry.file_name()) {
                    directories.push_back((entry.path(), depth + 1));
                }
            } else if file_type.is_file()
                && is_executable_path(&entry.path())
                && let Some(score) = executable_candidate_score(root, &entry.path())
            {
                executables.push((score, entry.path()));
            }
        }
    }
    executables.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    for (_, path) in executables
        .into_iter()
        .take(MAX_CATALOG_EXECUTABLES_PER_APP)
    {
        add_executable(catalog, &path, alias);
    }
}

fn collect_files_with_extension(
    root: &Path,
    extension: &str,
    limit: usize,
    output: &mut Vec<PathBuf>,
) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if output.len() >= limit {
                return;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if entry
                .path()
                .extension()
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
            {
                output.push(entry.path());
            }
        }
    }
}

fn add_executable(
    catalog: &mut BTreeMap<String, CatalogEntry>,
    path: &Path,
    alias: Option<&str>,
) -> bool {
    if !is_executable_path(path) {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = normalize_process_name(file_name);
    if name.is_empty() || is_indirect_host(&name) || is_maintenance_executable(&name) {
        return false;
    }
    let display_name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(&name)
        .to_string();
    let alias = alias
        .map(str::trim)
        .filter(|alias| !alias.is_empty() && normalize_process_name(alias) != name)
        .map(str::to_string);
    let entry = catalog.entry(name).or_default();
    if entry.display_name.is_empty() {
        entry.display_name = display_name;
    }
    if path.is_absolute() {
        entry
            .executable_paths
            .insert(path.to_string_lossy().into_owned());
    }
    if let Some(alias) = alias {
        entry.aliases.insert(alias);
    }
    true
}

fn executable_candidate_score(root: &Path, path: &Path) -> Option<i32> {
    let relative = path.strip_prefix(root).ok()?;
    if relative
        .components()
        .any(|component| is_ignored_directory(component.as_os_str()))
    {
        return None;
    }
    let file_name = path.file_name()?.to_str()?;
    let name = normalize_process_name(file_name);
    if name.is_empty() || is_indirect_host(&name) || is_maintenance_executable(&name) {
        return None;
    }

    let depth = relative.components().count().saturating_sub(1) as i32;
    let parent_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map(normalize_process_name)
        .unwrap_or_default();
    let mut score = 100 - depth * 10;
    if parent_name == name {
        score += 100;
    }
    if parent_name == "game" || parent_name == "bin" {
        score += 60;
    }
    if name.contains("client") || name.contains("launcher") {
        score += 35;
    }
    Some(score)
}

fn executable_path_from_command(command: &str) -> Option<PathBuf> {
    let trimmed = command.trim();
    let lowercase = trimmed.to_ascii_lowercase();
    let end = lowercase.find(".exe")? + 4;
    let raw_path = trimmed.get(..end)?.trim().trim_start_matches('"').trim();
    (!raw_path.is_empty()).then(|| PathBuf::from(raw_path))
}

fn is_executable_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

fn is_safe_scan_root(path: &Path) -> bool {
    if !path.is_dir() || path.parent().is_none() {
        return false;
    }
    let normalized = path
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase();
    let broad_roots = [
        std::env::var("ProgramFiles").ok(),
        std::env::var("ProgramFiles(x86)").ok(),
        std::env::var("ProgramData").ok(),
        std::env::var("SystemRoot").ok(),
        std::env::var("WINDIR").ok(),
    ];
    !broad_roots.into_iter().flatten().any(|root| {
        root.trim_end_matches(['\\', '/'])
            .eq_ignore_ascii_case(&normalized)
    })
}

fn is_ignored_directory(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_string_lossy().to_ascii_lowercase().as_str(),
        "anticheatexpert"
            | "cache"
            | "caches"
            | "coach"
            | "cross"
            | "diagnosticassistant"
            | "logs"
            | "redist"
            | "redistributable"
            | "temp"
            | "tmp"
    )
}

fn is_indirect_host(name: &str) -> bool {
    matches!(
        name,
        "applicationframehost"
            | "cmd"
            | "explorer"
            | "mshta"
            | "powershell"
            | "pwsh"
            | "rundll32"
            | "wscript"
    )
}

fn is_maintenance_executable(name: &str) -> bool {
    name.starts_with("unins")
        || name.contains("uninstall")
        || name.contains("crashhandler")
        || name == "setup"
        || name == "installer"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_executable_from_registered_commands() {
        assert_eq!(
            executable_path_from_command(r#""E:\Games\League of Legends.exe" --launch"#),
            Some(PathBuf::from(r"E:\Games\League of Legends.exe"))
        );
        assert_eq!(
            executable_path_from_command(r"C:\Apps\client.exe,0"),
            Some(PathBuf::from(r"C:\Apps\client.exe"))
        );
        assert_eq!(executable_path_from_command("shell:AppsFolder"), None);
    }

    #[test]
    fn excludes_shell_hosts_and_maintenance_tools() {
        let mut catalog = BTreeMap::new();
        add_executable(
            &mut catalog,
            Path::new(r"C:\Windows\explorer.exe"),
            Some("Store app"),
        );
        add_executable(
            &mut catalog,
            Path::new(r"E:\Game\League of Legends.exe"),
            Some("英雄联盟"),
        );
        add_executable(
            &mut catalog,
            Path::new(r"E:\Game\uninstall.exe"),
            Some("英雄联盟"),
        );

        assert_eq!(catalog.keys().collect::<Vec<_>>(), ["league of legends"]);
        assert!(catalog["league of legends"].aliases.contains("英雄联盟"));
    }

    #[test]
    fn ranks_game_entry_points_and_ignores_support_directories() {
        let root = Path::new(r"E:\WeGameApps\英雄联盟");
        let game = root.join(r"Game\League of Legends.exe");
        let client = root.join(r"LeagueClient\LeagueClient.exe");
        let diagnostic = root.join(r"LeagueClient\DiagnosticAssistant\diagnostic-assistant.exe");

        assert!(executable_candidate_score(root, &game).unwrap() >= 140);
        assert!(executable_candidate_score(root, &client).unwrap() >= 180);
        assert_eq!(executable_candidate_score(root, &diagnostic), None);
    }

    #[test]
    fn bounded_directory_scan_keeps_a_dormant_game_executable() {
        let root = std::env::temp_dir().join(format!(
            "proxy-client-installed-app-test-{}",
            std::process::id()
        ));
        let game = root.join("Game").join("League of Legends.exe");
        let diagnostic = root
            .join("DiagnosticAssistant")
            .join("diagnostic-assistant.exe");
        std::fs::create_dir_all(game.parent().unwrap()).unwrap();
        std::fs::create_dir_all(diagnostic.parent().unwrap()).unwrap();
        std::fs::write(&game, []).unwrap();
        std::fs::write(&diagnostic, []).unwrap();

        let mut catalog = BTreeMap::new();
        scan_application_directory(&mut catalog, &root, Some("英雄联盟"));

        assert!(catalog.contains_key("league of legends"));
        assert!(!catalog.contains_key("diagnostic-assistant"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
