//! Generated launchers. Each owns its settings, so it keeps working while
//! CipherRelay is closed, and keeps its path across edits so Dock items and
//! shortcuts stay valid. Only launchers inside the managed directory can be
//! replaced or moved to the Trash, and a failed save leaves the previous one.
use std::path::{Path, PathBuf};

use super::launch::Settings;
use super::{Entry, Error, Mode, Paths, Result, apps};

pub fn list(directory: &Path) -> Result<Vec<Entry>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in std::fs::read_dir(directory)? {
        let path = item?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with('.') || !platform::is_launcher(&path) {
            continue;
        }
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(Error::new("A managed launcher cannot be a symbolic link."));
        }
        entries.push(platform::read(&path)?);
    }
    entries.sort_by_key(|entry| entry.name.to_lowercase());
    Ok(entries)
}

pub fn find(directory: &Path, id: Option<&str>) -> Result<PathBuf> {
    list(directory)?
        .into_iter()
        .find(|entry| entry.id.as_deref() == id && id.is_some())
        .and_then(|entry| entry.launcher_path)
        .map(PathBuf::from)
        .ok_or_else(|| Error::new("Launcher no longer exists. Refresh the list."))
}

pub fn save(paths: &Paths, entry: Entry) -> Result<Entry> {
    if entry.mode == Mode::ClaudeNative {
        return Err(Error::new("Invalid launch mode."));
    }
    let app = apps::inspect(Path::new(&entry.app_path)).ok_or_else(|| {
        Error::new("Select an installed application, not another proxy launcher.")
    })?;
    if app
        .id
        .as_deref()
        .is_some_and(|id| id.starts_with(platform::IDENTIFIER_PREFIX))
    {
        return Err(Error::new(
            "Select an installed application, not another proxy launcher.",
        ));
    }
    if !paths.launcher_executable.is_file() {
        return Err(Error::new(
            "This build is missing the proxy launcher helper.",
        ));
    }
    let previous = match &entry.id {
        Some(id) => Some(find(&paths.launchers, Some(id))?),
        None => None,
    };
    let settings = Settings {
        schema_version: 1,
        id: entry.id.clone().unwrap_or_else(super::new_id),
        name: entry.name.trim().to_owned(),
        app_path: app.path.clone(),
        application_id: app.id.clone(),
        mode: entry.mode,
        port: entry.port,
        bypass_rules: entry.bypass_rules.clone(),
        shortcut_name: None,
    };
    std::fs::create_dir_all(&paths.launchers)?;
    let destination = platform::write(paths, settings, previous.as_deref())?;
    platform::read(&destination)
}

pub fn trash(directory: &Path, id: &str) -> Result<()> {
    let path = find(directory, Some(id))?;
    // A Windows launcher is its folder; the shortcut alone would orphan it.
    let target = if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
    {
        path.parent().map(Path::to_path_buf).unwrap_or(path)
    } else {
        path
    };
    trash::delete(&target).map_err(|error| Error::new(error.to_string()))
}

/// Builds `staged`, then swaps it in place of `destination`, restoring the
/// previous launcher if the swap fails.
fn replace(staged: &Path, destination: &Path, existing: bool) -> Result<()> {
    if !existing {
        if destination.exists() {
            return Err(Error::new("The launcher destination already exists."));
        }
        std::fs::rename(staged, destination)?;
        return Ok(());
    }
    let backup = destination.with_file_name(format!(".backup-{}", super::new_id()));
    std::fs::rename(destination, &backup)?;
    if let Err(error) = std::fs::rename(staged, destination) {
        let _ = std::fs::rename(&backup, destination);
        return Err(error.into());
    }
    let _ = std::fs::remove_dir_all(&backup);
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub const IDENTIFIER_PREFIX: &str = "com.cipherrelay.launcher.";
    const EXECUTABLE: &str = "ProxyLauncher";

    pub fn is_launcher(path: &Path) -> bool {
        path.extension().is_some_and(|ext| ext == "app")
    }

    pub fn read(bundle: &Path) -> Result<Entry> {
        let settings = Settings::read(
            &bundle
                .join("Contents/Resources")
                .join(super::super::launch::SETTINGS_FILE),
        )?;
        let identifier = plist::Value::from_file(bundle.join("Contents/Info.plist"))
            .ok()
            .and_then(plist::Value::into_dictionary)
            .and_then(|info| {
                info.get("CFBundleIdentifier")?
                    .as_string()
                    .map(str::to_owned)
            });
        if identifier.as_deref()
            != Some(&format!(
                "{IDENTIFIER_PREFIX}{}",
                settings.id.to_lowercase()
            ))
        {
            return Err(Error::new(
                "Unrecognized application in the launcher directory.",
            ));
        }
        Ok(settings.entry(bundle))
    }

    pub fn write(paths: &Paths, settings: Settings, previous: Option<&Path>) -> Result<PathBuf> {
        let destination = previous.map(Path::to_path_buf).unwrap_or_else(|| {
            paths
                .launchers
                .join(format!("{} - {}.app", settings.name, &settings.id[..8]))
        });
        let stage = paths
            .launchers
            .join(format!(".staging-{}.app", super::super::new_id()));
        let result = (|| {
            let contents = stage.join("Contents");
            std::fs::create_dir_all(contents.join("Resources"))?;
            std::fs::create_dir_all(contents.join("MacOS"))?;
            std::fs::copy(
                &paths.launcher_executable,
                contents.join("MacOS").join(EXECUTABLE),
            )?;
            settings.write(
                &contents
                    .join("Resources")
                    .join(super::super::launch::SETTINGS_FILE),
            )?;
            let mut info = plist::Dictionary::new();
            for (key, value) in [
                (
                    "CFBundleIdentifier",
                    format!("{IDENTIFIER_PREFIX}{}", settings.id.to_lowercase()),
                ),
                ("CFBundleName", settings.name.clone()),
                ("CFBundleDisplayName", settings.name.clone()),
                ("CFBundleExecutable", EXECUTABLE.into()),
                ("CFBundlePackageType", "APPL".into()),
                ("CFBundleVersion", "1".into()),
                ("CFBundleShortVersionString", "1.0".into()),
                ("LSMinimumSystemVersion", "12.0".into()),
            ] {
                info.insert(key.into(), plist::Value::String(value));
            }
            info.insert("LSUIElement".into(), plist::Value::Boolean(true));
            // The launcher wears the target app's icon in the Dock.
            if let Some(icon) = target_icon(Path::new(&settings.app_path)) {
                std::fs::copy(icon, contents.join("Resources/AppIcon.icns"))?;
                info.insert(
                    "CFBundleIconFile".into(),
                    plist::Value::String("AppIcon.icns".into()),
                );
            }
            plist::Value::Dictionary(info)
                .to_file_xml(contents.join("Info.plist"))
                .map_err(|error| Error::new(error.to_string()))?;
            for args in [
                &["--force", "--sign", "-", "--timestamp=none"][..],
                &["--verify", "--strict"][..],
            ] {
                let output = std::process::Command::new("/usr/bin/codesign")
                    .args(args)
                    .arg(&stage)
                    .output()?;
                if !output.status.success() {
                    return Err(Error::new(format!(
                        "Launcher signing failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    )));
                }
            }
            replace(&stage, &destination, previous.is_some())
        })();
        if stage.exists() {
            let _ = std::fs::remove_dir_all(&stage);
        }
        result.map(|()| destination)
    }

    fn target_icon(app: &Path) -> Option<PathBuf> {
        let info = plist::Value::from_file(app.join("Contents/Info.plist"))
            .ok()?
            .into_dictionary()?;
        let name = info.get("CFBundleIconFile")?.as_string()?;
        if name.contains('/') {
            return None;
        }
        let file = if Path::new(name).extension().is_some() {
            name.to_owned()
        } else {
            format!("{name}.icns")
        };
        Some(app.join("Contents/Resources").join(file)).filter(|path| path.is_file())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize, IPersistFile,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{HSTRING, Interface};

    use super::*;

    /// Windows launchers carry no bundle identifier of their own.
    pub const IDENTIFIER_PREFIX: &str = "com.cipherrelay.launcher.";
    const EXECUTABLE: &str = "CipherRelayLauncher.exe";

    pub fn is_launcher(path: &Path) -> bool {
        path.is_dir()
            && super::super::is_id(&path.file_name().unwrap_or_default().to_string_lossy())
    }

    pub fn read(folder: &Path) -> Result<Entry> {
        let settings = Settings::read(&folder.join(super::super::launch::SETTINGS_FILE))?;
        let shortcut = settings.shortcut_name.clone().unwrap_or_default();
        if settings.id != folder.file_name().unwrap_or_default().to_string_lossy()
            || shortcut.is_empty()
            || shortcut
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
            || !shortcut.to_lowercase().ends_with(".lnk")
        {
            return Err(Error::new("Invalid managed launcher."));
        }
        Ok(settings.entry(&folder.join(shortcut)))
    }

    pub fn write(
        paths: &Paths,
        mut settings: Settings,
        previous: Option<&Path>,
    ) -> Result<PathBuf> {
        let destination = paths.launchers.join(&settings.id);
        // Keep the shortcut's file name across edits, renames included.
        settings.shortcut_name = Some(match previous {
            Some(shortcut) => shortcut
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            None => format!("{}.lnk", settings.name),
        });
        let stage = paths
            .launchers
            .join(format!(".staging-{}", super::super::new_id()));
        let result = (|| {
            std::fs::create_dir_all(&stage)?;
            settings.write(&stage.join(super::super::launch::SETTINGS_FILE))?;
            std::fs::copy(&paths.launcher_executable, stage.join(EXECUTABLE))?;
            shortcut(
                &stage.join(settings.shortcut_name.as_deref().unwrap_or_default()),
                &destination,
                &settings,
            )?;
            replace(&stage, &destination, previous.is_some())
        })();
        if stage.exists() {
            let _ = std::fs::remove_dir_all(&stage);
        }
        result.map(|()| destination)
    }

    /// A Shell shortcut to the launcher in its final folder, wearing the target
    /// app's icon.
    fn shortcut(path: &Path, folder: &Path, settings: &Settings) -> Result<()> {
        let error = |error: windows::core::Error| Error::new(error.to_string());
        // SAFETY: COM is initialized for this thread and balanced below; every
        // string passed is an owned HSTRING that outlives its call.
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_APARTMENTTHREADED).is_ok();
            let result = (|| {
                let link: IShellLinkW =
                    CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(error)?;
                link.SetPath(&HSTRING::from(folder.join(EXECUTABLE).as_os_str()))
                    .map_err(error)?;
                link.SetArguments(&HSTRING::from(format!(
                    "--config \"{}\"",
                    folder.join(super::super::launch::SETTINGS_FILE).display()
                )))
                .map_err(error)?;
                link.SetWorkingDirectory(&HSTRING::from(folder.as_os_str()))
                    .map_err(error)?;
                link.SetDescription(&HSTRING::from(settings.name.as_str()))
                    .map_err(error)?;
                link.SetIconLocation(&HSTRING::from(settings.app_path.as_str()), 0)
                    .map_err(error)?;
                link.cast::<IPersistFile>()
                    .map_err(error)?
                    .Save(&HSTRING::from(path.as_os_str()), true)
                    .map_err(error)
            })();
            if initialized {
                CoUninitialize();
            }
            result
        }
    }
}
