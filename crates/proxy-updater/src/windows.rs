//! Windows installer handoff. ShellExecute gives the worker an independent
//! lifetime and resolves UAC before the application is allowed to exit.
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use ring::digest;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, MOVEFILE_REPLACE_EXISTING, MoveFileExW,
    VerQueryValueW,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW, SW_HIDE};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    process_id: u32,
    installer: PathBuf,
    app: PathBuf,
    version: String,
    sha256: String,
    size: u64,
    #[serde(default = "yes")]
    elevate: bool,
    #[serde(default = "yes")]
    reopen: bool,
    #[serde(default = "yes")]
    show_errors: bool,
    #[serde(default = "exit_timeout")]
    exit_timeout_seconds: u64,
}

fn yes() -> bool {
    true
}
fn exit_timeout() -> u64 {
    120
}

#[derive(Serialize, Deserialize)]
struct Status {
    stage: String,
    message: String,
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn write_status(work: &Path, stage: &str, message: &str) -> Result<()> {
    let pending = work.join("install-status.tmp");
    let final_path = work.join("install-status.json");
    let bytes = serde_json::to_vec(&Status {
        stage: stage.into(),
        message: message.into(),
    })?;
    fs::write(&pending, bytes)?;
    // SAFETY: both paths remain alive and are terminated UTF-16 strings.
    ensure!(
        unsafe {
            MoveFileExW(
                wide(&pending).as_ptr(),
                wide(&final_path).as_ptr(),
                MOVEFILE_REPLACE_EXISTING,
            )
        } != 0,
        "Writing updater state: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn shell_launch(executable: &Path, parameters: &OsStr, elevate: bool) -> Result<OwnedHandle> {
    let file = wide(executable);
    let parameters = wide(parameters);
    let verb = wide(if elevate { "runas" } else { "open" });
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: all pointers are valid for this synchronous call. A successful
    // launch transfers one process handle to us.
    ensure!(
        unsafe { ShellExecuteExW(&mut info) } != 0,
        "Starting updater: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        !info.hProcess.is_null(),
        "Windows did not return the updater process"
    );
    Ok(unsafe { OwnedHandle::from_raw_handle(info.hProcess) })
}

fn read_request(path: &Path) -> Result<Request> {
    ensure!(
        path.is_absolute(),
        "Updater request must be an absolute path"
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= 16 * 1024, "Updater request is too large");
    let request: Request = serde_json::from_slice(&bytes)?;
    ensure!(request.process_id != 0, "Missing outgoing process");
    ensure!(
        request.app.is_absolute() && request.installer.is_absolute(),
        "Update paths must be absolute"
    );
    ensure!(
        request.app.is_file() && request.installer.is_file(),
        "Update files are missing"
    );
    ensure!(
        request.size > 0
            && request.sha256.len() == 64
            && request.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid installer identity"
    );
    ensure!(
        !request.version.is_empty() && request.version.len() <= 80,
        "Invalid target version"
    );
    ensure!(
        (1..=600).contains(&request.exit_timeout_seconds),
        "Invalid exit timeout"
    );
    Ok(request)
}

pub fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mode = arguments.next().context("Missing updater mode")?;
    let path = PathBuf::from(arguments.next().context("Missing updater request")?);
    ensure!(arguments.next().is_none(), "Unexpected updater argument");
    let work = path.parent().context("Missing updater directory")?;
    let result = match mode.to_str() {
        Some("--prepare") => prepare(&path),
        Some("--worker") => worker(&path),
        _ => bail!("Unknown updater mode"),
    };
    if let Err(error) = &result {
        let _ = write_status(work, "failed", &format!("{error:#}"));
    }
    result
}

fn prepare(path: &Path) -> Result<()> {
    let request = read_request(path)?;
    let work = path.parent().unwrap();
    ensure!(
        !work.join("cancel").exists() && !work.join("install-status.json").exists(),
        "Update directory was already used"
    );
    // The installed copy can now be overwritten by Inno while this copy runs.
    let helper = work.join("cipherrelay-update-worker.exe");
    ensure!(!helper.exists(), "Update worker already exists");
    fs::copy(std::env::current_exe()?, &helper)?;
    // Windows file names cannot contain quotes. This is an argv argument,
    // never cmd.exe or PowerShell input.
    let parameters = OsString::from(format!("--worker \"{}\"", path.display()));
    let handle = shell_launch(&helper, &parameters, request.elevate)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(bytes) = fs::read(work.join("install-status.json")) {
            let status: Status = serde_json::from_slice(&bytes)?;
            ensure!(status.stage != "failed", "{}", status.message);
            if status.stage == "ready" {
                return Ok(());
            }
        }
        // SAFETY: handle is held for the entire wait.
        let wait = unsafe { WaitForSingleObject(handle.as_raw_handle(), 100) };
        if wait != WAIT_TIMEOUT || Instant::now() >= deadline {
            let _ = fs::write(work.join("cancel"), b"launch failed");
            // The worker can publish its failure between our read and wait.
            if let Ok(bytes) = fs::read(work.join("install-status.json"))
                && let Ok(status) = serde_json::from_slice::<Status>(&bytes)
                && status.stage == "failed"
            {
                bail!("{}", status.message);
            }
            bail!("Update worker exited or did not acknowledge readiness");
        }
    }
}

fn verify_installer(request: &Request) -> Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    // Deny writes and deletion while the verified executable is being launched.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&request.installer)?;
    ensure!(
        file.metadata()?.len() == request.size,
        "Installer size differs from the signed manifest"
    );
    let mut hash = digest::Context::new(&digest::SHA256);
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual = hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ensure!(
        actual == request.sha256,
        "Installer checksum differs from the signed manifest"
    );
    Ok(file)
}

fn worker(path: &Path) -> Result<()> {
    let request = read_request(path)?;
    let work = path.parent().unwrap();
    // Pin the actual outgoing process, so PID reuse can never target another app.
    let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, request.process_id) };
    ensure!(
        !raw.is_null(),
        "Opening outgoing application: {}",
        std::io::Error::last_os_error()
    );
    let parent = unsafe { OwnedHandle::from_raw_handle(raw) };
    ensure!(
        unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } == WAIT_TIMEOUT,
        "Outgoing application already exited"
    );
    verify_installer(&request)?;
    write_status(work, "ready", "Waiting for application shutdown")?;
    let deadline = Instant::now() + Duration::from_secs(request.exit_timeout_seconds);
    loop {
        if work.join("cancel").exists() || Instant::now() >= deadline {
            return write_status(
                work,
                "cancelled",
                "Application shutdown was cancelled or timed out",
            );
        }
        let wait = unsafe { WaitForSingleObject(parent.as_raw_handle(), 100) };
        if wait == WAIT_OBJECT_0 {
            break;
        }
        ensure!(
            wait == WAIT_TIMEOUT,
            "Waiting for outgoing application failed"
        );
    }
    if work.join("cancel").exists() {
        return write_status(work, "cancelled", "Application shutdown was cancelled");
    }
    let result = install(&request, work);
    if let Err(error) = &result {
        write_status(work, "failed", &format!("{error:#}"))?;
        if request.show_errors {
            let message = wide(format!(
                "CipherRelay update failed:\n{error:#}\n\nLogs and the installer were kept in:\n{}",
                work.display()
            ));
            // Only show errors after the old app has exited; before that the UI
            // reports the failure without closing the running application.
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    message.as_ptr(),
                    wide("CipherRelay").as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
    }
    result
}

fn install(request: &Request, work: &Path) -> Result<()> {
    let pinned_installer = verify_installer(request)?;
    write_status(work, "installing", "Installer started")?;
    let exit = Command::new(&request.installer)
        .args([
            "/SP-",
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/NOCLOSEAPPLICATIONS",
            "/NORESTARTAPPLICATIONS",
            "/RESTARTEXITCODE=3010",
        ])
        .arg(format!(
            "/DIR={}",
            request
                .app
                .parent()
                .context("Missing install directory")?
                .display()
        ))
        .arg(format!("/LOG={}", work.join("installer.log").display()))
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("Running installer")?;
    ensure!(
        exit.success(),
        "Installer failed with exit code {:?}",
        exit.code()
    );
    let version = product_version(&request.app)?;
    ensure!(
        version == request.version,
        "Installer returned success but installed version is {version}, expected {}",
        request.version
    );
    if request.reopen {
        Command::new(&request.app)
            .current_dir(request.app.parent().unwrap())
            .spawn()
            .context("Reopening updated application")?;
    }
    write_status(work, "complete", &version)?;
    drop(pinned_installer);
    // Cleanup failure must not turn a verified successful install into a failed
    // update (antivirus can temporarily retain a handle to the package).
    let _ = fs::remove_file(&request.installer);
    Ok(())
}

fn product_version(path: &Path) -> Result<String> {
    let path = wide(path);
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), std::ptr::null_mut()) };
    ensure!(size > 0, "Application has no version resource");
    let mut bytes = vec![0u8; size as usize];
    ensure!(
        unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, bytes.as_mut_ptr().cast()) } != 0,
        "Reading application version failed"
    );
    let mut value = std::ptr::null_mut();
    let mut length = 0;
    let translation = wide(r"\VarFileInfo\Translation");
    ensure!(
        unsafe {
            VerQueryValueW(
                bytes.as_ptr().cast(),
                translation.as_ptr(),
                &mut value,
                &mut length,
            )
        } != 0
            && length >= 4,
        "Application version translation is missing"
    );
    // The resource buffer owns this (possibly unaligned) language/codepage pair.
    let language = unsafe { std::ptr::read_unaligned(value.cast::<u16>()) };
    let codepage = unsafe { std::ptr::read_unaligned(value.cast::<u16>().add(1)) };
    let query = wide(format!(
        r"\StringFileInfo\{language:04x}{codepage:04x}\ProductVersion"
    ));
    ensure!(
        unsafe {
            VerQueryValueW(
                bytes.as_ptr().cast(),
                query.as_ptr(),
                &mut value,
                &mut length,
            )
        } != 0
            && length > 0,
        "Application ProductVersion is missing"
    );
    let units = unsafe { std::slice::from_raw_parts(value.cast::<u16>(), length as usize) };
    Ok(String::from_utf16(units)?
        .trim_end_matches('\0')
        .trim()
        .to_owned())
}
