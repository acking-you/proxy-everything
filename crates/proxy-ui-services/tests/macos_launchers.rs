//! Generates real launchers with the shipped launcher executable and opens an
//! inert test app through LaunchServices, which only records what it received.
#![cfg(target_os = "macos")]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use proxy_ui_services::app_proxies::{AppProxies, Entry, Mode, Paths};

fn target_app(root: &Path, marker: &Path) -> PathBuf {
    // Shell syntax and non-ASCII in the path must reach the app intact.
    let app = root.join("测试 App '$;.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    let mut info = plist::Dictionary::new();
    for (key, value) in [
        (
            "CFBundleIdentifier",
            format!("test.cipherrelay.{}", std::process::id()),
        ),
        ("CFBundleExecutable", "Target".into()),
        ("CFBundleName", "Test App".into()),
        ("CFBundlePackageType", "APPL".into()),
    ] {
        info.insert(key.into(), plist::Value::String(value));
    }
    info.insert("LSUIElement".into(), plist::Value::Boolean(true));
    plist::Value::Dictionary(info)
        .to_file_xml(app.join("Contents/Info.plist"))
        .unwrap();
    let executable = app.join("Contents/MacOS/Target");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$HTTP_PROXY\" \"$NO_PROXY\" \"$@\" > '{}'\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    app.canonicalize().unwrap()
}

fn settings(path: &Path) -> Vec<u8> {
    std::fs::read(path.join("Contents/Resources/launcher.json")).unwrap()
}

#[test]
fn launchers_launch_with_their_settings_and_keep_their_path_across_edits() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let marker = root.join("received.txt");
    let app = target_app(&root, &marker);
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    let mut service = AppProxies::new(
        Paths {
            state: root.join("state"),
            claude_library: root.join("claude"),
            launchers: root.join("Launchers"),
            launcher_executable: PathBuf::from(env!("CARGO_BIN_EXE_cipherrelay-app-launcher")),
        },
        runtime.handle().clone(),
    );
    let entry = Entry {
        id: None,
        name: "Test Launcher".into(),
        app_path: app.to_string_lossy().into_owned(),
        mode: Mode::Chromium,
        port,
        bypass_rules: vec!["*OA*".into(), ".oa.com".into(), ".woa.com".into()],
        application_id: None,
        launcher_path: None,
        warning: None,
    };
    let first = service.save(entry.clone()).unwrap();
    assert_eq!(first.bypass_rules, ["*oa*", ".oa.com", ".woa.com"]);
    let bundle = PathBuf::from(first.launcher_path.clone().unwrap());
    let launcher = bundle.join("Contents/MacOS/ProxyLauncher");

    let check = Command::new(&launcher).arg("--check").output().unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(report["proxyListening"], true);
    assert_eq!(report["running"], serde_json::json!([]));

    assert!(Command::new(&launcher).status().unwrap().success());
    let started = Instant::now();
    while !marker.exists() && started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let received = std::fs::read_to_string(&marker).unwrap();
    assert!(
        received.contains(&format!("http://127.0.0.1:{port}")),
        "{received}"
    );
    assert!(
        received.contains("localhost,127.0.0.1,::1,.oa.com,.woa.com"),
        "{received}"
    );
    assert!(
        received.contains("--proxy-bypass-list=localhost;127.0.0.1;[::1];*oa*;"),
        "{received}"
    );

    // A second launcher for the same app keeps its own rules.
    let second = service
        .save(Entry {
            bypass_rules: vec![".internal.example".into()],
            ..entry.clone()
        })
        .unwrap();
    let edited = service
        .save(Entry {
            name: "Renamed".into(),
            bypass_rules: vec![],
            ..first.clone()
        })
        .unwrap();
    assert_eq!(
        edited.launcher_path, first.launcher_path,
        "edits keep Dock paths"
    );
    assert!(edited.bypass_rules.is_empty());
    let listed = service.list().unwrap();
    let independent = listed.iter().find(|item| item.id == second.id).unwrap();
    assert_eq!(independent.bypass_rules, [".internal.example"]);

    let before = settings(&bundle);
    let invalid = Entry {
        bypass_rules: vec!["host;--proxy-server=evil".into()],
        ..edited.clone()
    };
    assert!(service.save(invalid).is_err());
    let moved = Entry {
        app_path: root.join("Missing.app").to_string_lossy().into_owned(),
        ..edited
    };
    assert!(service.save(moved).is_err());
    assert_eq!(settings(&bundle), before, "failed edits keep the launcher");
    let signature = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&bundle)
        .status()
        .unwrap();
    assert!(signature.success());
}
