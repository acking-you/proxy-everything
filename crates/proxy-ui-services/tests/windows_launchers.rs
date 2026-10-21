//! Generates real Shell shortcuts with the shipped launcher executable and
//! checks what a click would start, without starting anything.
#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::Command;

use proxy_ui_services::app_proxies::{AppProxies, Entry, Mode, Paths};

#[test]
fn shortcuts_run_their_own_settings_and_keep_their_path_across_edits() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_cipherrelay-app-launcher"));
    let target = root.join("App with spaces.exe");
    std::fs::copy(&helper, &target).unwrap();
    let mut service = AppProxies::new(
        Paths {
            state: root.join("state"),
            claude_library: root.join("claude"),
            launchers: root.join("Launchers"),
            launcher_executable: helper,
        },
        runtime.handle().clone(),
    );
    let entry = Entry {
        id: None,
        name: "CipherRelay test launcher".into(),
        app_path: target.to_string_lossy().into_owned(),
        mode: Mode::Chromium,
        port: 10801,
        bypass_rules: vec![".woa.com".into()],
        application_id: None,
        launcher_path: None,
        warning: None,
    };
    let first = service.save(entry.clone()).unwrap();
    let shortcut = PathBuf::from(first.launcher_path.clone().unwrap());
    assert!(shortcut.is_file());
    assert!(shortcut.extension().is_some_and(|ext| ext == "lnk"));
    let folder = shortcut.parent().unwrap();

    let check = Command::new(folder.join("CipherRelayLauncher.exe"))
        .arg("--config")
        .arg(folder.join("launcher.json"))
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(
        report["launchArguments"],
        serde_json::json!([
            "--proxy-server=http://127.0.0.1:10801",
            "--proxy-bypass-list=localhost;127.0.0.1;[::1];woa.com;*.woa.com"
        ])
    );
    assert_eq!(
        report["environment"]["NO_PROXY"],
        "localhost,127.0.0.1,::1,.woa.com"
    );

    let second = service
        .save(Entry {
            bypass_rules: vec![".example.test".into()],
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
        "edits keep shortcut paths"
    );
    let moved = Entry {
        app_path: r"C:\missing-test-app.exe".into(),
        ..edited
    };
    assert!(service.save(moved).is_err());
    let listed = service.list().unwrap();
    let find = |id: &Option<String>| listed.iter().find(|item| &item.id == id).unwrap();
    assert!(find(&first.id).bypass_rules.is_empty());
    assert_eq!(find(&second.id).bypass_rules, [".example.test"]);
}
