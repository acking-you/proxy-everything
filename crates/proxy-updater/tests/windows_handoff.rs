#![cfg(windows)]
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ring::digest;
use serde_json::{Value, json};

fn compile(output: &Path, source: &str) {
    let input = output.with_extension("cs");
    fs::write(&input, source).unwrap();
    let compiler = Path::new(&std::env::var_os("SystemRoot").unwrap())
        .join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
    let result = Command::new(compiler)
        .arg("/nologo")
        .arg(format!("/out:{}", output.display()))
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}

fn fixtures() -> &'static tempfile::TempDir {
    static FIXTURES: OnceLock<tempfile::TempDir> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let directory = tempfile::tempdir().unwrap();
        compile(&directory.path().join("old.exe"), r#"
using System; using System.Reflection;
[assembly: AssemblyInformationalVersion("1.0.0+1")]
class App { static void Main() { Console.ReadLine(); } }"#);
        compile(&directory.path().join("new.exe"), r#"
using System; using System.Reflection;
[assembly: AssemblyInformationalVersion("9.9.9+9999")]
class App { static void Main() {} }"#);
        compile(&directory.path().join("installer.exe"), r#"
using System; using System.IO;
class Installer {
  static int Main(string[] args) {
    string work = AppDomain.CurrentDomain.BaseDirectory;
    string dir = null;
    foreach(string arg in args) {
      if(arg.StartsWith("/DIR=")) dir = arg.Substring(5);
      if(arg.StartsWith("/LOG=")) File.WriteAllText(arg.Substring(5), "installer ran");
    }
    string mode = File.ReadAllText(Path.Combine(work, "mode"));
    if(mode == "fail") return 23;
    if(mode != "noop") File.Copy(Path.Combine(work, "new.exe"), Path.Combine(dir, "CipherRelay.exe"), true);
    return 0;
  }
}"#);
        directory
    })
}

struct Parent(Child);
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn status(work: &Path, expected: &[&str]) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(bytes) = fs::read(work.join("install-status.json")) {
            let state: Value = serde_json::from_slice(&bytes).unwrap();
            if expected.contains(&state["stage"].as_str().unwrap()) {
                return state;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for {expected:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn scenario(mode: &str) {
    let directory = tempfile::Builder::new()
        .prefix("update 空格 & $ ")
        .tempdir()
        .unwrap();
    let work = directory.path();
    let install_dir = work.join("installed app");
    fs::create_dir(&install_dir).unwrap();
    let app = install_dir.join("CipherRelay.exe");
    let installer = work.join("setup.exe");
    fs::copy(fixtures().path().join("old.exe"), &app).unwrap();
    fs::copy(fixtures().path().join("new.exe"), work.join("new.exe")).unwrap();
    fs::copy(fixtures().path().join("installer.exe"), &installer).unwrap();
    fs::write(work.join("mode"), mode).unwrap();
    let bytes = fs::read(&installer).unwrap();
    let hash = digest::digest(&digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut parent = Parent(Command::new(&app).stdin(Stdio::piped()).spawn().unwrap());
    let request = work.join("install-request.json");
    fs::write(
        &request,
        serde_json::to_vec(&json!({
            "processId": parent.0.id(), "installer": installer, "app": app,
            "version": "9.9.9+9999", "sha256": if mode == "hash" { "0".repeat(64) } else { hash },
            "size": bytes.len(), "elevate": false, "reopen": false, "showErrors": false,
            "exitTimeoutSeconds": 10
        }))
        .unwrap(),
    )
    .unwrap();
    // This process exits after readiness. Its worker must survive that exit.
    let prepared = Command::new(env!("CARGO_BIN_EXE_cipherrelay-updater"))
        .arg("--prepare")
        .arg(&request)
        .status()
        .unwrap();
    if mode == "hash" {
        assert!(!prepared.success());
        assert!(installer.exists());
        assert!(!work.join("installer.log").exists());
        assert!(parent.0.try_wait().unwrap().is_none());
        return;
    }
    assert!(prepared.success(), "{}", status(work, &["failed"]));
    assert_eq!(status(work, &["ready"])["stage"], "ready");
    assert!(
        !work.join("installer.log").exists(),
        "Must wait for application exit"
    );
    if mode == "cancel" {
        fs::write(work.join("cancel"), b"cancel").unwrap();
    }
    parent.0.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    parent.0.wait().unwrap();
    let state = status(work, &["complete", "failed", "cancelled"]);
    match mode {
        "success" => {
            assert_eq!(state["stage"], "complete", "{state}");
            let deadline = Instant::now() + Duration::from_secs(5);
            while installer.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!installer.exists());
            assert_eq!(
                fs::read(&app).unwrap(),
                fs::read(work.join("new.exe")).unwrap()
            );
        }
        "cancel" => {
            assert_eq!(state["stage"], "cancelled", "{state}");
            assert!(!work.join("installer.log").exists());
            assert!(installer.exists());
        }
        _ => {
            assert_eq!(state["stage"], "failed", "{state}");
            assert!(installer.exists());
            assert!(work.join("installer.log").exists());
            if mode == "noop" {
                assert!(
                    state["message"]
                        .as_str()
                        .unwrap()
                        .contains("installed version")
                );
            }
        }
    }
}

#[test]
fn detached_worker_waits_for_exit_and_verifies_the_installed_version() {
    scenario("success");
}
#[test]
fn installer_errors_preserve_package_and_logs() {
    scenario("fail");
}
#[test]
fn installer_success_without_replacement_is_a_failure() {
    scenario("noop");
}
#[test]
fn cancelled_shutdown_does_not_install_later() {
    scenario("cancel");
}
#[test]
fn changed_package_is_rejected_before_application_shutdown() {
    scenario("hash");
}
