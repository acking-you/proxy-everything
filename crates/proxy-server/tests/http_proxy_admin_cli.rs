use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const DEFAULT_KEY: &str = "my-secret-key123my-secret-key123";
const CONTROL_KEY: &str = "control-session-key-32-bytes!!!!";
const ADMIN_TOKEN: &str = "admin-token-for-tests";

struct TestServer {
    child: Child,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unique_temp_home(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("proxy-everything-{name}-{suffix}"));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn start_server(extra_envs: &[(&str, &str)]) -> (TestServer, u16) {
    let server_bin = std::env::var_os("CARGO_BIN_EXE_http-proxy-server")
        .expect("http-proxy-server test binary path");
    let port = reserve_port();
    let home = unique_temp_home("admin-cli");
    let mut command = Command::new(server_bin);
    command
        .arg("-H")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .env("HOME", &home)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in extra_envs {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn server");
    wait_for_port(port);
    (TestServer { child }, port)
}

fn wait_for_port(port: u16) {
    for _ in 0..40 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not start on port {port}");
}

fn admin_json(port: u16, args: &[&str], envs: &[(&str, &str)]) -> (bool, Value, String, String) {
    let admin_bin =
        std::env::var_os("CARGO_BIN_EXE_http-proxy-admin").expect("http-proxy-admin binary path");
    let mut command = Command::new(admin_bin);
    command
        .arg("-H")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string());
    for (key, value) in envs {
        command.env(key, value);
    }
    for arg in args {
        command.arg(arg);
    }
    let output = command.output().expect("run http-proxy-admin");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    let json = serde_json::from_str::<Value>(&stdout).expect("stdout json");
    (output.status.success(), json, stdout, stderr)
}

fn expect_ok_type(json: &Value, expected_type: &str) {
    assert_eq!(json["ok"], Value::Bool(true), "unexpected response: {json}");
    assert_eq!(
        json["result"]["type"],
        Value::String(expected_type.to_string()),
        "unexpected response: {json}"
    );
}

fn expect_error_contains(json: &Value, needle: &str) {
    assert_eq!(
        json["ok"],
        Value::Bool(false),
        "unexpected response: {json}"
    );
    let error = json["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(needle),
        "expected error containing {needle:?}, got {error:?}"
    );
}

#[test]
fn admin_cli_supports_nodes_groups_and_relay_management() {
    let (_server, port) = start_server(&[]);

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "ping"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "pong");

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "nodes", "list"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "nodes");

    let node_addr = "192.168.1.100:1081";
    let (ok, json, _, stderr) =
        admin_json(port, &["-k", DEFAULT_KEY, "nodes", "add", node_addr], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "nodes", "list"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "nodes");
    let nodes = json["result"]["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|node| node["addr"] == node_addr));

    let group_id = "test-group";
    let group_name = "Test Group";
    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "groups",
            "create",
            "--id",
            group_id,
            "--name",
            group_name,
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "groups",
            "add-node",
            "--group-id",
            group_id,
            "--node-id",
            node_addr,
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "groups", "list"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "groups");
    let groups = json["result"]["groups"].as_array().unwrap();
    let group = groups
        .iter()
        .find(|item| item["group_id"] == group_id)
        .expect("group exists");
    assert_eq!(group["name"], group_name);
    assert!(
        group["node_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == node_addr)
    );

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "relay",
            "add-target",
            "--group-id",
            group_id,
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "relay",
            "add-target",
            "--addr",
            "10.0.0.200:1081",
            "--weight",
            "2",
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "relay", "get"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "relay_config");
    assert_eq!(json["result"]["config"]["enabled"], Value::Bool(false));
    let targets = json["result"]["config"]["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "relay", "enable"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &["-k", DEFAULT_KEY, "relay", "set-algo", "--algo", "weighted"],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "relay", "status"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "relay_status");
    assert_eq!(json["result"]["status"]["enabled"], Value::Bool(true));
    assert_eq!(
        json["result"]["status"]["algo"],
        Value::String("weighted".to_string())
    );

    let (ok, json, _, stderr) = admin_json(
        port,
        &["-k", DEFAULT_KEY, "relay", "remove-target", "--index", "0"],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "groups",
            "remove-node",
            "--group-id",
            group_id,
            "--node-id",
            node_addr,
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &["-k", DEFAULT_KEY, "groups", "delete", "--id", group_id],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");

    let (ok, json, _, stderr) = admin_json(
        port,
        &["-k", DEFAULT_KEY, "nodes", "remove", node_addr],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "ack");
}

#[test]
fn admin_cli_honors_admin_token_and_session_key_env() {
    let (_server, port) = start_server(&[
        ("CONTROL_ADMIN_TOKEN", ADMIN_TOKEN),
        ("CONTROL_SESSION_KEY", CONTROL_KEY),
    ]);

    let (ok, json, _, _) = admin_json(port, &["ping"], &[("CONTROL_SESSION_KEY", CONTROL_KEY)]);
    assert!(!ok);
    expect_error_contains(&json, "unauthorized");

    let (ok, json, _, _) = admin_json(
        port,
        &["--token", "wrong-token", "ping"],
        &[("CONTROL_SESSION_KEY", CONTROL_KEY)],
    );
    assert!(!ok);
    expect_error_contains(&json, "unauthorized");

    let (ok, json, _, stderr) = admin_json(
        port,
        &["--token", ADMIN_TOKEN, "ping"],
        &[("CONTROL_SESSION_KEY", CONTROL_KEY)],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "pong");
}

#[test]
fn admin_cli_supports_metrics_queries() {
    let (_server, port) = start_server(&[]);

    let (ok, json, _, stderr) = admin_json(port, &["-k", DEFAULT_KEY, "metrics", "realtime"], &[]);
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "realtime_stats");

    let (ok, json, _, stderr) = admin_json(
        port,
        &["-k", DEFAULT_KEY, "metrics", "connections", "--limit", "10"],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "connections");
    assert!(json["result"]["connections"].is_array());

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "metrics",
            "buckets",
            "--granularity",
            "minute",
            "--count",
            "5",
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "time_buckets");
    assert!(json["result"]["buckets"].is_array());

    let (ok, json, _, stderr) = admin_json(
        port,
        &[
            "-k",
            DEFAULT_KEY,
            "metrics",
            "top-n",
            "--category",
            "hosts",
            "--limit",
            "10",
        ],
        &[],
    );
    assert!(ok, "{stderr}");
    expect_ok_type(&json, "top_n");
    assert!(json["result"]["entries"].is_array());
}
