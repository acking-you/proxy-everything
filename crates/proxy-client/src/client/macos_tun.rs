//! Privileged TUN setup for macOS through an administrator-authorized helper.
//!
//! Creating a utun device on macOS requires root: `connect` on the
//! `PF_SYSTEM`/`UTUN_CONTROL_NAME` control socket fails with `EPERM` for an
//! unprivileged process, before any route change is attempted. Installing the
//! capture routes and DNS settings afterwards needs root as well. Windows can
//! relaunch its own GUI through UAC, but macOS has no equivalent for making an
//! already-running application privileged, so the work moves into a separate
//! helper that `osascript` starts with administrator rights.
//!
//! The helper owns the whole TUN session: it creates the device, installs the
//! routes, and runs the forwarding loop into the local SOCKS5 listener that
//! this (unprivileged) process keeps serving. A single Unix socket carries the
//! configuration, the readiness result, and the stop request. That last part is
//! what makes the socket necessary rather than convenient: an unprivileged
//! process cannot signal a root one, so shutdown must be cooperative, and the
//! socket reaching EOF is also how the helper learns that this process died and
//! that it has to restore the routes on its own.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use super::tun::TunConfig;

/// Executable name of the privileged helper, staged next to the current one.
pub const HELPER_BINARY_NAME: &str = "http-proxy-tun-helper";

/// How long to wait for the helper to connect back after `osascript` returns.
///
/// `osascript` returns as soon as the authorization dialog is dismissed, so the
/// remaining wait only covers process startup. A cancelled dialog never
/// connects, and this bound is what turns that into a reportable error.
const HELPER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Settings handed to the helper over the socket rather than on its command
/// line: `ps` output is world-readable on macOS, and this keeps the proxy
/// endpoint and port out of it.
#[derive(Debug, Serialize, Deserialize)]
pub struct HelperConfig {
    /// Local SOCKS5 port the helper forwards captured traffic into.
    pub local_port: u16,
    /// Remote proxy endpoint that must stay outside the TUN.
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub mtu: u16,
    pub ipv6_enabled: bool,
    pub udp_enabled: bool,
    pub udp_direct_fallback: bool,
    #[serde(default)]
    pub fake_ip: bool,
    /// Directory for the helper's own virtual-DNS persistence.
    pub cache_dir: Option<String>,
    /// Process names whose traffic bypasses the proxy, already normalized and
    /// including the application's own executable.
    ///
    /// Defaulted so a helper from an older build still decodes a configuration
    /// that omits it, and vice versa.
    #[serde(default)]
    pub bypass_processes: Vec<String>,
}

/// Messages the helper sends back over the socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HelperEvent {
    /// The device exists and the system routes are installed.
    Ready,
    /// Setup failed; the helper exits after sending this.
    Failed { message: String },
    /// Routes and DNS have been restored.
    Stopped,
    /// Bounded diagnostic records from the process that owns packet forwarding.
    Log {
        level: HelperLogLevel,
        target: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperLogLevel {
    Error,
    Warn,
    Info,
}

fn forward_helper_log(level: HelperLogLevel, target: &str, message: &str) {
    match level {
        HelperLogLevel::Error => tracing::error!(helper_target = target, "{message}"),
        HelperLogLevel::Warn => tracing::warn!(helper_target = target, "{message}"),
        HelperLogLevel::Info => tracing::info!(helper_target = target, "{message}"),
    }
}

/// Requests this process sends to the helper.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Tear down the TUN session and restore the previous network settings.
    Stop,
    /// Replace the process bypass list of the running session.
    ///
    /// The device and system routes stay in place; only the routing decision for
    /// new sessions changes, and established sessions whose decision flips are
    /// closed so the application reconnects on the newly selected path.
    SetBypassProcesses { names: Vec<String> },
}

/// Whether this process can create a utun device without the helper.
pub fn is_root() -> bool {
    // SAFETY: `geteuid` reads the calling process's effective user ID and
    // cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Locate the helper staged alongside the current executable.
///
/// Inside a `.app` this resolves to `Contents/MacOS/`, which is where both the
/// build script and the Xcode embed phase place it. A missing helper is by far
/// the most likely packaging mistake, so the error names the expected path.
pub fn helper_path() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "current executable has no parent directory: {}",
                executable.display()
            ),
        )
    })?;
    let helper = directory.join(HELPER_BINARY_NAME);
    if !helper.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "the privileged TUN helper is missing from this installation; expected it at {}",
                helper.display()
            ),
        ));
    }
    Ok(helper)
}

/// Bind the control socket inside a private directory.
///
/// `sun_path` holds only about 104 bytes on macOS, which rules out the
/// application-support directory and `$TMPDIR` (a long per-user path). `/tmp`
/// is shared, so the directory is created with mode 0700 and a unique name: the
/// helper runs as root and would otherwise be reachable through a socket any
/// local user could have pre-created.
fn bind_control_socket() -> io::Result<(UnixListener, PathBuf, PathBuf)> {
    let unique = format!(
        "proxy-tun-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    );
    let directory = Path::new("/tmp").join(unique);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not create the TUN helper control directory {}: {error}",
                    directory.display()
                ),
            )
        })?;
    let socket_path = directory.join("control.sock");
    match UnixListener::bind(&socket_path) {
        Ok(listener) => Ok((listener, socket_path, directory)),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&directory);
            Err(io::Error::new(
                error.kind(),
                format!(
                    "could not bind the TUN helper control socket {}: {error}",
                    socket_path.display()
                ),
            ))
        }
    }
}

/// Quote a path for `/bin/sh`, which `do shell script` runs the command with.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Escape a shell command for embedding in an AppleScript string literal.
///
/// Both layers are required: the command first becomes an AppleScript string,
/// which `do shell script` then hands to `/bin/sh`.
fn applescript_quote(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

/// Ask for administrator rights and start the helper in the background.
///
/// `do shell script` waits for the command to finish, so the helper is
/// detached; it reports its real status over the socket rather than through an
/// exit code. Output is redirected because `do shell script` would otherwise
/// hold the pipes open and keep waiting.
async fn spawn_privileged_helper(helper: &Path, socket_path: &Path) -> io::Result<()> {
    let command = format!(
        "{} {} >/dev/null 2>&1 &",
        shell_quote(&helper.to_string_lossy()),
        shell_quote(&socket_path.to_string_lossy())
    );
    let script = format!(
        "do shell script \"({})\" with administrator privileges",
        applescript_quote(&command)
    );
    tracing::info!(
        helper = %helper.display(),
        "requesting administrator privileges to start the macOS TUN helper"
    );
    let output = tokio::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .await
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not run osascript to request administrator privileges: {error}"),
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    // -128 is AppleScript's "user cancelled". Report it as its own kind so the
    // UI can distinguish a declined prompt from a genuine failure.
    if detail.contains("-128") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator authorization was cancelled, so TUN mode was not started",
        ));
    }
    Err(io::Error::other(format!(
        "could not start the privileged TUN helper: {}",
        if detail.is_empty() {
            "osascript reported no detail".to_string()
        } else {
            detail
        }
    )))
}

/// Remove the socket and its private directory.
fn cleanup_control_socket(directory: &Path) {
    if let Err(error) = std::fs::remove_dir_all(directory) {
        // Losing a /tmp directory is not worth failing a teardown over; the
        // name is unique so a leftover cannot collide with a later run.
        tracing::debug!(
            %error,
            directory = %directory.display(),
            "could not remove the TUN helper control directory"
        );
    }
}

/// Run a TUN session through the privileged helper.
///
/// The signature matches [`super::tun::run_with_ready`] so both can be used
/// interchangeably as the runner behind the FFI entry point. The returned
/// session count is always zero: the sessions belong to the helper process.
pub async fn run_with_privileged_helper(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    mut ready: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    let result = start_helper_session(local_port, config, shutdown_token, &mut ready).await;
    // Every failure before readiness has to answer the channel, or the caller
    // waits out its whole timeout and then blames the wrong thing.
    if let Err(error) = &result
        && let Some(ready) = ready.take()
    {
        let _ = ready.send(Err(error.to_string()));
    }
    result
}

async fn start_helper_session(
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    // Fail before the administrator prompt or any DNS restore/setup when an
    // existing VPN owns capture routes. The helper repeats this check to cover
    // changes that race authorization.
    tun2proxy::validate_macos_capture_routes()?;
    let helper = helper_path()?;
    let (listener, socket_path, directory) = bind_control_socket()?;
    let result = run_helper_session(
        &helper,
        &socket_path,
        listener,
        local_port,
        config,
        shutdown_token,
        ready,
    )
    .await;
    cleanup_control_socket(&directory);
    result
}

async fn run_helper_session(
    helper: &Path,
    socket_path: &Path,
    listener: UnixListener,
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    spawn_privileged_helper(helper, socket_path).await?;

    let stream = tokio::select! {
        accepted = listener.accept() => accepted?.0,
        _ = tokio::time::sleep(HELPER_CONNECT_TIMEOUT) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the privileged TUN helper did not start within the authorization window",
            ));
        }
        _ = shutdown_token.cancelled() => {
            return Err(io::Error::other(
                "TUN startup was cancelled before the privileged helper connected",
            ));
        }
    };

    drive_helper_session(stream, local_port, config, shutdown_token, ready).await
}

/// Exchange configuration, readiness, and teardown with a connected helper.
async fn drive_helper_session(
    stream: tokio::net::UnixStream,
    local_port: u16,
    config: TunConfig,
    shutdown_token: CancellationToken,
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<usize> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Runtime policy updates originate on whichever thread calls the FFI, while
    // the write half is owned by the loop below. An unbounded channel bridges
    // them: updates are small, rare, and must not block a UI thread.
    //
    // Attach before reading the list for the handoff, so an update arriving in
    // between is either captured by the read below or queued here.
    let (updates_tx, mut updates_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<String>>();
    config.bypass.attach_sink(std::sync::Arc::new(move |names| {
        // A closed channel means the session already ended; the helper is gone
        // and the next session sends a fresh list in its configuration.
        if updates_tx.send(names).is_err() {
            tracing::debug!("the TUN helper session ended before a bypass update was delivered");
        }
    }));

    let helper_config = HelperConfig {
        local_port,
        remote_host: config
            .remote_endpoint
            .as_ref()
            .map(|(host, _)| host.clone()),
        remote_port: config.remote_endpoint.as_ref().map(|(_, port)| *port),
        mtu: config.mtu,
        ipv6_enabled: config.ipv6_enabled,
        udp_enabled: config.udp_enabled,
        udp_direct_fallback: config.udp_direct_fallback,
        fake_ip: config.fake_ip,
        cache_dir: config
            .cache_dir
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        bypass_processes: config.bypass.effective_processes(),
    };
    let mut encoded = serde_json::to_vec(&helper_config).map_err(io::Error::other)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;

    // Readiness has to arrive before the caller is told TUN is active: the
    // helper only reports success once the device exists and the routes are in
    // place, matching what the in-process path guarantees.
    let mut line = String::new();
    let mut stop_requested = false;
    loop {
        line.clear();
        let read = tokio::select! {
            read = reader.read_line(&mut line) => read?,
            Some(names) = updates_rx.recv() => {
                send_bypass_update(&mut writer, names).await;
                continue;
            }
            _ = shutdown_token.cancelled() => {
                request_helper_stop(&mut writer).await;
                stop_requested = true;
                break;
            }
        };
        if read == 0 {
            // The helper exited without reporting readiness, so it never got
            // far enough to change any network settings.
            if ready.is_some() {
                return Err(io::Error::other(
                    "the privileged TUN helper exited before reporting readiness",
                ));
            }
            tracing::warn!(
                "the privileged TUN helper exited without acknowledging the stop request"
            );
            break;
        }

        match serde_json::from_str::<HelperEvent>(line.trim()) {
            Ok(HelperEvent::Log {
                level,
                target,
                message,
            }) => forward_helper_log(level, &target, &message),
            Ok(HelperEvent::Ready) => {
                tracing::info!("the privileged TUN helper reported adapter and route readiness");
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Ok(()));
                }
            }
            Ok(HelperEvent::Failed { message }) => {
                return Err(io::Error::other(message));
            }
            Ok(HelperEvent::Stopped) => {
                tracing::info!("the privileged TUN helper restored the previous network settings");
                break;
            }
            Err(error) => {
                tracing::warn!(%error, line = %line.trim(), "ignoring an unrecognized TUN helper message");
            }
        }
    }

    // Wait for the helper to confirm teardown so route restoration is complete
    // before the caller may start another TUN session.
    if stop_requested {
        await_helper_teardown(&mut reader, &mut line).await;
    }

    // Cancellation can win the race above before a pending `Ready` is read. The
    // caller is still waiting on the readiness channel, and dropping it would
    // surface as "ended without reporting readiness" rather than the stop that
    // actually happened, so answer it explicitly.
    if let Some(ready) = ready.take() {
        let _ = ready.send(Err("TUN startup was cancelled before the privileged \
                                helper reported readiness"
            .to_string()));
    }
    Ok(0)
}

/// Push a new bypass list to the running helper.
///
/// A delivery failure is not fatal: the routes and the device are unaffected, so
/// the session keeps running under the policy the helper already has.
async fn send_bypass_update(writer: &mut tokio::net::unix::OwnedWriteHalf, names: Vec<String>) {
    let request = HelperRequest::SetBypassProcesses {
        names: names.clone(),
    };
    let mut encoded = match serde_json::to_vec(&request) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::warn!(%error, "could not encode a TUN helper bypass update");
            return;
        }
    };
    encoded.push(b'\n');
    if let Err(error) = writer.write_all(&encoded).await {
        tracing::warn!(%error, "could not send a TUN helper bypass update");
        return;
    }
    let _ = writer.flush().await;
    tracing::info!(bypass_processes = ?names, "sent a bypass policy update to the TUN helper");
}

/// Ask the helper to tear down, ignoring a socket it has already closed.
async fn request_helper_stop(writer: &mut tokio::net::unix::OwnedWriteHalf) {
    let mut encoded = match serde_json::to_vec(&HelperRequest::Stop) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::warn!(%error, "could not encode the TUN helper stop request");
            return;
        }
    };
    encoded.push(b'\n');
    if let Err(error) = writer.write_all(&encoded).await {
        // A closed socket is itself the stop signal, so the helper is already
        // tearing down.
        tracing::debug!(%error, "the TUN helper socket was closed before the stop request");
        return;
    }
    let _ = writer.flush().await;
}

/// Drain the socket until the helper confirms teardown or closes it.
async fn await_helper_teardown(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    line: &mut String,
) {
    const TEARDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    let drain = async {
        loop {
            line.clear();
            match reader.read_line(line).await {
                Ok(0) => return,
                Ok(_) => match serde_json::from_str::<HelperEvent>(line.trim()) {
                    Ok(HelperEvent::Stopped) => return,
                    Ok(HelperEvent::Log {
                        level,
                        target,
                        message,
                    }) => forward_helper_log(level, &target, &message),
                    _ => {}
                },
                Err(error) => {
                    tracing::debug!(%error, "the TUN helper socket ended during teardown");
                    return;
                }
            }
        }
    };
    if tokio::time::timeout(TEARDOWN_TIMEOUT, drain).await.is_err() {
        tracing::warn!(
            "the privileged TUN helper did not confirm route restoration in time; system routes \
             may still point at the tunnel"
        );
    }
}

/// Report whether a TUN session started here needs the privileged helper.
pub fn requires_privileged_helper() -> bool {
    !is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quoting_survives_paths_with_quotes_and_spaces() {
        assert_eq!(shell_quote("/Users/a b/app"), "'/Users/a b/app'");
        assert_eq!(shell_quote("/tmp/it's"), r"'/tmp/it'\''s'");
    }

    #[test]
    fn applescript_quoting_escapes_backslashes_before_quotes() {
        // Escaping quotes first would leave the inserted backslash to be
        // doubled by the backslash pass, corrupting the literal.
        assert_eq!(applescript_quote(r#"a\b"c"#), r#"a\\b\"c"#);
    }

    // `UnixListener::bind` registers with the tokio reactor, so this needs a
    // runtime even though the assertions are about the filesystem.
    #[tokio::test]
    async fn control_socket_directory_is_private_to_this_user() {
        use std::os::unix::fs::PermissionsExt;

        let (listener, socket_path, directory) = bind_control_socket().unwrap();
        let mode = std::fs::metadata(&directory).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(socket_path.exists());
        drop(listener);
        cleanup_control_socket(&directory);
        assert!(!directory.exists());
    }

    /// Connected socket pair standing in for an authorized helper.
    async fn stub_helper_pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
        tokio::net::UnixStream::pair().unwrap()
    }

    fn test_config() -> TunConfig {
        TunConfig::new(Vec::<String>::new())
            .unwrap()
            .with_remote_endpoint("203.0.113.10", 1081)
            .with_mtu(1400)
    }

    #[tokio::test]
    async fn session_sends_configuration_then_reports_readiness() {
        let (ours, helper) = stub_helper_pair().await;
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let token = CancellationToken::new();

        let helper_task = tokio::spawn(async move {
            let (reader, mut writer) = helper.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let config: HelperConfig = serde_json::from_str(line.trim()).unwrap();

            writer
                .write_all(b"{\"event\":\"ready\"}\n{\"event\":\"stopped\"}\n")
                .await
                .unwrap();
            config
        });

        let mut ready = Some(ready_sender);
        let sessions = drive_helper_session(ours, 1080, test_config(), token, &mut ready)
            .await
            .unwrap();

        assert_eq!(sessions, 0);
        let config = helper_task.await.unwrap();
        assert_eq!(config.local_port, 1080);
        assert_eq!(config.remote_host.as_deref(), Some("203.0.113.10"));
        assert_eq!(config.remote_port, Some(1081));
        assert_eq!(config.mtu, 1400);
        // Readiness must reach the caller, not just be logged.
        assert!(matches!(ready_receiver.await, Ok(Ok(()))));
    }

    /// The whole reason the helper protocol carries a bypass update: on macOS the
    /// matcher lives in the helper, so changing the policy in this process has to
    /// travel over the socket to take effect.
    #[tokio::test]
    async fn bypass_updates_reach_the_helper_without_restarting_the_session() {
        let (ours, helper) = stub_helper_pair().await;
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let token = CancellationToken::new();
        let config = test_config();
        let bypass = config.bypass.clone();

        let helper_task = tokio::spawn(async move {
            let (reader, mut writer) = helper.into_split();
            let mut reader = BufReader::new(reader);

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let initial: HelperConfig = serde_json::from_str(line.trim()).unwrap();

            // Readiness first: an update only makes sense against a live session.
            writer.write_all(b"{\"event\":\"ready\"}\n").await.unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let update: HelperRequest = serde_json::from_str(line.trim()).unwrap();

            writer
                .write_all(b"{\"event\":\"stopped\"}\n")
                .await
                .unwrap();
            (initial, update)
        });

        let mut ready = Some(ready_sender);
        let session = tokio::spawn(async move {
            drive_helper_session(ours, 1080, config, token, &mut ready).await
        });

        // Only push the update once the helper has acknowledged readiness, so the
        // ordering under test is the real one.
        ready_receiver.await.unwrap().unwrap();
        bypass.set_user_processes(["Curl.EXE".to_string()]);

        let (initial, update) = helper_task.await.unwrap();
        session.await.unwrap().unwrap();

        let self_process = crate::client::tun::current_process_name().unwrap();
        assert!(
            initial.bypass_processes.contains(&self_process),
            "the handoff must already protect this process: {:?}",
            initial.bypass_processes
        );

        let HelperRequest::SetBypassProcesses { names } = update else {
            panic!("expected a bypass update, got {update:?}");
        };
        // Normalized on the way out, and the mandatory self entry survives a
        // caller that did not include it.
        assert!(names.contains(&"curl".to_string()), "got {names:?}");
        assert!(names.contains(&self_process), "got {names:?}");
    }

    #[tokio::test]
    async fn setup_failure_from_the_helper_becomes_the_session_error() {
        let (ours, helper) = stub_helper_pair().await;
        let (ready_sender, _ready_receiver) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (reader, mut writer) = helper.into_split();
            let mut line = String::new();
            BufReader::new(reader).read_line(&mut line).await.unwrap();
            writer
                .write_all(b"{\"event\":\"failed\",\"message\":\"route add failed\"}\n")
                .await
                .unwrap();
        });

        let mut ready = Some(ready_sender);
        let error = drive_helper_session(
            ours,
            1080,
            test_config(),
            CancellationToken::new(),
            &mut ready,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("route add failed"));
    }

    #[tokio::test]
    async fn a_helper_that_exits_before_readiness_is_reported_as_such() {
        let (ours, helper) = stub_helper_pair().await;
        let (ready_sender, _ready_receiver) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (reader, writer) = helper.into_split();
            let mut line = String::new();
            BufReader::new(reader).read_line(&mut line).await.unwrap();
            // Drop without reporting anything, as a helper killed during setup
            // would.
            drop(writer);
        });

        let mut ready = Some(ready_sender);
        let error = drive_helper_session(
            ours,
            1080,
            test_config(),
            CancellationToken::new(),
            &mut ready,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("before reporting readiness"));
    }

    #[tokio::test]
    async fn cancelling_asks_the_helper_to_restore_the_routes() {
        let (ours, helper) = stub_helper_pair().await;
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let token = CancellationToken::new();

        let helper_task = tokio::spawn(async move {
            let (reader, mut writer) = helper.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            writer.write_all(b"{\"event\":\"ready\"}\n").await.unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let request = line.trim().to_string();
            writer
                .write_all(b"{\"event\":\"stopped\"}\n")
                .await
                .unwrap();
            request
        });

        // Cancel only once readiness has actually been delivered, so this covers
        // teardown of a running session rather than racing a startup abort.
        let cancel_token = token.clone();
        let readiness = tokio::spawn(async move {
            let readiness = ready_receiver.await;
            cancel_token.cancel();
            readiness
        });

        let mut ready = Some(ready_sender);
        drive_helper_session(ours, 1080, test_config(), token, &mut ready)
            .await
            .unwrap();

        assert!(matches!(readiness.await.unwrap(), Ok(Ok(()))));
        assert_eq!(helper_task.await.unwrap(), r#"{"request":"stop"}"#);
    }

    #[test]
    fn helper_events_round_trip_over_the_wire_format() {
        let encoded = serde_json::to_string(&HelperEvent::Failed {
            message: "no route".to_string(),
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<HelperEvent>(&encoded).unwrap(),
            HelperEvent::Failed { message } if message == "no route"
        ));
        assert!(matches!(
            serde_json::from_str::<HelperEvent>(r#"{"event":"ready"}"#).unwrap(),
            HelperEvent::Ready
        ));
        assert!(matches!(
            serde_json::from_str::<HelperEvent>(r#"{"event":"log","level":"warn","target":"tun2proxy","message":"DNS unavailable"}"#).unwrap(),
            HelperEvent::Log { level: HelperLogLevel::Warn, message, .. } if message == "DNS unavailable"
        ));
    }
}
