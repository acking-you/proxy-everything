//! Privileged TUN helper for macOS.
//!
//! macOS requires root to create a utun device and to install the capture
//! routes, and it offers no way to make an already-running GUI privileged.
//! `osascript` starts this helper with administrator rights instead, and it
//! runs the whole TUN session on behalf of the unprivileged application: it
//! creates the device, installs the routes, and forwards captured traffic into
//! the local SOCKS5 listener that the application keeps serving.
//!
//! Everything travels over the single Unix socket named on the command line.
//! The configuration arrives on it (keeping the proxy endpoint out of the
//! world-readable `ps` output), readiness and teardown are reported back on it,
//! and its EOF is how this helper learns that the application exited: an
//! unprivileged process cannot signal a root one, so shutdown is cooperative
//! and losing the peer has to trigger route restoration by itself. Without that
//! last part a crashed application would leave the machine with a default route
//! pointing at a tunnel that no longer exists.

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "http-proxy-tun-helper is only used on macOS, where creating a utun device requires root. \
         On this platform run the client itself with the privileges its TUN mode needs."
    );
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    match macos::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("http-proxy-tun-helper failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::path::PathBuf;

    use proxy_client::client::macos_tun::{HelperConfig, HelperEvent, HelperRequest};
    use proxy_client::client::tun::{TunConfig, TunVirtualDnsState, run_with_ready};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::net::unix::OwnedWriteHalf;
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;

    /// Subdirectory for this helper's fake-IP mappings.
    ///
    /// The application persists its own mappings in the cache directory root.
    /// Two processes appending to one journal would interleave their records, so
    /// the helper keeps a separate file. Only the helper resolves names while
    /// macOS TUN is active, so the application's copy simply stays idle.
    const HELPER_STATE_SUBDIR: &str = "tun-helper";

    pub fn run() -> io::Result<()> {
        let socket_path = std::env::args_os().nth(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: http-proxy-tun-helper <control-socket-path>",
            )
        })?;

        // SAFETY: `geteuid` reads the calling process's effective user ID and
        // cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "http-proxy-tun-helper must run as root; it is started through an administrator \
                 authorization prompt rather than directly",
            ));
        }

        // This process terminates every captured flow on the device, so it is
        // the most descriptor-hungry part of TUN mode. It uses the `log` facade
        // rather than `init_tracing`, so the limit is raised explicitly here.
        if let Some(limit) = proxy_core::rlimit::raise_file_descriptor_limit() {
            log::info!(
                "open file descriptor limit: {} (was {}, hard {})",
                limit.current_soft,
                limit.previous_soft,
                limit.hard
            );
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(serve(PathBuf::from(socket_path)))
    }

    async fn serve(socket_path: PathBuf) -> io::Result<()> {
        let stream = UnixStream::connect(&socket_path).await.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not connect to the control socket {}: {error}",
                    socket_path.display()
                ),
            )
        })?;
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let writer = std::sync::Arc::new(Mutex::new(writer));

        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the control socket closed before the TUN configuration arrived",
            ));
        }
        let config: HelperConfig = serde_json::from_str(line.trim()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not decode the TUN configuration: {error}"),
            )
        })?;

        let shutdown_token = CancellationToken::new();
        install_signal_handlers(shutdown_token.clone());

        // A stop request and a closed socket mean the same thing here: the peer
        // no longer wants the tunnel, and the routes must be restored.
        let socket_token = shutdown_token.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        log::info!("the control socket closed; restoring network settings");
                        break;
                    }
                    Ok(_) => {
                        if matches!(
                            serde_json::from_str::<HelperRequest>(line.trim()),
                            Ok(HelperRequest::Stop)
                        ) {
                            log::info!("received a stop request; restoring network settings");
                            break;
                        }
                    }
                    Err(error) => {
                        log::warn!("the control socket failed: {error}");
                        break;
                    }
                }
            }
            socket_token.cancel();
        });

        let tun_config = build_tun_config(&config).await?;
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        // Forward readiness as soon as it is known so the application can settle
        // its UI without waiting for the whole session to finish.
        let ready_writer = std::sync::Arc::clone(&writer);
        tokio::spawn(async move {
            let event = match ready_receiver.await {
                Ok(Ok(())) => HelperEvent::Ready,
                Ok(Err(message)) => HelperEvent::Failed { message },
                Err(_) => HelperEvent::Failed {
                    message: "the TUN session ended without reporting readiness".to_string(),
                },
            };
            send_event(&ready_writer, event).await;
        });

        let result = run_with_ready(
            config.local_port,
            tun_config,
            shutdown_token.clone(),
            Some(ready_sender),
        )
        .await;

        match &result {
            Ok(sessions) => log::info!("TUN forwarding stopped with {sessions} sessions remaining"),
            Err(error) => log::error!("TUN forwarding failed: {error}"),
        }

        // Routes and DNS are already restored by the time `run_with_ready`
        // returns, so this tells the application it is safe to start again.
        send_event(&writer, HelperEvent::Stopped).await;
        if let Ok(mut writer) = writer.try_lock() {
            let _ = writer.shutdown().await;
        }
        result.map(|_| ())
    }

    async fn build_tun_config(config: &HelperConfig) -> io::Result<TunConfig> {
        let virtual_dns = TunVirtualDnsState::default();
        if let Some(cache_dir) = &config.cache_dir {
            let directory = PathBuf::from(cache_dir).join(HELPER_STATE_SUBDIR);
            match std::fs::create_dir_all(&directory) {
                Ok(()) => {
                    if let Err(error) = virtual_dns.enable_persistence_in(&directory).await {
                        log::warn!(
                            "fake-IP mappings will not survive a restart ({}): {error}",
                            directory.display()
                        );
                    }
                }
                Err(error) => log::warn!(
                    "could not create the helper state directory {}: {error}",
                    directory.display()
                ),
            }
        }

        // The application already enforces its own executable in the bypass
        // list, but process matching is not built for macOS at all, so the
        // helper relies purely on the route-level bypass below.
        let mut tun_config = TunConfig::new(Vec::<String>::new())?
            .with_udp_enabled(config.udp_enabled)
            .with_udp_direct_fallback(config.udp_direct_fallback)
            .with_ipv6_enabled(config.ipv6_enabled)
            .with_mtu(config.mtu)
            .with_virtual_dns_state(virtual_dns);
        if let (Some(host), Some(port)) = (&config.remote_host, config.remote_port) {
            tun_config = tun_config.with_remote_endpoint(host.clone(), port);
        }
        Ok(tun_config)
    }

    async fn send_event(writer: &std::sync::Arc<Mutex<OwnedWriteHalf>>, event: HelperEvent) {
        let mut encoded = match serde_json::to_vec(&event) {
            Ok(encoded) => encoded,
            Err(error) => {
                log::warn!("could not encode a control event: {error}");
                return;
            }
        };
        encoded.push(b'\n');
        let mut writer = writer.lock().await;
        if let Err(error) = writer.write_all(&encoded).await {
            // The application may already be gone; teardown continues anyway.
            log::debug!("could not send a control event: {error}");
            return;
        }
        let _ = writer.flush().await;
    }

    /// Cancel on termination signals so route restoration still runs.
    fn install_signal_handlers(shutdown_token: CancellationToken) {
        use tokio::signal::unix::{SignalKind, signal};

        for kind in [
            SignalKind::terminate(),
            SignalKind::interrupt(),
            SignalKind::hangup(),
        ] {
            let token = shutdown_token.clone();
            match signal(kind) {
                Ok(mut stream) => {
                    tokio::spawn(async move {
                        stream.recv().await;
                        log::info!("received a termination signal; restoring network settings");
                        token.cancel();
                    });
                }
                Err(error) => log::warn!("could not install a signal handler: {error}"),
            }
        }
    }
}
