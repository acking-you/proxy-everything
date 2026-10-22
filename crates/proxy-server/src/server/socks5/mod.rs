//! A separately bound SOCKS5 endpoint managed through the encrypted control plane.

mod listener;

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use proxy_core::socks5::{Socks5Config, Socks5Status};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::ServerContext;

struct Running {
    listener: Arc<TcpListener>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

struct State {
    config: Socks5Config,
    running: Option<Running>,
    last_error: Option<String>,
}

impl State {
    fn status(&self) -> Socks5Status {
        Socks5Status {
            config: self.config.clone(),
            running: self.running.as_ref().is_some_and(|r| !r.task.is_finished()),
            last_error: self.last_error.clone(),
        }
    }
}

/// Owns the persisted settings and one listener generation. Mutations serialize
/// here; established connections use immutable authentication state without locks.
pub struct Socks5Manager {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

pub(super) enum Change {
    SetEnabled {
        enabled: bool,
        listen: Option<SocketAddr>,
    },
    RotateKey,
}

impl Socks5Manager {
    /// Create an isolated, disabled endpoint without writing to the user's profile.
    pub fn in_memory() -> io::Result<Self> {
        Ok(Self::new(None, fresh_config()?))
    }

    /// Load settings or generate and atomically persist the initial credentials.
    /// Invalid existing state is never silently replaced with a different key.
    pub fn load(path: PathBuf) -> io::Result<Self> {
        let config = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice::<Socks5Config>(&data).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 state file")
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let config = fresh_config()?;
                persist(&path, &config)?;
                config
            }
            Err(error) => return Err(error),
        };
        if config.username.is_empty()
            || config.username.len() > 255
            || config.password.is_empty()
            || config.password.len() > 255
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 credential lengths",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self::new(Some(path), config))
    }

    fn new(path: Option<PathBuf>, config: Socks5Config) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                config,
                running: None,
                last_error: None,
            }),
        }
    }

    pub async fn status(&self) -> Socks5Status {
        self.state.lock().await.status()
    }

    pub(super) async fn restore(ctx: Arc<ServerContext>) {
        let manager = ctx.socks5.clone();
        let enabled = manager.state.lock().await.config.enabled;
        if enabled
            && let Err(error) = Self::change(
                ctx,
                Change::SetEnabled {
                    enabled,
                    listen: None,
                },
            )
            .await
        {
            manager.state.lock().await.last_error = Some(error.to_string());
            tracing::error!(%error, "could not restore SOCKS5 listener; native proxy remains available");
        }
    }

    pub(super) async fn change(
        ctx: Arc<ServerContext>,
        change: Change,
    ) -> io::Result<Socks5Status> {
        // Once accepted, complete the persistence/runtime transaction even if the
        // requesting control connection is cancelled. Shutdown joins this work
        // through the same state mutex before releasing the listener.
        tokio::spawn(async move {
            let manager = ctx.socks5.clone();
            manager.apply(ctx, change).await
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn apply(&self, ctx: Arc<ServerContext>, change: Change) -> io::Result<Socks5Status> {
        let mut state = self.state.lock().await;
        if ctx.cancel.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "server is shutting down",
            ));
        }
        let mut next = state.config.clone();
        match change {
            Change::SetEnabled { enabled, listen } => {
                if !enabled && listen.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "listen address is only accepted when enabling SOCKS5",
                    ));
                }
                next.enabled = enabled;
                if let Some(listen) = listen {
                    next.listen = listen;
                }
            }
            Change::RotateKey => next.password = generate_password()?,
        }
        if next == state.config && (state.status().running || !next.enabled) {
            return Ok(state.status());
        }
        let prepared = if next.enabled {
            let socket = if let Some(running) = state
                .running
                .as_ref()
                .filter(|_| next.listen == state.config.listen)
            {
                running.listener.clone()
            } else {
                Arc::new(TcpListener::bind(next.listen).await?)
            };
            next.listen = socket.local_addr()?;
            Some((socket, Arc::new(listener::Authenticator::new(&next)?)))
        } else {
            None
        };
        if let Some(path) = self.path.clone() {
            let saved = next.clone();
            tokio::task::spawn_blocking(move || persist(&path, &saved))
                .await
                .map_err(io::Error::other)??;
        }
        // No fallible operations remain after the atomic replacement. Revoke
        // every old authenticated session before acknowledging disable/rotation.
        if let Some(running) = state.running.take() {
            running.stop().await;
        }
        state.config = next;
        state.last_error = None;
        if let Some((listener, auth)) = prepared {
            let cancel = ctx.cancel.child_token();
            let task = tokio::spawn(listener::run(listener.clone(), auth, ctx, cancel.clone()));
            state.running = Some(Running {
                listener,
                cancel,
                task,
            });
        }
        tracing::info!(enabled = state.config.enabled, listen = %state.config.listen, "SOCKS5 settings applied");
        Ok(state.status())
    }

    pub(super) async fn shutdown(&self) {
        if let Some(running) = self.state.lock().await.running.take() {
            running.stop().await;
        }
    }
}

fn generate_password() -> io::Result<String> {
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("OS random generator failed"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

fn fresh_config() -> io::Result<Socks5Config> {
    Ok(Socks5Config {
        enabled: false,
        listen: SocketAddr::from(([0, 0, 0, 0], 1080)),
        username: "cipherrelay".into(),
        password: generate_password()?,
    })
}

fn persist(path: &std::path::Path, config: &Socks5Config) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    // NamedTempFile creates mode 0600 on Unix and atomically replaces the target
    // on both Windows and Unix; failed writes leave the previous key intact.
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut file, config).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}
