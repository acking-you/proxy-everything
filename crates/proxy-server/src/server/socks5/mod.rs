//! A separately bound SOCKS5 endpoint managed through the encrypted control plane.

mod listener;

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use proxy_core::socks5::{Socks5Config, Socks5Endpoint, Socks5Session, Socks5Status, Socks5Update};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use self::listener::Generation;
use super::ServerContext;

const DEFAULT_USERNAME: &str = "cipherrelay";

struct Running {
    listener: Arc<TcpListener>,
    generation: Arc<Generation>,
    task: JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        self.generation.cancel.cancel();
        let _ = self.task.await;
    }
}

struct State {
    config: Socks5Config,
    running: Option<Running>,
    last_error: Option<String>,
    /// The saved file exists but cannot be used. It is reported, never
    /// overwritten, and blocks changes until an operator repairs it.
    blocked: Option<String>,
}

impl State {
    fn running(&self) -> Option<&Running> {
        self.running.as_ref().filter(|r| !r.task.is_finished())
    }

    fn status(&self) -> Socks5Status {
        Socks5Status {
            config: self.config.clone(),
            running: self.running().is_some(),
            last_error: self.blocked.clone().or_else(|| self.last_error.clone()),
            active_sessions: self.running().map_or(0, |r| r.generation.active()),
        }
    }

    async fn stop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop().await;
        }
    }

    /// Serve `config` on `listener`, revoking the previous generation first.
    async fn install(
        &mut self,
        ctx: Arc<ServerContext>,
        listener: Arc<TcpListener>,
        generation: Generation,
    ) {
        self.stop().await;
        let generation = Arc::new(generation);
        self.config = generation.config.clone();
        self.last_error = None;
        let task = tokio::spawn(listener::run(listener.clone(), generation.clone(), ctx));
        self.running = Some(Running {
            listener,
            generation,
            task,
        });
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
    Update(Socks5Update),
}

impl Change {
    /// Apply to `config`. Returns whether the request must take effect as a
    /// whole: enabling or moving the listener fails if it cannot bind, while
    /// credential and policy changes are kept for the next successful start.
    fn apply(self, config: &mut Socks5Config) -> io::Result<bool> {
        match self {
            Self::SetEnabled { enabled, listen } => {
                if !enabled && listen.is_some() {
                    return Err(invalid_input(
                        "listen address is only accepted when enabling SOCKS5",
                    ));
                }
                config.enabled = enabled;
                if let Some(listen) = listen {
                    config.listen = listen;
                }
                Ok(true)
            }
            Self::RotateKey => {
                config.password = generate_password()?;
                Ok(false)
            }
            Self::Update(update) => {
                config.apply(update).map_err(invalid_input)?;
                Ok(false)
            }
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl Socks5Manager {
    /// Create an isolated, disabled endpoint without writing to the user's profile.
    pub fn in_memory() -> io::Result<Self> {
        Ok(Self::new(None, fresh_config()?, None, None))
    }

    /// Load settings, or generate and atomically persist the initial credentials.
    ///
    /// Never fails: SOCKS5 is optional, so a problem with its state must not
    /// stop the native proxy. An unusable existing file is reported and kept
    /// as is rather than silently replaced with a different key.
    pub fn load(path: PathBuf) -> Self {
        match std::fs::read(&path) {
            Ok(data) => {
                let config = serde_json::from_slice::<Socks5Config>(&data)
                    .map_err(|error| error.to_string())
                    .and_then(|config| config.validate().map(|()| config));
                match config {
                    Ok(config) => {
                        restrict_permissions(&path);
                        Self::new(Some(path), config, None, None)
                    }
                    Err(error) => {
                        let reason = format!(
                            "invalid SOCKS5 state file {}: {error}; repair or remove it",
                            path.display()
                        );
                        Self::blocked(path, reason)
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let config = match fresh_config() {
                    Ok(config) => config,
                    Err(error) => return Self::blocked(path, error.to_string()),
                };
                let last_error = persist(&path, &config).err().map(|error| {
                    let message = format!("could not save {}: {error}", path.display());
                    tracing::warn!(%message, "SOCKS5 settings are not persisted yet");
                    message
                });
                Self::new(Some(path), config, last_error, None)
            }
            Err(error) => {
                let reason = format!("could not read {}: {error}", path.display());
                Self::blocked(path, reason)
            }
        }
    }

    fn blocked(path: PathBuf, reason: String) -> Self {
        tracing::error!(%reason, "SOCKS5 is unavailable; native proxy remains available");
        let placeholder =
            Socks5Config::new(default_listen(), DEFAULT_USERNAME.into(), String::new());
        Self::new(Some(path), placeholder, None, Some(reason))
    }

    fn new(
        path: Option<PathBuf>,
        config: Socks5Config,
        last_error: Option<String>,
        blocked: Option<String>,
    ) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                config,
                running: None,
                last_error,
                blocked,
            }),
        }
    }

    pub async fn status(&self) -> Socks5Status {
        self.state.lock().await.status()
    }

    pub(super) async fn sessions(&self) -> Vec<Socks5Session> {
        let state = self.state.lock().await;
        state
            .running()
            .map_or_else(Vec::new, |r| r.generation.sessions())
    }

    pub(super) async fn close_sessions(&self, id: Option<u64>, peer: Option<IpAddr>) -> usize {
        let state = self.state.lock().await;
        state.running().map_or(0, |r| r.generation.close(id, peer))
    }

    /// What proxy users dial; only while the listener is serving. The saved
    /// settings are current: an advertise change keeps the running generation.
    pub(super) async fn endpoint(&self) -> Option<Socks5Endpoint> {
        let state = self.state.lock().await;
        state.running().map(|_| state.config.endpoint())
    }

    /// Start a saved enabled listener. Nothing is written: the saved state
    /// already describes it, and a read-only state directory must not stop it.
    pub(super) async fn restore(ctx: Arc<ServerContext>) {
        let manager = ctx.socks5.clone();
        let mut state = manager.state.lock().await;
        if !state.config.enabled || state.blocked.is_some() {
            return;
        }
        let config = state.config.clone();
        let started = async {
            let listener = Arc::new(TcpListener::bind(config.listen).await?);
            Ok::<_, io::Error>((listener, Generation::new(config.clone(), &ctx)?))
        };
        match started.await {
            Ok((listener, generation)) => state.install(ctx.clone(), listener, generation).await,
            Err(error) => {
                tracing::error!(%error, "could not restore SOCKS5 listener; native proxy remains available");
                state.last_error = Some(error.to_string());
            }
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
        if let Some(reason) = &state.blocked {
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason.clone()));
        }
        let mut next = state.config.clone();
        let strict = change.apply(&mut next)?;
        let running = state.running().is_some();
        if next == state.config && (running || !next.enabled) {
            return Ok(state.status());
        }
        if !next.enabled {
            self.persist(&next).await?;
            state.stop().await;
            state.config = next;
            state.last_error = None;
            return Ok(state.status());
        }
        if running && next.same_listener(&state.config) {
            // Only the advertised client address changed; sessions are unaffected.
            self.persist(&next).await?;
            state.config = next;
            return Ok(state.status());
        }
        let reusable = state
            .running()
            .filter(|_| next.listen == state.config.listen)
            .map(|running| running.listener.clone());
        let listener = match reusable {
            Some(listener) => listener,
            None => match TcpListener::bind(next.listen).await {
                Ok(listener) => Arc::new(listener),
                Err(error)
                    if error.kind() == io::ErrorKind::AddrInUse
                        && state.running().is_some_and(|running| {
                            running
                                .listener
                                .local_addr()
                                .is_ok_and(|addr| addr.port() == next.listen.port())
                        }) =>
                {
                    return self.move_listener(&mut state, ctx, next).await;
                }
                Err(error) if strict => return Err(error),
                Err(error) => {
                    // Not running, so nothing is revoked: keep the new
                    // credentials and policy for the next successful start.
                    self.persist(&next).await?;
                    state.config = next;
                    state.last_error = Some(error.to_string());
                    return Ok(state.status());
                }
            },
        };
        next.listen = listener.local_addr()?;
        let generation = Generation::new(next.clone(), &ctx)?;
        self.persist(&next).await?;
        // Revoke every old authenticated session before acknowledging.
        state.install(ctx, listener, generation).await;
        tracing::info!(listen = %state.config.listen, "SOCKS5 settings applied");
        Ok(state.status())
    }

    /// Two overlapping addresses on one port, such as `127.0.0.1:1080` and
    /// `0.0.0.0:1080`, cannot be bound at once, so the running listener closes
    /// first. If the new address still fails, the previous one is restored.
    async fn move_listener(
        &self,
        state: &mut State,
        ctx: Arc<ServerContext>,
        next: Socks5Config,
    ) -> io::Result<Socks5Status> {
        let previous = state.config.clone();
        self.persist(&next).await?;
        state.stop().await;
        let bound = async {
            let listener = Arc::new(TcpListener::bind(next.listen).await?);
            Ok::<_, io::Error>((listener, Generation::new(next.clone(), &ctx)?))
        };
        match bound.await {
            Ok((listener, generation)) => {
                state.install(ctx, listener, generation).await;
                Ok(state.status())
            }
            Err(error) => {
                let restored = async {
                    self.persist(&previous).await?;
                    let listener = Arc::new(TcpListener::bind(previous.listen).await?);
                    Ok::<_, io::Error>((listener, Generation::new(previous.clone(), &ctx)?))
                };
                match restored.await {
                    Ok((listener, generation)) => state.install(ctx, listener, generation).await,
                    Err(restore_error) => {
                        state.last_error = Some(format!(
                            "could not restore {} after failing to bind {}: {restore_error}",
                            previous.listen, next.listen
                        ));
                        state.config = previous;
                    }
                }
                Err(error)
            }
        }
    }

    async fn persist(&self, config: &Socks5Config) -> io::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let config = config.clone();
        tokio::task::spawn_blocking(move || persist(&path, &config))
            .await
            .map_err(io::Error::other)?
    }

    pub(super) async fn shutdown(&self) {
        self.state.lock().await.stop().await;
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 1080))
}

fn generate_password() -> io::Result<String> {
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("OS random generator failed"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random))
}

fn fresh_config() -> io::Result<Socks5Config> {
    Ok(Socks5Config::new(
        default_listen(),
        DEFAULT_USERNAME.into(),
        generate_password()?,
    ))
}

/// Keep credentials private to the service account. Failure is reported but
/// does not disable SOCKS5, for example when another user owns the file.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(%error, path = %path.display(), "could not restrict SOCKS5 state file permissions");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn persist(path: &Path, config: &Socks5Config) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
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
