use std::sync::{atomic::AtomicBool, Arc};

use futures::Future;
#[cfg(not(target_env = "msvc"))]
use tokio::signal::unix::{signal, Signal, SignalKind};

use tokio::task::JoinHandle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub type TaskId = i64;
const SIGNAL_TASK_ID: TaskId = -1;

pub trait TaskIdGenerator {
    fn gen(&mut self) -> TaskId;
}

macro_rules! make_task_id {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name(TaskId);
        impl $name {
            pub fn new() -> Self {
                Self(0)
            }
        }

        impl TaskIdGenerator for $name {
            fn gen(&mut self) -> TaskId {
                let ret = self.0;
                self.0 += 1;
                ret
            }
        }
    };
}

make_task_id!(ProxyTaskId);
make_task_id!(QueryIpTaskId);

pub trait GracefulShutdownManager {
    async fn wait(&self);

    fn spawn<F>(&self, task_id: TaskId, task: F) -> JoinHandle<()>
    where
        F: Future + Send + 'static;

    #[cfg(not(target_env = "msvc"))]
    fn spawn_signal_task(&mut self, signal: Signal);

    fn is_cancelled(&self) -> bool;
}

pub struct GracefulShutdownManagerImpl {
    tracker: TaskTracker,
    token: CancellationToken,
    is_cancel: Arc<AtomicBool>,
}

#[cfg(not(target_env = "msvc"))]
fn get_signal(kind: SignalKind) -> Option<Signal> {
    match signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("Signal register error:{e}");
            None
        }
    }
}

impl GracefulShutdownManagerImpl {
    pub fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
            is_cancel: Arc::new(false.into()),
        }
    }

    #[cfg(not(target_env = "msvc"))]
    fn register_signal(&mut self, kind: SignalKind) -> bool {
        if let Some(signal) = get_signal(kind) {
            self.spawn_signal_task(signal);
            true
        } else {
            false
        }
    }

    #[cfg(not(target_env = "msvc"))]
    pub fn spawn_graceful_signals(&mut self) -> bool {
        self.register_signal(SignalKind::interrupt())
            && self.register_signal(SignalKind::terminate())
            && self.register_signal(SignalKind::quit())
    }

    #[cfg(target_env = "msvc")]
    pub fn spawn_graceful_signals(&mut self) -> bool {
        use tokio::signal;

        let tracker = self.tracker.clone();
        let token = self.token.clone();
        let is_cancle = self.is_cancel.clone();
        self.spawn(SIGNAL_TASK_ID, async move {
            signal::ctrl_c()
                .await
                .expect("await ctrl-c signal nerver fails");
            if is_cancle.load(std::sync::atomic::Ordering::Acquire) {
                tracing::info!("Windows platform only support ctrl-c signal!");
                return;
            }
            tracing::info!("Start to cancle tasks");
            is_cancle.store(true, std::sync::atomic::Ordering::Release);
            tracker.close();
            token.cancel();
        });
        true
    }
}

impl GracefulShutdownManager for GracefulShutdownManagerImpl {
    async fn wait(&self) {
        self.tracker.wait().await;
    }

    fn spawn<F>(&self, task_id: TaskId, task: F) -> JoinHandle<()>
    where
        F: Future + Send + 'static,
    {
        let token = self.token.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                _ = token.cancelled()=>{
                    tracing::info!(task_id, "cancelled ok!");
                }
                _ = task =>{
                    tracing::debug!(task_id, "finished ok!");
                }
            }
        })
    }

    #[cfg(not(target_env = "msvc"))]
    fn spawn_signal_task(&mut self, mut signal: Signal) {
        let tracker = self.tracker.clone();
        let token = self.token.clone();
        let is_cancle = self.is_cancel.clone();
        self.spawn(SIGNAL_TASK_ID, async move {
            let fmt_sig = format!("{signal:?}");
            signal
                .recv()
                .await
                .expect("Received signal must nerver fails!");
            if is_cancle.load(std::sync::atomic::Ordering::Acquire) {
                tracing::info!(signal = fmt_sig, "Tasks already cancle",);
                return;
            }
            tracing::info!(signal = fmt_sig, "Start to cancle tasks");
            is_cancle.store(true, std::sync::atomic::Ordering::Release);
            tracker.close();
            token.cancel();
        });
    }

    fn is_cancelled(&self) -> bool {
        self.is_cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
}
