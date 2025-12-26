use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use futures::Future;
#[cfg(not(target_env = "msvc"))]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub type TaskId = i64;
const SIGNAL_TASK_ID: TaskId = -1;

pub trait TaskIdGenerator {
    fn r#gen(&mut self) -> TaskId;
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
            fn r#gen(&mut self) -> TaskId {
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

    fn cancellation_token(&self) -> CancellationToken;
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
    pub fn spawn_graceful_signals(&mut self) -> bool {
        macro_rules! fetch_signal {
            ($signal:expr) => {
                if let Some(sig) = get_signal($signal) {
                    sig
                } else {
                    return false;
                }
            };
        }
        let tracker = self.tracker.clone();
        let token = self.token.clone();
        let is_cancle = self.is_cancel.clone();
        let handle_signal = move |name: &'static str| {
            tracing::info!("Signal trigger:{name}");
            if is_cancle.load(std::sync::atomic::Ordering::Acquire) {
                tracing::warn!("Already cancled!");
            }
            tracing::info!("Start to cancle tasks");
            is_cancle.store(true, std::sync::atomic::Ordering::Release);
            tracker.close();
            token.cancel();
        };

        let mut interrupt = fetch_signal!(SignalKind::interrupt());
        let mut terminate = fetch_signal!(SignalKind::terminate());
        let mut quit = fetch_signal!(SignalKind::quit());

        self.spawn(SIGNAL_TASK_ID, async move {
            tokio::select! {
                _ = interrupt.recv()=>{
                    handle_signal("interrupt");
                }
                _ = terminate.recv()=>{
                    handle_signal("terminate");
                }
                _ = quit.recv()=>{
                    handle_signal("quit");
                }
            }
        });

        true
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

    fn cancellation_token(&self) -> CancellationToken {
        self.token.clone()
    }
}
