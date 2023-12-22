use std::sync::{atomic::AtomicBool, Arc};

use futures::Future;
use tokio::{
    signal::unix::{signal, Signal, SignalKind},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

type TaskId = i64;
const SIGNAL_TASK_ID: TaskId = -1;

pub trait GracefulShutdownManager {
    async fn wait(&self);

    fn spawn<F>(&self, task_id: TaskId, task: F) -> JoinHandle<()>
    where
        F: Future + Send + 'static;

    fn spawn_signal_task(&mut self, signal: Signal);

    fn is_cancelled(&self) -> bool;
}

pub struct GracefulShutdownManagerImpl {
    tracker: TaskTracker,
    token: CancellationToken,
    is_cancel: Arc<AtomicBool>,
}

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

    fn register_signal(&mut self, kind: SignalKind) -> bool {
        if let Some(signal) = get_signal(kind) {
            self.spawn_signal_task(signal);
            true
        } else {
            false
        }
    }

    pub fn spawn_graceful_signals(&mut self) -> bool {
        self.register_signal(SignalKind::interrupt())
            && self.register_signal(SignalKind::terminate())
            && self.register_signal(SignalKind::quit())
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
                    tracing::info!("TaskId:{task_id} cancelled ok!");
                }
                _ = task =>{
                    tracing::info!("TaskId:{task_id} norlmal finished!");
                }
            }
        })
    }

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
                tracing::info!("Received {}, but tasks already cancle", fmt_sig);
                return;
            }
            tracing::info!("Received {}, Start to cancle tasks", fmt_sig);
            is_cancle.store(true, std::sync::atomic::Ordering::Release);
            tracker.close();
            token.cancel();
        });
    }

    fn is_cancelled(&self) -> bool {
        self.is_cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
}
