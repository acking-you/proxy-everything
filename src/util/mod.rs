use std::sync::atomic::AtomicBool;

use futures::Future;
use tokio::{signal::unix::Signal, task::JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

trait GracefulShutdownManager {
    fn cancel();

    fn register_signal(signal: Signal);

    async fn wait();

    fn spawn<F>(&self, task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

struct GracefulShutdownManagerImpl {
    tracker: TaskTracker,
    token: CancellationToken,
    is_cancel: AtomicBool,
    signals: Vec<Signal>,
}
