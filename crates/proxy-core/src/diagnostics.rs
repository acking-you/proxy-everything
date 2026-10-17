//! Opt-in, read-only connection observations. A probe scope retains its last
//! phase across cancellation without changing socket options or wire behavior.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::TcpStream;

#[cfg(windows)]
mod windows;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
tokio::task_local! {
    static CURRENT: ConnectionTrace;
}

struct Phase {
    name: &'static str,
    since: Instant,
}

/// A process-local correlation ID and phase timeline for one diagnostic probe.
/// Task-local scoping prevents concurrent probes from sharing phase state.
#[derive(Clone)]
pub struct ConnectionTrace {
    id: u64,
    started: Instant,
    phase: Arc<Mutex<Phase>>,
}

impl Default for ConnectionTrace {
    fn default() -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            phase: Arc::new(Mutex::new(Phase {
                name: "starting",
                since: Instant::now(),
            })),
        }
    }
}

impl ConnectionTrace {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn phase(&self) -> &'static str {
        self.phase.lock().name
    }

    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT.scope(self.clone(), future).await
    }
}

/// Record a phase boundary only within an explicitly enabled diagnostic scope.
pub fn phase(name: &'static str) {
    let _ = CURRENT.try_with(|trace| {
        let now = Instant::now();
        let previous = {
            let mut phase = trace.phase.lock();
            std::mem::replace(&mut *phase, Phase { name, since: now })
        };
        tracing::info!(
            connection_id = trace.id,
            process_id = std::process::id(),
            previous_phase = previous.name,
            phase = name,
            previous_phase_us = now.duration_since(previous.since).as_micros() as u64,
            elapsed_us = now.duration_since(trace.started).as_micros() as u64,
            "connection diagnostic phase"
        );
    });
}

pub fn tcp_connect_finished(
    address: SocketAddr,
    elapsed: Duration,
    result: &std::io::Result<TcpStream>,
) {
    let _ = CURRENT.try_with(|trace| {
        tracing::info!(
            connection_id = trace.id,
            process_id = std::process::id(),
            destination = %address,
            tcp_connect_us = elapsed.as_micros() as u64,
            success = result.is_ok(),
            os_error = result.as_ref().err().and_then(std::io::Error::raw_os_error),
            error = ?result.as_ref().err(),
            "connection diagnostic TCP connect completed"
        );
        if let Ok(stream) = result {
            record_socket("tcp_connected", stream);
        }
    });
}

/// Inspect the same live socket before it is dropped after success or failure.
/// A route query is a snapshot, not evidence that a packet traversed that NIC.
pub fn record_socket(observation: &'static str, stream: &TcpStream) {
    let _ = CURRENT.try_with(|trace| {
        let started = Instant::now();
        let (local, peer) = (stream.local_addr(), stream.peer_addr());
        tracing::info!(
            connection_id = trace.id,
            process_id = std::process::id(),
            observation,
            elapsed_us = trace.started.elapsed().as_micros() as u64,
            local_addr = ?local.as_ref().ok(),
            peer_addr = ?peer.as_ref().ok(),
            local_addr_error = ?local.as_ref().err(),
            peer_addr_error = ?peer.as_ref().err(),
            "connection diagnostic socket endpoints"
        );
        #[cfg(windows)]
        windows::record(trace.id, observation, stream);
        tracing::info!(
            connection_id = trace.id,
            observation,
            diagnostic_cost_us = started.elapsed().as_micros() as u64,
            "connection diagnostic observation completed"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_scopes_and_cancelled_probes_keep_their_own_phase() {
        let left = ConnectionTrace::default();
        let right = ConnectionTrace::default();
        assert_ne!(left.id(), right.id());
        tokio::join!(
            left.scope(async {
                phase("tcp_connect");
                tokio::task::yield_now().await;
                assert_eq!(left.phase(), "tcp_connect");
            }),
            right.scope(async {
                phase("response_wait");
                tokio::task::yield_now().await;
                assert_eq!(right.phase(), "response_wait");
            })
        );
        let cancelled = tokio::time::timeout(
            Duration::from_millis(1),
            left.scope(async {
                phase("proxy_header_write");
                std::future::pending::<()>().await;
            }),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(left.phase(), "proxy_header_write");
        phase("outside_scope");
        assert_eq!(right.phase(), "response_wait");
        assert_eq!(left.phase(), "proxy_header_write");
    }
}
