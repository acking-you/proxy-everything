//! Connection-level liveness, independent of application response deadlines.
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use quinn::{Connection, ConnectionError, ConnectionStats, FrameStats, Side};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const ACK_STALL_TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

fn ack_eliciting_frames(frames: &FrameStats) -> u64 {
    // All QUIC frames except ACK, PADDING and CONNECTION_CLOSE elicit ACKs.
    // In particular, Quinn's PTO probes can contain only IMMEDIATE_ACK, with
    // neither a retransmitted STREAM nor PING, even during a one-way black hole.
    [
        frames.ack_frequency,
        frames.crypto,
        frames.data_blocked,
        frames.datagram,
        u64::from(frames.handshake_done),
        frames.immediate_ack,
        frames.max_data,
        frames.max_stream_data,
        frames.max_streams_bidi,
        frames.max_streams_uni,
        frames.new_connection_id,
        frames.new_token,
        frames.path_challenge,
        frames.path_response,
        frames.ping,
        frames.reset_stream,
        frames.retire_connection_id,
        frames.stream_data_blocked,
        frames.streams_blocked_bidi,
        frames.streams_blocked_uni,
        frames.stop_sending,
        frames.stream,
    ]
    .into_iter()
    .fold(0, u64::wrapping_add)
}

pub(super) struct Health {
    pub id: usize,
    pub isolated: CancellationToken,
    pub released: CancellationToken,
    side: Side,
    local_addr: Option<SocketAddr>,
    started: Instant,
    progress: Mutex<Progress>,
}

struct Progress {
    previous: ConnectionStats,
    last_rx: Instant,
    last_ack: Instant,
    awaiting_ack: Option<Instant>,
}

impl Progress {
    fn new(now: Instant, stats: ConnectionStats) -> Self {
        Self {
            previous: stats,
            last_rx: now,
            last_ack: now,
            awaiting_ack: None,
        }
    }

    fn stalled(&self, now: Instant, stats: &ConnectionStats) -> bool {
        let budget = ACK_STALL_TIMEOUT.max(stats.path.rtt.saturating_mul(8));
        self.awaiting_ack
            .is_some_and(|since| now.duration_since(since) >= budget)
    }

    fn observe(&mut self, now: Instant, stats: ConnectionStats) {
        if stats.udp_rx.datagrams != self.previous.udp_rx.datagrams {
            self.last_rx = now;
        }
        // Raw UDP receipt is not proof of a working QUIC connection. Only
        // authenticated ACK progress clears a pending transmission's deadline.
        if stats.frame_rx.acks != self.previous.frame_rx.acks {
            self.last_ack = now;
            self.awaiting_ack = None;
        } else if ack_eliciting_frames(&stats.frame_tx)
            != ack_eliciting_frames(&self.previous.frame_tx)
        {
            // Retransmissions and new requests must not keep extending it.
            self.awaiting_ack.get_or_insert(now);
        }
        // Sending only ACKs (e.g. a download) needs no ACK from the peer.
        // An application waiting on a slow backend needs no response deadline.
        self.previous = stats;
    }
}

impl Health {
    pub fn start(connection: &Connection, local_addr: Option<SocketAddr>, side: Side) -> Arc<Self> {
        let now = Instant::now();
        let health = Arc::new(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            isolated: CancellationToken::new(),
            released: CancellationToken::new(),
            side,
            local_addr,
            started: now,
            progress: Mutex::new(Progress::new(now, connection.stats())),
        });
        // Do not retain SharedConnection or EndpointOwner: the pool's idle
        // reaper and normal stream drops still control the UDP driver's lifetime.
        tokio::spawn(Arc::clone(&health).monitor(connection.clone()));
        health
    }

    async fn monitor(self: Arc<Self>, connection: Connection) {
        let mut ticks = tokio::time::interval(SAMPLE_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                reason = connection.closed() => {
                    let (cause, code, normal) = close_details(&reason);
                    self.record(&connection, if normal { tracing::Level::INFO } else { tracing::Level::WARN }, "closed", cause, code);
                    self.isolated.cancel();
                    return;
                }
                _ = self.released.cancelled() => return,
                _ = ticks.tick() => {
                    let now = Instant::now();
                    let stats = connection.stats();
                    let stalled = {
                        let mut progress = self.progress.lock();
                        // Observe ACKs before deciding: a late but valid reply
                        // wins over the sampling timer at the deadline.
                        progress.observe(now, stats);
                        progress.stalled(now, &stats)
                    };
                    if self.side == Side::Client && stalled && !self.isolated.is_cancelled() {
                        self.isolated.cancel();
                        self.record(&connection, tracing::Level::WARN, "isolated", "ack_progress_timeout", None);
                    }
                }
            }
        }
    }

    pub fn record(
        &self,
        connection: &Connection,
        level: tracing::Level,
        observation: &str,
        cause: &str,
        close_code: Option<u64>,
    ) {
        let stats = connection.stats();
        let now = Instant::now();
        // Only the monitor advances liveness. Concurrent stream diagnostics
        // must not apply older snapshots or change admission decisions.
        let progress = self.progress.lock();
        // One event per isolation/close, plus explicit debug observations. No
        // payloads, credentials or peer-supplied close reason text are logged.
        macro_rules! record {
            ($level:expr) => {
                tracing::event!($level,
                    carrier = "quic", connection_id = self.id, side = ?self.side,
                    local_addr = ?self.local_addr, peer = %connection.remote_address(),
                    observation, cause, close_code,
                    age_ms = now.duration_since(self.started).as_millis() as u64,
                    last_rx_ms = now.duration_since(progress.last_rx).as_millis() as u64,
                    last_ack_ms = now.duration_since(progress.last_ack).as_millis() as u64,
                    awaiting_ack_ms = progress.awaiting_ack.map(|t| now.duration_since(t).as_millis() as u64),
                    ack_stall_budget_ms = ACK_STALL_TIMEOUT.max(stats.path.rtt.saturating_mul(8)).as_millis() as u64,
                    isolated = self.isolated.is_cancelled(),
                    rtt_us = stats.path.rtt.as_micros() as u64,
                    cwnd = stats.path.cwnd, mtu = stats.path.current_mtu,
                    sent_packets = stats.path.sent_packets, lost_packets = stats.path.lost_packets,
                    congestion_events = stats.path.congestion_events,
                    mtu_black_holes = stats.path.black_holes_detected,
                    tx_bytes = stats.udp_tx.bytes, rx_bytes = stats.udp_rx.bytes,
                    tx_datagrams = stats.udp_tx.datagrams, rx_datagrams = stats.udp_rx.datagrams,
                    tx_ios = stats.udp_tx.ios, rx_ios = stats.udp_rx.ios,
                    tx_acks = stats.frame_tx.acks, rx_acks = stats.frame_rx.acks,
                    tx_ack_eliciting_frames = ack_eliciting_frames(&stats.frame_tx),
                    tx_immediate_acks = stats.frame_tx.immediate_ack,
                    tx_stream_frames = stats.frame_tx.stream, rx_stream_frames = stats.frame_rx.stream,
                    tx_pings = stats.frame_tx.ping, rx_pings = stats.frame_rx.ping,
                    peer_stream_blocked = stats.frame_rx.stream_data_blocked,
                    peer_connection_blocked = stats.frame_rx.data_blocked,
                    local_streams_blocked = stats.frame_tx.streams_blocked_bidi,
                    "QUIC connection diagnostics"
                )
            };
        }
        match level {
            tracing::Level::WARN => record!(tracing::Level::WARN),
            tracing::Level::INFO => record!(tracing::Level::INFO),
            _ => record!(tracing::Level::DEBUG),
        }
    }
}

fn close_details(reason: &ConnectionError) -> (&'static str, Option<u64>, bool) {
    match reason {
        ConnectionError::VersionMismatch => ("version_mismatch", None, false),
        ConnectionError::TransportError(error) => {
            ("transport_error", Some(error.code.into()), false)
        }
        ConnectionError::ConnectionClosed(close) => {
            ("peer_transport_close", Some(close.error_code.into()), false)
        }
        ConnectionError::ApplicationClosed(close) => (
            "peer_application_close",
            Some(close.error_code.into()),
            close.error_code == 0u32.into(),
        ),
        ConnectionError::Reset => ("stateless_reset", None, false),
        ConnectionError::TimedOut => ("idle_timeout", None, false),
        ConnectionError::LocallyClosed => ("local_close", None, true),
        ConnectionError::CidsExhausted => ("connection_ids_exhausted", None, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_acks_isolate_transmissions_without_treating_udp_or_retries_as_progress() {
        let start = Instant::now();
        let mut stats = ConnectionStats::default();
        let mut progress = Progress::new(start, stats);
        stats.frame_tx.immediate_ack += 1;
        progress.observe(start, stats);
        let deadline = start + ACK_STALL_TIMEOUT;
        stats.frame_tx.stream += 8;
        stats.udp_rx.datagrams += 20;
        progress.observe(deadline, stats);
        assert!(progress.stalled(deadline, &stats));
        stats.frame_rx.acks += 1;
        progress.observe(deadline, stats);
        assert!(!progress.stalled(deadline, &stats));
    }

    #[test]
    fn ack_only_traffic_and_slow_application_responses_do_not_isolate_a_live_connection() {
        let start = Instant::now();
        let mut stats = ConnectionStats::default();
        let mut progress = Progress::new(start, stats);
        stats.frame_tx.acks += 100;
        stats.frame_rx.stream += 100;
        progress.observe(start, stats);
        assert!(!progress.stalled(start + ACK_STALL_TIMEOUT * 2, &stats));
        stats.frame_tx.ping += 1;
        progress.observe(start, stats);
        stats.frame_rx.acks += 1;
        progress.observe(start + Duration::from_secs(1), stats);
        assert!(!progress.stalled(start + ACK_STALL_TIMEOUT * 2, &stats));
        stats.path.rtt = Duration::from_secs(2);
        stats.frame_tx.stream += 1;
        progress.observe(start + ACK_STALL_TIMEOUT, stats);
        assert!(!progress.stalled(start + ACK_STALL_TIMEOUT * 2, &stats));
    }
}
