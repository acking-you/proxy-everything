//! Baseline single-ingress black hole and Phase 1 dual-ingress failover acceptance scenarios.

mod common;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{DualIngressHarness, FaultMode, SECRET};
use proxy_core::quic::{self, FailureKind, StandbyRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinSet;

#[derive(Clone)]
struct LogCapture {
    buffer: Arc<Mutex<String>>,
    isolated_seen: Arc<AtomicBool>,
    isolated_notify: Arc<Notify>,
}

struct BufferWriter {
    buffer: Arc<Mutex<String>>,
    isolated_seen: Arc<AtomicBool>,
    isolated_notify: Arc<Notify>,
}

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let notify = {
            let mut logs = self.buffer.lock().unwrap();
            logs.push_str(&text);
            text.contains("observation=\"isolated\"")
                && !self.isolated_seen.swap(true, Ordering::SeqCst)
        };
        if notify {
            self.isolated_notify.notify_waiters();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter {
            buffer: Arc::clone(&self.buffer),
            isolated_seen: Arc::clone(&self.isolated_seen),
            isolated_notify: Arc::clone(&self.isolated_notify),
        }
    }
}

impl LogCapture {
    fn install() -> Self {
        let capture = Self {
            buffer: Arc::new(Mutex::new(String::new())),
            isolated_seen: Arc::new(AtomicBool::new(false)),
            isolated_notify: Arc::new(Notify::new()),
        };
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(capture.clone())
            .try_init();
        capture
    }

    fn reset_isolation(&self) {
        self.isolated_seen.store(false, Ordering::SeqCst);
    }

    async fn wait_isolated(&self) {
        loop {
            let notified = self.isolated_notify.notified();
            if self.isolated_seen.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    fn snapshot(&self) -> String {
        self.buffer.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn standby_ingress_failover_baseline_metrics_rescue_and_log_hygiene() {
    let logs = LogCapture::install();
    tokio::time::timeout(Duration::from_secs(120), async {
        baseline_single_ingress_black_hole_and_healthy_comparison(&logs).await;
        cold_start_and_active_stream_failover_with_flapping_and_rollback(&logs).await;
        slow_backend_and_old_connection_primary_rescue(&logs).await;
    })
    .await
    .unwrap();

    let captured = logs.snapshot();
    assert!(
        captured.contains("QUIC ingress attempt failed; trying alternate ingress"),
        "failover attempts must emit structured diagnostics"
    );
    assert!(
        captured.contains("promoted standby QUIC ingress for new sessions"),
        "standby promotion must be logged once authenticated"
    );
    assert!(
        !captured.contains(SECRET),
        "QUIC logs must never contain SECRET_KEY"
    );
    assert!(
        !captured.contains("SENSITIVE_PAYLOAD_MARKER"),
        "QUIC logs must never contain application payload bytes"
    );
    assert!(
        !captured.contains("https://secret-origin.example/private"),
        "QUIC logs must never contain target URLs"
    );
}

async fn baseline_single_ingress_black_hole_and_healthy_comparison(logs: &LogCapture) {
    quic::configure_standby(Vec::new()).unwrap();
    let mut harness = DualIngressHarness::start(Duration::ZERO).await;
    let primary_port = harness.primary.port();
    let standby_port = harness.standby.port();

    // Warm single-port baseline: p50/p95 stream open and 8 MiB echo throughput.
    let warm_root = quic::connect("localhost", primary_port).await.unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    let (single_p50_us, single_p95_us, single_mib_s) =
        measure_stream_latencies_and_throughput(primary_port).await;
    drop(warm_root);

    // Enable standby while primary stays healthy: standby is never dialed or packeted.
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    let stats_before = quic::selector_stats();
    let standby_packets_before = harness.standby.client_datagrams();
    let (dual_p50_us, dual_p95_us, dual_mib_s) =
        measure_stream_latencies_and_throughput(primary_port).await;
    let stats_after = quic::selector_stats();
    assert_eq!(
        stats_after.standby_dials - stats_before.standby_dials,
        0,
        "healthy primary must never dial standby"
    );
    assert_eq!(
        harness.standby.client_datagrams(),
        standby_packets_before,
        "healthy primary must send zero UDP packets to standby"
    );
    println!(
        "healthy comparison: single(p50={}us, p95={}us, {:.1} MiB/s) vs dual_configured(p50={}us, \
         p95={}us, {:.1} MiB/s)",
        single_p50_us, single_p95_us, single_mib_s, dual_p50_us, dual_p95_us, dual_mib_s
    );

    // Step 1 baseline: disable standby and inject a full primary return black hole.
    quic::configure_standby(Vec::new()).unwrap();
    quic::shutdown_clients().await;
    let mut original = quic::connect("localhost", primary_port).await.unwrap();
    let _old_server = harness.connections_rx.recv().await.unwrap();
    original.write_u8(10).await.unwrap();
    assert_eq!(original.read_u8().await.unwrap(), 10);
    assert_eq!(harness.received_rx.recv().await, Some(10));

    logs.reset_isolation();
    harness.primary.set_fault(FaultMode::DropReturn, 0);
    let fault_at = Instant::now();
    original.write_u8(11).await.unwrap();
    assert_eq!(harness.received_rx.recv().await, Some(11));

    logs.wait_isolated().await;
    let fault_to_detection = fault_at.elapsed();

    let acquire_at = Instant::now();
    let err = quic::connect("localhost", primary_port)
        .await
        .err()
        .unwrap();
    let acquire_elapsed = acquire_at.elapsed();
    assert_eq!(quic::classify_error(&err), FailureKind::Timeout);
    assert!(
        !quic::connect_error(&err).unwrap().standby_attempted(),
        "unconfigured node must not attempt standby"
    );
    assert!(
        (Duration::from_millis(3800)..Duration::from_secs(11)).contains(&acquire_elapsed),
        "single-ingress black hole must fail once per-address 4s attempts expire (<= 10s budget), \
         got {acquire_elapsed:?}"
    );
    println!(
        "baseline single-ingress black hole: fault_to_detection={:?}, new_session_timeout={:?}",
        fault_to_detection, acquire_elapsed
    );

    // Restoring the single ingress before Quinn's 30s idle timeout delivers the in-flight byte
    // once.
    harness.primary.set_fault(FaultMode::Pass, 0);
    assert_eq!(original.read_u8().await.unwrap(), 11);
    assert!(harness.received_rx.try_recv().is_err());
    drop(original);
    harness.shutdown().await;
}

async fn cold_start_and_active_stream_failover_with_flapping_and_rollback(logs: &LogCapture) {
    let mut harness = DualIngressHarness::start(Duration::ZERO).await;
    let primary_port = harness.primary.port();
    let standby_port = harness.standby.port();
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();

    // Row 2: Cold start with primary unreachable and standby reachable.
    harness.primary.set_fault(FaultMode::DropAll, 0);
    harness.standby.set_fault(FaultMode::Pass, 0);
    let stats_before = quic::selector_stats();
    let cold_started = Instant::now();
    let mut cold_stream = quic::connect("localhost", primary_port).await.unwrap();
    let cold_acquire = cold_started.elapsed();
    let _standby_server = harness.connections_rx.recv().await.unwrap();
    assert_eq!(cold_stream.peer_addr().port(), standby_port);
    assert!(
        (Duration::from_millis(3800)..Duration::from_secs(7)).contains(&cold_acquire),
        "cold-start failover must finish after the ~4s primary slice within the 10s deadline, got \
         {cold_acquire:?}"
    );
    let marker = b"SENSITIVE_PAYLOAD_MARKER:https://secret-origin.example/private";
    cold_stream.write_all(marker).await.unwrap();
    let mut echoed = vec![0u8; marker.len()];
    cold_stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, marker);
    println!("cold-start standby failover: session_acquire={cold_acquire:?}");

    // Row 8: Flapping primary while standby connection stays healthy causes zero dials or jitter.
    let dials_after_cold = quic::selector_stats();
    assert_eq!(
        dials_after_cold.standby_dials - stats_before.standby_dials,
        1
    );
    for mode in [
        FaultMode::Pass,
        FaultMode::DropAll,
        FaultMode::Pass,
        FaultMode::DropReturn,
        FaultMode::Pass,
    ] {
        harness.primary.set_fault(mode, 0);
        let reused_at = Instant::now();
        let reused = quic::connect("localhost", primary_port).await.unwrap();
        assert!(reused_at.elapsed() < Duration::from_millis(100));
        assert_eq!(reused.connection_id(), cold_stream.connection_id());
    }
    let dials_after_flap = quic::selector_stats();
    assert_eq!(
        dials_after_flap.primary_dials, dials_after_cold.primary_dials,
        "primary flapping must not trigger primary probes while standby stays healthy"
    );

    // Reverse recovery: when standby becomes unavailable and primary is healthy, fail back to
    // primary.
    drop(cold_stream);
    _standby_server.close();
    tokio::time::sleep(Duration::from_millis(50)).await;
    harness.standby.set_fault(FaultMode::DropAll, 0);
    let mut recovered_primary = quic::connect("localhost", primary_port).await.unwrap();
    let _primary_server = harness.connections_rx.recv().await.unwrap();
    assert_eq!(recovered_primary.peer_addr().port(), primary_port);
    recovered_primary.write_u8(21).await.unwrap();
    assert_eq!(recovered_primary.read_u8().await.unwrap(), 21);
    assert_eq!(harness.received_rx.recv().await, Some(21));

    // Row 3: Existing stream open on primary when whole primary return path blackholes.
    harness.standby.set_fault(FaultMode::Pass, 0);
    logs.reset_isolation();
    harness.primary.set_fault(FaultMode::DropReturn, 0);
    let fault_at = Instant::now();
    recovered_primary.write_u8(22).await.unwrap();
    assert_eq!(harness.received_rx.recv().await, Some(22));

    logs.wait_isolated().await;
    let fault_to_detection = fault_at.elapsed();

    let acquire_at = Instant::now();
    let mut concurrent = JoinSet::new();
    for _ in 0..8 {
        concurrent.spawn(async move { quic::connect("localhost", primary_port).await.unwrap() });
    }
    let mut standby_replacement = concurrent.join_next().await.unwrap().unwrap();
    let session_acquire = acquire_at.elapsed();
    let _standby_server_2 = harness.connections_rx.recv().await.unwrap();
    assert_eq!(standby_replacement.peer_addr().port(), standby_port);
    assert!(
        session_acquire < Duration::from_secs(2),
        "after primary isolation, new sessions must try standby immediately without waiting 4s, \
         got {session_acquire:?}"
    );
    while let Some(stream) = concurrent.join_next().await {
        assert_eq!(
            stream.unwrap().connection_id(),
            standby_replacement.connection_id()
        );
    }
    standby_replacement.write_u8(23).await.unwrap();
    assert_eq!(standby_replacement.read_u8().await.unwrap(), 23);
    assert_eq!(harness.received_rx.recv().await, Some(23));
    println!(
        "active-stream primary black hole: fault_to_detection={:?}, \
         post_isolation_session_acquire={:?}",
        fault_to_detection, session_acquire
    );

    // Original stream was neither closed nor replayed by selector switching.
    harness.primary.set_fault(FaultMode::Pass, 0);
    assert_eq!(recovered_primary.read_u8().await.unwrap(), 22);
    assert!(
        harness.received_rx.try_recv().is_err(),
        "application bytes must never replay across connections"
    );
    drop(recovered_primary);
    drop(standby_replacement);

    // Rollback: clearing standby configuration immediately restores single-port behavior.
    quic::configure_standby(Vec::new()).unwrap();
    quic::shutdown_clients().await;
    harness.primary.set_fault(FaultMode::DropAll, 0);
    let standby_before = harness.standby.client_datagrams();
    let rollback_err = tokio::time::timeout(
        Duration::from_secs(12),
        quic::connect("localhost", primary_port),
    )
    .await
    .unwrap()
    .err()
    .unwrap();
    assert_eq!(quic::classify_error(&rollback_err), FailureKind::Timeout);
    assert_eq!(
        harness.standby.client_datagrams(),
        standby_before,
        "clearing standby rules must immediately stop standby dialing"
    );

    harness.shutdown().await;
}

async fn slow_backend_and_old_connection_primary_rescue(logs: &LogCapture) {
    // Row 4a: A slow backend response (1.5s) with healthy QUIC ACKs never isolates or dials
    // standby.
    let mut slow_harness = DualIngressHarness::start(Duration::from_millis(1500)).await;
    let slow_primary = slow_harness.primary.port();
    let slow_standby = slow_harness.standby.port();
    quic::configure_standby([StandbyRule::new("localhost", slow_primary, slow_standby).unwrap()])
        .unwrap();
    let standby_before = quic::selector_stats().standby_dials;
    let mut slow_stream = quic::connect("localhost", slow_primary).await.unwrap();
    let _ = slow_harness.connections_rx.recv().await.unwrap();
    slow_stream.write_u8(41).await.unwrap();
    assert_eq!(slow_stream.read_u8().await.unwrap(), 41);
    assert_eq!(quic::selector_stats().standby_dials, standby_before);
    drop(slow_stream);
    slow_harness.shutdown().await;

    // Row 4b: Fault affects ONLY the old connection's client source port while standby is
    // unreachable -> primary rescue attempt succeeds within the single 10s acquisition budget!
    let mut harness = DualIngressHarness::start(Duration::ZERO).await;
    let primary_port = harness.primary.port();
    let standby_port = harness.standby.port();
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    harness.standby.set_fault(FaultMode::DropAll, 0);

    let mut original = quic::connect("localhost", primary_port).await.unwrap();
    let _old_server = harness.connections_rx.recv().await.unwrap();
    original.write_u8(51).await.unwrap();
    assert_eq!(original.read_u8().await.unwrap(), 51);
    assert_eq!(harness.received_rx.recv().await, Some(51));

    logs.reset_isolation();
    let old_client_port = original.local_addr().unwrap().port();
    harness.primary.set_fault(FaultMode::Pass, old_client_port);
    original.write_u8(52).await.unwrap();
    assert_eq!(harness.received_rx.recv().await, Some(52));

    logs.wait_isolated().await;
    let rescue_started = Instant::now();
    let mut rescued = quic::connect("localhost", primary_port).await.unwrap();
    let rescue_elapsed = rescue_started.elapsed();
    let _rescued_server = harness.connections_rx.recv().await.unwrap();
    assert_eq!(rescued.peer_addr().port(), primary_port);
    assert_ne!(rescued.connection_id(), original.connection_id());
    assert!(
        (Duration::from_millis(3800)..Duration::from_secs(8)).contains(&rescue_elapsed),
        "primary rescue after standby timeout must complete inside the 10s budget, got \
         {rescue_elapsed:?}"
    );
    rescued.write_u8(53).await.unwrap();
    assert_eq!(rescued.read_u8().await.unwrap(), 53);
    assert_eq!(harness.received_rx.recv().await, Some(53));
    println!("old-connection fault + standby down -> primary rescue={rescue_elapsed:?}");

    harness.primary.set_fault(FaultMode::Pass, 0);
    assert_eq!(original.read_u8().await.unwrap(), 52);
    drop(rescued);
    drop(original);
    harness.shutdown().await;
}

async fn measure_stream_latencies_and_throughput(port: u16) -> (u64, u64, f64) {
    let mut samples_us = Vec::with_capacity(64);
    for _ in 0..64 {
        let t = Instant::now();
        let mut s = quic::connect("localhost", port).await.unwrap();
        samples_us.push(t.elapsed().as_micros() as u64);
        s.write_all(b"ok").await.unwrap();
        let mut pong = [0u8; 2];
        s.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ok");
    }
    samples_us.sort_unstable();
    let p50 = samples_us[samples_us.len() / 2];
    let p95 = samples_us[(samples_us.len() * 95) / 100];

    let total_bytes: usize = 4 * 1024 * 1024;
    let payload = vec![0x5au8; 64 * 1024];
    let mut stream = quic::connect("localhost", port).await.unwrap();
    let (mut recv, mut send) = tokio::io::split(&mut stream);
    let started = Instant::now();
    tokio::join!(
        async {
            let mut remaining = total_bytes;
            while remaining > 0 {
                let chunk = remaining.min(payload.len());
                send.write_all(&payload[..chunk]).await.unwrap();
                remaining -= chunk;
            }
            send.shutdown().await.unwrap();
        },
        async {
            let mut buf = vec![0u8; 64 * 1024];
            let mut got = 0usize;
            while got < total_bytes {
                let n = recv.read(&mut buf).await.unwrap();
                assert!(n > 0);
                got += n;
            }
        }
    );
    let secs = started.elapsed().as_secs_f64().max(1e-6);
    let mib_s = (total_bytes as f64 / (1024.0 * 1024.0)) / secs;
    (p50, p95, mib_s)
}
