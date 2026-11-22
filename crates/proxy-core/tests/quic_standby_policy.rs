//! Policy verification for QUIC primary/standby selection:
//! - Both ingresses unreachable: shared 10s deadline, bounded dials, per-node backoff, no TCP
//!   fallback
//! - Concurrent dial coalescing, independent waiter deadlines and early caller cancellation
//! - TLS/certificate/ALPN/authentication errors never masked by standby, and identity/config
//!   generation isolation
//! - Prepared-address (`connect_addresses` / TUN) and multi-node isolation

mod common;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{CERT, DualIngressHarness, FaultMode, KEY, SECRET};
use proxy_core::config::runtime::set_secret_key;
use proxy_core::quic::{self, AuthenticatedConnection, EndpointOwner, FailureKind, StandbyRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

const OTHER_SECRET: &str = "abcdef0123456789abcdef0123456789";

#[tokio::test]
async fn dual_failure_concurrency_cancellation_identity_errors_and_node_isolation() {
    tokio::time::timeout(Duration::from_secs(90), async {
        concurrent_coalescing_and_early_cancellation().await;
        tls_and_authentication_rejections_and_generation_updates().await;
        both_ingresses_unreachable_bounded_dials_no_tcp_fallback_and_node_isolation().await;
    })
    .await
    .unwrap();
}

async fn concurrent_coalescing_and_early_cancellation() {
    let mut harness = DualIngressHarness::start(Duration::ZERO).await;
    let primary_port = harness.primary.port();
    let standby_port = harness.standby.port();
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();

    harness.primary.set_fault(FaultMode::DropAll, 0);
    harness.standby.set_fault(FaultMode::Pass, 0);

    // A single caller cancelled before the 4s primary slice expires must never start standby.
    let before_cancel = quic::selector_stats();
    let standby_pkts_before = harness.standby.client_datagrams();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(200),
        quic::connect("localhost", primary_port),
    )
    .await;
    assert!(cancelled.is_err());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_cancel = quic::selector_stats();
    assert_eq!(
        after_cancel.standby_dials - before_cancel.standby_dials,
        0,
        "caller cancellation must not start a standby attempt"
    );
    assert_eq!(harness.standby.client_datagrams(), standby_pkts_before);

    // 16 concurrent callers (4 impatient at 250ms, 12 full budget) coalesce into 1 primary + 1
    // standby dial.
    let stats_before = quic::selector_stats();
    let mut impatient = JoinSet::new();
    for _ in 0..4 {
        impatient.spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(250),
                quic::connect("localhost", primary_port),
            )
            .await
        });
    }
    let mut patient = JoinSet::new();
    for _ in 0..12 {
        patient.spawn(async move { quic::connect("localhost", primary_port).await.unwrap() });
    }
    while let Some(res) = impatient.join_next().await {
        assert!(res.unwrap().is_err(), "short waiter deadline must fire");
    }
    let _standby_server = harness.connections_rx.recv().await.unwrap();
    let mut shared_conn_id = None;
    while let Some(res) = patient.join_next().await {
        let mut stream = res.unwrap();
        assert_eq!(stream.peer_addr().port(), standby_port);
        match shared_conn_id {
            None => shared_conn_id = Some(stream.connection_id()),
            Some(expected) => assert_eq!(stream.connection_id(), expected),
        }
        stream.write_u8(7).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 7);
        let _ = harness.received_rx.recv().await;
    }
    let stats_after = quic::selector_stats();
    assert_eq!(
        stats_after.primary_dials - stats_before.primary_dials,
        1,
        "16 concurrent callers must coalesce onto 1 primary dial"
    );
    assert_eq!(
        stats_after.standby_dials - stats_before.standby_dials,
        1,
        "12 remaining callers must coalesce onto 1 standby dial"
    );

    // Windows TUN prepared-address entry point (`connect_addresses`) switches to standby within 5s
    // probe window.
    quic::shutdown_clients().await;
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    let prepared_ips: Arc<[IpAddr]> = Arc::from(["127.0.0.1".parse().unwrap()]);
    let tun_probe = tokio::time::timeout(
        Duration::from_secs(6),
        quic::connect_addresses("localhost", primary_port, &prepared_ips),
    )
    .await
    .unwrap()
    .unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(tun_probe.peer_addr().port(), standby_port);
    drop(tun_probe);

    harness.shutdown().await;
}

async fn tls_and_authentication_rejections_and_generation_updates() {
    let mut harness = DualIngressHarness::start(Duration::ZERO).await;
    let primary_port = harness.primary.port();
    let standby_port = harness.standby.port();
    let ips: Arc<[IpAddr]> = Arc::from(["127.0.0.1".parse().unwrap()]);

    // 1. Wrong SAN hostname on primary must return FailureKind::Tls immediately without dialing
    //    standby.
    quic::configure_standby([
        StandbyRule::new("unlisted.example", primary_port, standby_port).unwrap(),
    ])
    .unwrap();
    let before_san = quic::selector_stats();
    let san_err = quic::connect_addresses("unlisted.example", primary_port, &ips)
        .await
        .err()
        .unwrap();
    assert_eq!(quic::classify_error(&san_err), FailureKind::Tls);
    assert!(!quic::connect_error(&san_err).unwrap().standby_attempted());
    assert_eq!(
        quic::selector_stats().standby_dials,
        before_san.standby_dials
    );

    // 2. Wrong application SECRET_KEY on primary must return FailureKind::Authentication
    //    (PermissionDenied)
    // immediately without dialing standby.
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    set_secret_key(Some(OTHER_SECRET.into()));
    let before_auth = quic::selector_stats();
    let auth_err = quic::connect("localhost", primary_port)
        .await
        .err()
        .unwrap();
    assert_eq!(auth_err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(quic::classify_error(&auth_err), FailureKind::Authentication);
    assert!(!quic::connect_error(&auth_err).unwrap().standby_attempted());
    assert_eq!(
        quic::selector_stats().standby_dials,
        before_auth.standby_dials
    );
    set_secret_key(Some(SECRET.into()));

    // 3. Standby reachable over UDP but failing application authentication is NEVER promoted as
    //    preferred.
    let bad_standby = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            quic::server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let bad_standby_port = bad_standby.0.local_addr().unwrap().port();
    let bad_owner = Arc::clone(&bad_standby);
    let bad_server = tokio::spawn(async move {
        if let Some(incoming) = bad_owner.0.accept().await {
            let _ =
                AuthenticatedConnection::accept(incoming, bad_owner, OTHER_SECRET.as_bytes()).await;
        }
    });
    quic::configure_standby([
        StandbyRule::new("localhost", primary_port, bad_standby_port).unwrap(),
    ])
    .unwrap();
    harness.primary.set_fault(FaultMode::DropAll, 0);
    let standby_auth_err = quic::connect("localhost", primary_port)
        .await
        .err()
        .unwrap();
    assert_eq!(
        quic::classify_error(&standby_auth_err),
        FailureKind::Authentication
    );
    bad_server.await.unwrap();
    bad_standby.0.close(0u32.into(), b"done");

    // Restoring primary immediately succeeds on primary without waiting 4s on bad_standby,
    // proving unauthenticated standby was NOT promoted.
    harness.primary.set_fault(FaultMode::Pass, 0);
    let restored_at = Instant::now();
    let on_primary = quic::connect("localhost", primary_port).await.unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(on_primary.peer_addr().port(), primary_port);
    assert!(restored_at.elapsed() < Duration::from_secs(1));
    drop(on_primary);

    // 4. Configuration and trust generation updates do not inherit old standby preference, and
    //    in-flight dials from an older generation cannot overwrite a newer configuration.
    quic::shutdown_clients().await;
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    harness.primary.set_fault(FaultMode::DropAll, 0);
    harness.standby.set_fault(FaultMode::Pass, 0);

    // Start an in-flight dial under generation G1 while primary is black-holed, then reconfigure
    // standby to generation G2 before G1 finishes.
    let stale_inflight = tokio::spawn(quic::connect("localhost", primary_port));
    tokio::time::sleep(Duration::from_millis(100)).await;
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();

    // Let G1 finish failing over to standby (~4s): POOL[standby] is now warm while POOL[primary]
    // is empty, and G1 records standby preference under G1's SelectorKey.
    let g1_stream = stale_inflight.await.unwrap().unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(g1_stream.peer_addr().port(), standby_port);

    // Restore primary: if G1 had overwritten G2's selector preference, G2 would reuse
    // POOL[standby]; instead G2 dials primary immediately.
    harness.primary.set_fault(FaultMode::Pass, 0);
    let g2_started = Instant::now();
    let g2_stream = quic::connect("localhost", primary_port).await.unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(
        g2_stream.peer_addr().port(),
        primary_port,
        "stale async dial from an older config generation must not overwrite current selector \
         preference"
    );
    assert!(g2_started.elapsed() < Duration::from_secs(1));
    drop(g1_stream);
    drop(g2_stream);

    // Promote standby under the current trust generation, then rotate trust: the new trust
    // generation must not inherit old standby preference or reuse old identity connections.
    quic::shutdown_clients().await;
    quic::configure_standby([StandbyRule::new("localhost", primary_port, standby_port).unwrap()])
        .unwrap();
    harness.primary.set_fault(FaultMode::DropAll, 0);
    let promoted = quic::connect("localhost", primary_port).await.unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(promoted.peer_addr().port(), standby_port);
    harness.primary.set_fault(FaultMode::Pass, 0);
    // Confirm standby is sticky before rotating trust.
    let sticky = quic::connect("localhost", primary_port).await.unwrap();
    assert_eq!(sticky.peer_addr().port(), standby_port);

    quic::configure_trust(Some(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quic-cert.pem"),
    ))
    .unwrap();
    let fresh_trust_stream = quic::connect("localhost", primary_port).await.unwrap();
    let _ = harness.connections_rx.recv().await.unwrap();
    assert_eq!(fresh_trust_stream.peer_addr().port(), primary_port);
    drop(promoted);
    drop(sticky);
    drop(fresh_trust_stream);

    harness.shutdown().await;
}

async fn both_ingresses_unreachable_bounded_dials_no_tcp_fallback_and_node_isolation() {
    let node_a = DualIngressHarness::start(Duration::ZERO).await;
    let mut node_b = DualIngressHarness::start(Duration::ZERO).await;
    let a_primary = node_a.primary.port();
    let a_standby = node_a.standby.port();
    let b_primary = node_b.primary.port();
    let b_standby = node_b.standby.port();

    // Bind a TCP listener to verify QUIC failure never triggers silent TCP fallback.
    let tcp_canary = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();

    quic::configure_standby([
        StandbyRule::new("localhost", a_primary, a_standby).unwrap(),
        StandbyRule::new("localhost", b_primary, b_standby).unwrap(),
    ])
    .unwrap();

    node_a.primary.set_fault(FaultMode::DropAll, 0);
    node_a.standby.set_fault(FaultMode::DropAll, 0);

    let stats_before = quic::selector_stats();
    let started = Instant::now();
    let err = quic::connect("localhost", a_primary).await.err().unwrap();
    let elapsed = started.elapsed();
    let stats_after = quic::selector_stats();

    assert_eq!(quic::classify_error(&err), FailureKind::Timeout);
    let details = quic::connect_error(&err).unwrap();
    assert!(details.standby_attempted());
    assert_eq!(details.primary_failure(), Some(FailureKind::Timeout));
    assert_eq!(details.standby_failure(), Some(FailureKind::Timeout));
    assert!(
        (Duration::from_millis(7800)..Duration::from_secs(11)).contains(&elapsed),
        "both ingresses failing on localhost must exhaust 4s per-address attempts within the 10s \
         deadline (not 20s), got {elapsed:?}"
    );
    assert_eq!(stats_after.primary_dials - stats_before.primary_dials, 1);
    assert_eq!(stats_after.standby_dials - stats_before.standby_dials, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), tcp_canary.accept())
            .await
            .is_err(),
        "QUIC dual-ingress failure must never fall back to TCP"
    );

    // Node A is now in all-failed backoff; verify rapid short-deadline burst does zero extra dials
    // while Node B remains completely unthrottled and independent!
    let burst_before = quic::selector_stats();
    for _ in 0..10 {
        let res = tokio::time::timeout(
            Duration::from_millis(40),
            quic::connect("localhost", a_primary),
        )
        .await;
        assert!(res.is_err());
    }
    let burst_after = quic::selector_stats();
    assert_eq!(
        burst_after.primary_dials - burst_before.primary_dials,
        0,
        "all-failed per-node backoff must suppress immediate retry storms"
    );

    let b_started = Instant::now();
    let mut b_stream = quic::connect("localhost", b_primary).await.unwrap();
    let _ = node_b.connections_rx.recv().await.unwrap();
    assert!(
        b_started.elapsed() < Duration::from_secs(1),
        "failure backoff on Node A must not throttle Node B"
    );
    b_stream.write_u8(99).await.unwrap();
    assert_eq!(b_stream.read_u8().await.unwrap(), 99);
    assert_eq!(node_b.received_rx.recv().await, Some(99));
    drop(b_stream);

    // With 4 unreachable addresses (two 4s waves = 8s if uncapped), cand0 (4s) + cand1 (remaining
    // 6s) must still terminate strictly at the shared 10s deadline (not 12s or 20s).
    quic::shutdown_clients().await;
    quic::configure_standby([StandbyRule::new("localhost", b_primary, b_standby).unwrap()])
        .unwrap();
    node_b.primary.set_fault(FaultMode::DropAll, 0);
    node_b.standby.set_fault(FaultMode::DropAll, 0);
    let four_ips: Arc<[IpAddr]> = Arc::from([
        "127.0.0.1".parse().unwrap(),
        "127.0.0.2".parse().unwrap(),
        "127.0.0.3".parse().unwrap(),
        "127.0.0.4".parse().unwrap(),
    ]);
    let multi_started = Instant::now();
    let multi_err = quic::connect_addresses("localhost", b_primary, &four_ips)
        .await
        .err()
        .unwrap();
    let multi_elapsed = multi_started.elapsed();
    assert_eq!(quic::classify_error(&multi_err), FailureKind::Timeout);
    assert!(
        (Duration::from_millis(9500)..Duration::from_millis(11200)).contains(&multi_elapsed),
        "multi-address dual failure must terminate at the shared 10s deadline, got \
         {multi_elapsed:?}"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}
