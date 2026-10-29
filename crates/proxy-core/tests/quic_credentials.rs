//! Configuration changes must not relabel an in-flight authenticated connection.
use std::sync::Arc;
use std::time::Duration;

use proxy_core::config::runtime::set_secret_key;
use proxy_core::quic::{self, AuthenticatedConnection, EndpointOwner};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "abcdef0123456789abcdef0123456789";
const CERT: &[u8] = include_bytes!("fixtures/quic-cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/quic-key.pem");

#[tokio::test]
async fn an_inflight_handshake_keeps_its_credential_and_new_credentials_cannot_reuse_it() {
    // A dedicated integration binary owns the process-wide credential and trust.
    set_secret_key(Some(SECRET.into()));
    quic::configure_trust(Some(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quic-cert.pem"),
    ))
    .unwrap();
    let endpoint = Arc::new(EndpointOwner(
        quinn::Endpoint::server(
            quic::server_config(CERT, KEY).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap(),
    ));
    let port = endpoint.0.local_addr().unwrap().port();
    tokio::time::timeout(Duration::from_secs(5), async {
        let dialing = tokio::spawn(quic::connect("127.0.0.1", port));
        let incoming = endpoint.0.accept().await.unwrap();
        // The client selected its pool entry, but TLS has not completed.
        set_secret_key(Some(OTHER.into()));
        let (server, stream) = tokio::join!(
            AuthenticatedConnection::accept(incoming, endpoint.clone(), SECRET.as_bytes()),
            dialing,
        );
        let server = server.unwrap();
        let stream = stream.unwrap().unwrap();
        let reject = async {
            AuthenticatedConnection::accept(
                endpoint.0.accept().await.unwrap(),
                endpoint.clone(),
                SECRET.as_bytes(),
            )
            .await
        };
        let (rejected_server, rejected_client) =
            tokio::join!(reject, quic::connect("127.0.0.1", port));
        assert!(rejected_server.is_err());
        assert!(
            rejected_client.is_err(),
            "a different credential must perform fresh authentication"
        );
        set_secret_key(Some(SECRET.into()));
        let reused = quic::connect("127.0.0.1", port).await.unwrap();
        assert_eq!(reused.connection_id(), stream.connection_id());
        drop(reused);
        drop(stream);
        server.close();
    })
    .await
    .unwrap();
    quic::shutdown_clients().await;
    endpoint.0.close(0u32.into(), b"done");
}
