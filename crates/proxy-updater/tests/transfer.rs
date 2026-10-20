use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use proxy_updater::transfer::{Request, execute};
use ring::digest;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn hash(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn serve(body: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/package", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 8192];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(body).await.unwrap();
    });
    (url, task)
}

#[tokio::test]
async fn streams_verified_package_and_reports_signed_size() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("update.apk");
    let (url, server) = serve(b"verified package").await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = events.clone();
    execute(
        Request::Download {
            url,
            target: target.clone(),
            size: 16,
            sha256: hash(b"verified package"),
            proxy_port: None,
        },
        CancellationToken::new(),
        move |event| captured.lock().unwrap().push(event),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"verified package");
    assert!(!target.with_extension("part").exists());
    let events = events.lock().unwrap();
    assert_eq!(events.last().unwrap()["received"], 16);
    assert_eq!(events.last().unwrap()["total"], 16);
}

#[tokio::test]
async fn rejects_wrong_size_or_hash_without_publishing_a_package() {
    for (size, sha256) in [(4, hash(b"1234")), (3, hash(b"bad"))] {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("update.apk");
        let (url, server) = serve(b"123").await;
        let error = execute(
            Request::Download {
                url,
                target: target.clone(),
                size,
                sha256,
                proxy_port: None,
            },
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert_eq!(error.kind, "checksum");
        assert!(!target.exists());
        assert!(!target.with_extension("part").exists());
    }
}

#[tokio::test]
async fn a_preexisting_partial_belongs_to_someone_else() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("update.apk");
    let partial = target.with_extension("part");
    std::fs::write(&partial, b"other job").unwrap();
    let (url, server) = serve(b"123").await;
    assert!(
        execute(
            Request::Download {
                url,
                target,
                size: 3,
                sha256: hash(b"123"),
                proxy_port: None
            },
            CancellationToken::new(),
            |_| {}
        )
        .await
        .is_err()
    );
    server.await.unwrap();
    assert_eq!(std::fs::read(partial).unwrap(), b"other job");
}

#[tokio::test]
async fn cancellation_interrupts_a_stalled_body_and_removes_owned_partial() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("update.apk");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 8192];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
            .await
            .unwrap();
        let mut byte = [0];
        let _ = socket.read(&mut byte).await;
    });
    let cancellation = CancellationToken::new();
    let token = cancellation.clone();
    let partial = target.with_extension("part");
    let partial_probe = partial.clone();
    let cancel = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !partial_probe.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        token.cancel();
    });
    let error = execute(
        Request::Download {
            url,
            target: target.clone(),
            size: 100,
            sha256: hash(&[0; 100]),
            proxy_port: None,
        },
        cancellation,
        |_| {},
    )
    .await
    .unwrap_err();
    cancel.await.unwrap();
    server.await.unwrap();
    assert_eq!(error.kind, "cancelled");
    assert!(!target.exists() && !partial.exists());
}

#[tokio::test]
async fn metadata_has_a_hard_size_limit() {
    let (url, server) = serve(b"too much metadata").await;
    let error = execute(
        Request::Fetch {
            url,
            limit: 3,
            proxy_port: None,
        },
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap_err();
    server.await.unwrap();
    assert_eq!(error.kind, "network");
}

#[tokio::test]
async fn signature_covers_exact_manifest_bytes_and_key() {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let signature = BASE64_STANDARD.encode(pair.sign(b"manifest").as_ref());
    for body in [b"manifest".as_slice(), b"modified"] {
        let result = execute(
            Request::VerifySignature {
                body: BASE64_STANDARD.encode(body),
                signature: signature.clone(),
                public_key: BASE64_STANDARD.encode(pair.public_key().as_ref()),
            },
            CancellationToken::new(),
            |_| {},
        )
        .await;
        assert_eq!(result.is_ok(), body == b"manifest");
    }
}
