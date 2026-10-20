use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ring::{digest, signature};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Fetch {
        url: String,
        limit: usize,
        proxy_port: Option<u16>,
    },
    Download {
        url: String,
        target: PathBuf,
        size: u64,
        sha256: String,
        proxy_port: Option<u16>,
    },
    Verify {
        target: PathBuf,
        size: u64,
        sha256: String,
    },
    VerifySignature {
        body: String,
        signature: String,
        public_key: String,
    },
}

#[derive(Debug)]
pub struct Failure {
    pub kind: &'static str,
    pub message: String,
}
impl Failure {
    fn new(kind: &'static str, message: impl ToString) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }
}

fn client(proxy_port: Option<u16>) -> Result<reqwest::Client, Failure> {
    let mut builder = proxy_core::util::http_client_builder()
        .no_proxy()
        .user_agent("CipherRelay-updater")
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(10));
    if let Some(port) = proxy_port {
        builder = builder.proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
                .map_err(|error| Failure::new("network", error))?,
        );
    }
    builder
        .build()
        .map_err(|error| Failure::new("network", error))
}

async fn response(url: &str, proxy_port: Option<u16>) -> Result<reqwest::Response, Failure> {
    let response = client(proxy_port)?.get(url).send().await;
    // Preserve the existing local-proxy/DIRECT fallback, but never restart a
    // partially received file or fall back on HTTP/authentication errors.
    let response = match response {
        Err(error) if proxy_port.is_some() && error.is_connect() => {
            client(None)?.get(url).send().await
        }
        other => other,
    }
    .map_err(|error| Failure::new("network", error.without_url()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Failure::new(
            "network",
            format!("HTTP {}", response.status()),
        ));
    }
    Ok(response)
}

fn hash_matches(actual: digest::Digest, expected: &str) -> bool {
    let encoded = actual
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    encoded == expected
}

pub async fn execute(
    request: Request,
    cancelled: CancellationToken,
    progress: impl Fn(Value),
) -> Result<Value, Failure> {
    let partial = match &request {
        Request::Download { target, .. } => Some(target.with_extension("part")),
        _ => None,
    };
    let mut owns_partial = false;
    let result = tokio::select! {
        biased;
        _ = cancelled.cancelled() => Err(Failure::new("cancelled", "Download cancelled")),
        result = execute_inner(request, progress, &mut owns_partial) => result,
    };
    if result.is_err()
        && owns_partial
        && let Some(partial) = partial
    {
        let _ = tokio::fs::remove_file(partial).await;
    }
    result
}

async fn execute_inner(
    request: Request,
    progress: impl Fn(Value),
    owns_partial: &mut bool,
) -> Result<Value, Failure> {
    match request {
        Request::Fetch {
            url,
            limit,
            proxy_port,
        } => {
            if limit == 0 || limit > 1024 * 1024 {
                return Err(Failure::new("network", "Invalid metadata size limit"));
            }
            let mut response = response(&url, proxy_port).await?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| Failure::new("network", error.without_url()))?
            {
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Err(Failure::new(
                        "network",
                        "Update metadata exceeds the size limit",
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(json!({"body": BASE64_STANDARD.encode(bytes)}))
        }
        Request::Download {
            url,
            target,
            size,
            sha256,
            proxy_port,
        } => {
            if size == 0
                || sha256.len() != 64
                || !sha256.bytes().all(|c| c.is_ascii_hexdigit())
                || target.exists()
            {
                return Err(Failure::new(
                    "checksum",
                    "Invalid update file identity or destination already exists",
                ));
            }
            let partial = target.with_extension("part");
            let mut response = response(&url, proxy_port).await?;
            if response
                .content_length()
                .is_some_and(|length| length != size)
            {
                return Err(Failure::new(
                    "checksum",
                    "Package size differs from the signed manifest",
                ));
            }
            // Creation and ownership registration are synchronous: cancelling a
            // spawned filesystem operation between these steps could leak a file
            // or accidentally remove another job's partial download.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
                .map_err(|error| Failure::new("install", error))?;
            *owns_partial = true;
            let mut file = tokio::fs::File::from_std(file);
            let mut hash = digest::Context::new(&digest::SHA256);
            let mut received = 0;
            let started = Instant::now();
            let mut reported = started;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| Failure::new("network", error.without_url()))?
            {
                if chunk.len() as u64 > size.saturating_sub(received) {
                    return Err(Failure::new("checksum", "Package exceeds the signed size"));
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|error| Failure::new("install", error))?;
                hash.update(&chunk);
                received += chunk.len() as u64;
                if reported.elapsed() >= Duration::from_millis(100) || received == size {
                    progress(json!({"received": received, "total": size,
                        "bytes_per_second": received as f64 / started.elapsed().as_secs_f64().max(0.001)}));
                    reported = Instant::now();
                }
            }
            if received != size || !hash_matches(hash.finish(), &sha256) {
                return Err(Failure::new(
                    "checksum",
                    "Package checksum differs from the signed manifest",
                ));
            }
            file.sync_all()
                .await
                .map_err(|error| Failure::new("install", error))?;
            drop(file);
            tokio::fs::rename(&partial, &target)
                .await
                .map_err(|error| Failure::new("install", error))?;
            *owns_partial = false;
            Ok(json!({"received": received, "total": size, "sha256": sha256}))
        }
        Request::Verify {
            target,
            size,
            sha256,
        } => {
            use tokio::io::AsyncReadExt;
            let mut file = tokio::fs::File::open(&target)
                .await
                .map_err(|error| Failure::new("checksum", error))?;
            let mut hash = digest::Context::new(&digest::SHA256);
            let mut buffer = vec![0; 64 * 1024];
            let mut length = 0;
            loop {
                let count = file
                    .read(&mut buffer)
                    .await
                    .map_err(|error| Failure::new("checksum", error))?;
                if count == 0 {
                    break;
                }
                length += count as u64;
                hash.update(&buffer[..count]);
            }
            if length != size || !hash_matches(hash.finish(), &sha256) {
                return Err(Failure::new(
                    "checksum",
                    "Package checksum differs from the signed manifest",
                ));
            }
            Ok(json!({}))
        }
        Request::VerifySignature {
            body,
            signature: encoded_signature,
            public_key,
        } => {
            let decode = |value: &str| {
                BASE64_STANDARD
                    .decode(value.trim())
                    .map_err(|error| Failure::new("signature", error))
            };
            let body = decode(&body)?;
            signature::UnparsedPublicKey::new(&signature::ED25519, decode(&public_key)?)
                .verify(&body, &decode(&encoded_signature)?)
                .map_err(|_| Failure::new("signature", "Release manifest signature is invalid"))?;
            Ok(json!({}))
        }
    }
}
