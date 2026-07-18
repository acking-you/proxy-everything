//! Proxy-Core: Core library for proxy-everything.
//!
//! This crate provides the core functionality for the proxy system:
//! - Cryptographic primitives (AES-256-GCM)
//! - Wire protocol definitions
//! - Stream codecs (encrypt/decrypt/normal)
//! - Configuration management
//! - Metrics and node management
//! - Control plane protocol
//! - Transport utilities

// ============================================================================
// Public modules
// ============================================================================

pub mod allocator;
pub mod codec;
pub mod config;
pub mod control;
pub mod crypto;
pub mod datagram;
pub mod error;
pub mod geo;
pub mod metrics;
pub mod nodes;
pub mod protocol;
pub mod relay;
pub mod transport;
pub mod util;

// ============================================================================
// Re-exports for public API
// ============================================================================

pub use crypto::{
    Aes256GcmCryption, Aes256GcmDecryptor, Aes256GcmEncryptor, Decryptor, Encryptor, RingResult,
};
pub use error::{ProxyError, Result};
pub use protocol::{
    DataSize, MAX_DATA_SIZE, ProxyHeader, ProxyTransport, get_data_size, set_data_size,
};

// ============================================================================
// Async I/O Traits
// ============================================================================

/// Async read extension trait.
///
/// Provides a runtime-agnostic interface for async read operations,
/// allowing the codebase to potentially support multiple async runtimes.
pub trait MyAsyncReadExt {
    /// Reads a big-endian u32.
    fn read_u32(
        &mut self,
    ) -> impl std::future::Future<Output = std::result::Result<u32, std::io::Error>> + Send;

    /// Reads into buffer, returning bytes read.
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = std::result::Result<usize, std::io::Error>> + Send;

    /// Reads exactly enough bytes to fill the buffer.
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = std::result::Result<usize, std::io::Error>> + Send;
}

/// Async write extension trait.
///
/// Provides a runtime-agnostic interface for async write operations.
pub trait MyAsyncWriteExt {
    /// Writes a big-endian u32.
    fn write_u32(
        &mut self,
        n: u32,
    ) -> impl std::future::Future<Output = std::result::Result<(), std::io::Error>> + Send;

    /// Writes all bytes from the buffer.
    fn write_all(
        &mut self,
        src: &[u8],
    ) -> impl std::future::Future<Output = std::result::Result<(), std::io::Error>> + Send;

    /// Shuts down the writer (best-effort for half-close).
    fn shutdown(
        &mut self,
    ) -> impl std::future::Future<Output = std::result::Result<(), std::io::Error>> + Send {
        async { Ok(()) }
    }
}

/// Async codec reader trait.
///
/// Provides streaming read with optional encoding/decoding transformation.
pub trait MyAsyncCodecReader {
    /// The item type returned by codec operations.
    type Item<'a>
    where
        Self: 'a;

    /// Reads and decodes the next chunk of data.
    fn codec(&mut self) -> impl std::future::Future<Output = Result<Self::Item<'_>>> + Send;

    /// Reads, decodes, and writes to the given writer.
    fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> impl std::future::Future<Output = Result<DataSize>> + Send;
}

// ============================================================================
// Proxy Result Handling
// ============================================================================

/// Logs the result of a proxy operation.
///
/// Used for consistent logging of proxy completion or errors.
pub fn proxy_result_handle(host: impl AsRef<str>, ret: Result<DataSize>, detail: &'static str) {
    match ret {
        Ok(n) => tracing::info!(
            "Transferred {n} bytes, detail:{detail} host:{}",
            host.as_ref()
        ),
        Err(e) => {
            if e.is_expected_disconnect() {
                tracing::debug!(
                    "Proxy closed by peer: {}, detail:{detail} host:{}",
                    crate::util::error_report(&e),
                    host.as_ref()
                );
            } else {
                tracing::error!(
                    "Proxy error: {}, detail:{detail} host:{}",
                    crate::util::error_report(&e),
                    host.as_ref()
                );
            }
        }
    }
}

struct ProxyDirectionResults {
    client_to_server: Option<Result<DataSize>>,
    server_to_client: Option<Result<DataSize>>,
}

/// Drive both relay directions while preserving a clean TCP half-close.
///
/// A clean EOF shuts down the opposite writer inside [`codec::copy`], so the
/// peer direction is allowed to drain. An I/O error cannot make that progress:
/// waiting for the other future would retain both socket halves indefinitely,
/// which accumulates `CLOSE_WAIT` connections after peer resets. Dropping the
/// other future immediately closes its reader and writer halves.
async fn drive_proxy_directions<ClientToServer, ServerToClient>(
    client_to_server: ClientToServer,
    server_to_client: ServerToClient,
) -> ProxyDirectionResults
where
    ClientToServer: std::future::Future<Output = Result<DataSize>>,
    ServerToClient: std::future::Future<Output = Result<DataSize>>,
{
    tokio::pin!(client_to_server);
    tokio::pin!(server_to_client);

    tokio::select! {
        client_result = &mut client_to_server => {
            if client_result.is_err() {
                return ProxyDirectionResults {
                    client_to_server: Some(client_result),
                    server_to_client: None,
                };
            }
            ProxyDirectionResults {
                client_to_server: Some(client_result),
                server_to_client: Some(server_to_client.await),
            }
        }
        server_result = &mut server_to_client => {
            if server_result.is_err() {
                return ProxyDirectionResults {
                    client_to_server: None,
                    server_to_client: Some(server_result),
                };
            }
            ProxyDirectionResults {
                client_to_server: Some(client_to_server.await),
                server_to_client: Some(server_result),
            }
        }
    }
}

// ============================================================================
// Codec Factory Functions
// ============================================================================

/// Creates a decryption codec for the given reader and key.
pub fn get_decryptor_codec<R: MyAsyncReadExt + Unpin>(
    key: &impl AsRef<str>,
    reader: R,
) -> Result<codec::AsyncDecryptCodec<R, Aes256GcmDecryptor>> {
    Ok(codec::AsyncDecryptCodec::new(
        reader,
        Aes256GcmDecryptor::try_new(key.as_ref().as_bytes()).map_err(|e| ProxyError::Crypto {
            detail: format!("{e}"),
        })?,
    ))
}

/// Creates an encryption codec for the given reader and key.
pub fn get_encryptor_codec<R: MyAsyncReadExt + Unpin>(
    key: impl AsRef<str>,
    reader: R,
) -> Result<codec::AsyncEncryptCodec<R, Aes256GcmEncryptor>> {
    Ok(codec::AsyncEncryptCodec::new(
        reader,
        Aes256GcmEncryptor::try_new(key.as_ref().as_bytes()).map_err(|e| ProxyError::Crypto {
            detail: format!("{e}"),
        })?,
    ))
}

// ============================================================================
// Bidirectional Proxy Functions
// ============================================================================

/// Starts bidirectional proxy between client and server.
///
/// This is the core proxy loop that copies data in both directions
/// until one side closes the connection.
pub async fn start_proxy<
    ClientCodec: MyAsyncCodecReader + Send + Unpin,
    ServerCodec: MyAsyncCodecReader + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    client_codec: ClientCodec,
    server_codec: ServerCodec,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    let client_to_server = codec::copy(client_codec, server_writer);
    let server_to_client = codec::copy(server_codec, client_writer);

    let results = drive_proxy_directions(client_to_server, server_to_client).await;
    if let Some(client_result) = results.client_to_server {
        proxy_result_handle(&host, client_result, "client->server");
    } else {
        tracing::debug!(
            host = host.as_ref(),
            direction = "client->server",
            "relay direction canceled after the peer direction failed"
        );
    }
    if let Some(server_result) = results.server_to_client {
        proxy_result_handle(&host, server_result, "server->client");
    } else {
        tracing::debug!(
            host = host.as_ref(),
            direction = "server->client",
            "relay direction canceled after the peer direction failed"
        );
    }
    Ok(())
}

/// Client-side proxy with encryption.
///
/// Encrypts data from client before sending to server,
/// decrypts data from server before sending to client.
///
/// # Data Flow
///
/// ```text
/// Client ──► [encrypt] ──► Server
/// Client ◄── [decrypt] ◄── Server
/// ```
pub async fn client_proxy_with_cryptor_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    key: &impl AsRef<str>,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    tracing::info!("Client proxy starting with session key:{}", key.as_ref());
    start_proxy(
        host,
        get_encryptor_codec(key, client_reader)?,
        get_decryptor_codec(key, server_reader)?,
        client_writer,
        server_writer,
    )
    .await
}

/// Server-side proxy with decryption.
///
/// Decrypts data from client, encrypts data to client.
/// This is the inverse of `client_proxy_with_cryptor_codec`.
///
/// # Data Flow
///
/// ```text
/// Client ──► [decrypt] ──► Destination
/// Client ◄── [encrypt] ◄── Destination
/// ```
#[allow(dead_code)]
pub async fn server_proxy_with_cryptor_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    key: &impl AsRef<str>,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    tracing::info!("Server proxy starting with session key:{}", key.as_ref());
    start_proxy(
        host,
        get_decryptor_codec(key, client_reader)?,
        get_encryptor_codec(key, server_reader)?,
        client_writer,
        server_writer,
    )
    .await
}

/// Plain proxy without encryption.
///
/// Used for direct connections that don't require encryption,
/// such as local traffic or already-encrypted protocols.
pub async fn proxy_with_normal_codec<
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    client_reader: R,
    server_reader: R,
    client_writer: W,
    server_writer: W,
) -> Result<()> {
    start_proxy(
        host,
        codec::AsyncNormalCodec::new(client_reader),
        codec::AsyncNormalCodec::new(server_reader),
        client_writer,
        server_writer,
    )
    .await
}

// Backward compatibility alias
pub use proxy_with_normal_codec as proxy_with_norlmal_codec;

#[cfg(test)]
mod tests {
    use std::future;
    use std::time::Duration;

    use super::*;

    fn reset_error() -> ProxyError {
        ProxyError::CodecRead {
            source: std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "peer reset test connection",
            ),
        }
    }

    #[tokio::test]
    async fn relay_error_cancels_pending_peer_direction() {
        assert!(reset_error().is_expected_disconnect());
        let results = tokio::time::timeout(
            Duration::from_millis(100),
            drive_proxy_directions(
                future::ready(Err(reset_error())),
                future::pending::<Result<DataSize>>(),
            ),
        )
        .await
        .expect("relay error must not wait for the peer direction");

        assert!(matches!(
            results.client_to_server,
            Some(Err(ProxyError::CodecRead { .. }))
        ));
        assert!(results.server_to_client.is_none());
    }

    #[tokio::test]
    async fn clean_half_close_drains_peer_direction() {
        let results = drive_proxy_directions(future::ready(Ok(11)), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(17)
        })
        .await;

        assert!(matches!(results.client_to_server, Some(Ok(11))));
        assert!(matches!(results.server_to_client, Some(Ok(17))));
    }
}
