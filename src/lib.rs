//! Proxy-Everything: A secure TCP proxy with AES-256-GCM encryption.
//!
//! This crate provides a three-layer proxy system for secure traffic forwarding:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Proxy Architecture                               │
//! │                                                                         │
//! │  Application ──► Client (local:1080) ──► [encrypted] ──► Server        │
//! │                                                          (remote:1081) │
//! │                                                               │         │
//! │                                                               ▼         │
//! │                                                          Destination    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **HTTP/HTTPS proxy**: Supports CONNECT method for HTTPS tunneling
//! - **SOCKS5 proxy**: Full SOCKS5 protocol implementation
//! - **AES-256-GCM encryption**: Secure traffic between client and server
//! - **Auto-proxy**: Geo-based routing (CN=direct, US/SG/TW/HK/JP=proxy)
//! - **Graceful shutdown**: Proper cleanup on SIGINT/SIGTERM/SIGQUIT
//!
//! # Modules
//!
//! - [`client`]: Client-side proxy implementation
//! - [`server`]: Server-side proxy implementation
//! - [`config`]: Configuration management
//! - [`error`]: Unified error types
//! - [`crypto`]: Cryptographic primitives
//! - [`protocol`]: Wire protocol definitions

// ============================================================================
// Public modules
// ============================================================================

pub mod client;
pub mod config;
pub mod control;
pub mod error;
pub mod geo;
pub mod metrics;
pub mod nodes;
pub mod server;

#[cfg(feature = "tui")]
pub mod tui;

// ============================================================================
// Internal modules
// ============================================================================

pub(crate) mod codec;
pub(crate) mod crypto;
pub(crate) mod protocol;
pub(crate) mod util;

// ============================================================================
// Re-exports for public API
// ============================================================================

pub use crypto::{
    Aes256GcmCryption, Aes256GcmDecryptor, Aes256GcmEncryptor, Decryptor, Encryptor, RingResult,
};
pub use error::{ProxyError, Result};
pub use protocol::{DataSize, MAX_DATA_SIZE, ProxyHeader};

// ============================================================================
// Internal re-exports (for use within the crate)
// ============================================================================

pub(crate) use codec::{AsyncDecryptCodec, AsyncEncryptCodec, AsyncNormalCodec};
pub(crate) use protocol::{get_data_size, set_data_size};

// Note: snafu context types are used in submodules via crate::error

// ============================================================================
// Async I/O Traits
// ============================================================================

/// Async read extension trait.
///
/// Provides a runtime-agnostic interface for async read operations,
/// allowing the codebase to potentially support multiple async runtimes.
pub(crate) trait MyAsyncReadExt {
    /// Reads a big-endian u32.
    async fn read_u32(&mut self) -> std::result::Result<u32, std::io::Error>;

    /// Reads into buffer, returning bytes read.
    async fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error>;

    /// Reads exactly enough bytes to fill the buffer.
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error>;
}

/// Async write extension trait.
///
/// Provides a runtime-agnostic interface for async write operations.
pub(crate) trait MyAsyncWriteExt {
    /// Writes a big-endian u32.
    async fn write_u32(&mut self, n: u32) -> std::result::Result<(), std::io::Error>;

    /// Writes all bytes from the buffer.
    async fn write_all(&mut self, src: &[u8]) -> std::result::Result<(), std::io::Error>;

    /// Shuts down the writer (best-effort for half-close).
    async fn shutdown(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

/// Async codec reader trait.
///
/// Provides streaming read with optional encoding/decoding transformation.
pub(crate) trait MyAsyncCodecReader {
    /// The item type returned by codec operations.
    type Item<'a>
    where
        Self: 'a;

    /// Reads and decodes the next chunk of data.
    async fn codec(&mut self) -> Result<Self::Item<'_>>;

    /// Reads, decodes, and writes to the given writer.
    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<DataSize>;
}

// ============================================================================
// Proxy Result Handling
// ============================================================================

/// Logs the result of a proxy operation.
///
/// Used for consistent logging of proxy completion or errors.
pub(crate) fn proxy_result_handle(
    host: impl AsRef<str>,
    ret: Result<DataSize>,
    detail: &'static str,
) {
    match ret {
        Ok(n) => tracing::info!(
            "Transferred {n} bytes, detail:{detail} host:{}",
            host.as_ref()
        ),
        Err(e) => tracing::error!("Proxy error:{e}, detail:{detail} host:{}", host.as_ref()),
    }
}

// ============================================================================
// Codec Factory Functions
// ============================================================================

/// Creates a decryption codec for the given reader and key.
fn get_decryptor_codec<R: MyAsyncReadExt + Unpin>(
    key: &impl AsRef<str>,
    reader: R,
) -> Result<AsyncDecryptCodec<R, Aes256GcmDecryptor>> {
    Ok(AsyncDecryptCodec::new(
        reader,
        Aes256GcmDecryptor::try_new(key.as_ref().as_bytes()).map_err(|e| ProxyError::Crypto {
            detail: format!("{e}"),
        })?,
    ))
}

/// Creates an encryption codec for the given reader and key.
fn get_encryptor_codec<R: MyAsyncReadExt + Unpin>(
    key: impl AsRef<str>,
    reader: R,
) -> Result<AsyncEncryptCodec<R, Aes256GcmEncryptor>> {
    Ok(AsyncEncryptCodec::new(
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
async fn start_proxy<
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

    // Race both directions - first to complete wins
    tokio::select! {
        ret = client_to_server => {
            proxy_result_handle(&host, ret, "client->server");
        }
        ret = server_to_client => {
            proxy_result_handle(&host, ret, "server->client");
        }
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
pub(crate) async fn client_proxy_with_cryptor_codec<
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
pub(crate) async fn server_proxy_with_cryptor_codec<
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
pub(crate) async fn proxy_with_normal_codec<
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
        AsyncNormalCodec::new(client_reader),
        AsyncNormalCodec::new(server_reader),
        client_writer,
        server_writer,
    )
    .await
}

// Backward compatibility alias
pub(crate) use proxy_with_normal_codec as proxy_with_norlmal_codec;
