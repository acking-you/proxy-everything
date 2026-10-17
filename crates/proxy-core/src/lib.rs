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
pub mod diagnostics;
pub mod error;
pub mod geo;
pub mod metrics;
pub mod nodes;
pub mod protocol;
pub mod relay;
pub mod rlimit;
pub mod secure_transport;
pub mod session;
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

    /// Reads, transforms, and writes a chunk; returns forwarded payload bytes.
    /// Codec framing and authentication tags are excluded from this count.
    fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> impl std::future::Future<Output = Result<DataSize>> + Send;
}

pub mod forward;
pub use forward::*;
