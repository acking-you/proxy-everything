//! Stream codecs for proxy data transformation.
//!
//! This module provides streaming codecs that handle reading, optional
//! encryption/decryption, and writing of proxy data.
//!
//! # Codec Types
//!
//! - [`AsyncNormalCodec`]: Plain passthrough with dynamic buffer sizing
//! - [`AsyncEncryptCodec`]: Encrypts data before transmission
//! - [`AsyncDecryptCodec`]: Decrypts received data
//!
//! # Data Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Codec Pipeline                               │
//! │                                                                 │
//! │  Source ──► AsyncReader ──► Codec ──► AsyncWriter ──► Dest     │
//! │                              │                                  │
//! │                              ▼                                  │
//! │                    ┌─────────────────┐                         │
//! │                    │ Normal: pass    │                         │
//! │                    │ Encrypt: seal   │                         │
//! │                    │ Decrypt: open   │                         │
//! │                    └─────────────────┘                         │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use ring::aead::Tag;
use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use snafu::{ResultExt, Snafu};

use crate::crypto::{Decryptor, Encryptor};
use crate::error::{IoSnafu, ProxyError};
use crate::protocol::{DataSize, get_data_size, set_data_size};
use crate::{MyAsyncCodecReader, MyAsyncReadExt, MyAsyncWriteExt};

// ============================================================================
// Async I/O Wrappers
// ============================================================================

/// Async reader wrapper for Tokio streams.
pub struct AsyncReader<T>(T);

/// Async writer wrapper for Tokio streams.
pub struct AsyncWriter<T>(T);

/// Async reader/writer reference wrapper.
///
/// Allows using a single stream for both reading and writing
/// without splitting ownership.
pub struct AsyncReaderWriterRef<'a, T>(&'a mut T);

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncReadExt + Unpin> AsyncReader<T> {
    pub fn new(reader: T) -> Self {
        Self(reader)
    }
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncWriteExt + Unpin> AsyncWriter<T> {
    pub fn new(writer: T) -> Self {
        Self(writer)
    }
}

#[cfg(feature = "tokio")]
impl<'a, T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>
    AsyncReaderWriterRef<'a, T>
{
    pub fn new(stream: &'a mut T) -> Self {
        Self(stream)
    }
}

// ============================================================================
// MyAsyncReadExt Implementations
// ============================================================================

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncReadExt + Send + Unpin + 'static> MyAsyncReadExt for AsyncReader<T> {
    async fn read_u32(&mut self) -> std::result::Result<u32, std::io::Error> {
        self.0.read_u32().await
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.0.read(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.0.read_exact(buf).await
    }
}

#[cfg(feature = "tokio")]
impl<'a, T: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Send + Unpin> MyAsyncReadExt
    for AsyncReaderWriterRef<'a, T>
{
    async fn read_u32(&mut self) -> std::result::Result<u32, std::io::Error> {
        self.0.read_u32().await
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.0.read(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.0.read_exact(buf).await
    }
}

// ============================================================================
// MyAsyncWriteExt Implementations
// ============================================================================

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncWriteExt + Send + Unpin> MyAsyncWriteExt for AsyncWriter<T> {
    async fn write_u32(&mut self, n: u32) -> std::result::Result<(), std::io::Error> {
        self.0.write_u32(n).await
    }

    async fn write_all(&mut self, src: &[u8]) -> std::result::Result<(), std::io::Error> {
        self.0.write_all(src).await
    }

    async fn shutdown(&mut self) -> std::result::Result<(), std::io::Error> {
        self.0.shutdown().await
    }
}

#[cfg(feature = "tokio")]
impl<'a, T: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Send + Unpin> MyAsyncWriteExt
    for AsyncReaderWriterRef<'a, T>
{
    async fn write_u32(&mut self, n: u32) -> std::result::Result<(), std::io::Error> {
        self.0.write_u32(n).await
    }

    async fn write_all(&mut self, src: &[u8]) -> std::result::Result<(), std::io::Error> {
        self.0.write_all(src).await
    }

    async fn shutdown(&mut self) -> std::result::Result<(), std::io::Error> {
        self.0.shutdown().await
    }
}

// ============================================================================
// Codec Error (kept for backward compatibility, may be removed in future)
// ============================================================================

/// Codec-specific error type.
///
/// Retained for backward compatibility. New code should use `ProxyError`.
#[derive(Debug, Snafu)]
#[allow(dead_code)]
pub enum CodecError {
    #[snafu(display("Normal reader error"))]
    Normal { source: std::io::Error },
    #[snafu(display("Decrypt error: {detail}"))]
    Decrypt { detail: String },
    #[snafu(display("Encrypt error: {detail}"))]
    Encrypt { detail: String },
}

// ============================================================================
// AsyncNormalCodec
// ============================================================================

/// Dynamic buffer codec for efficient streaming I/O.
///
/// This codec implements an adaptive buffer sizing strategy to balance memory usage
/// and performance. The buffer automatically grows when data fills it completely,
/// and shrinks after consecutive small reads to avoid holding unnecessary memory.
///
/// # Buffer Sizing Strategy
///
/// ```text
/// Buffer Size
///     ^
/// 8MB |                    ┌─────────────────── MAX_BUF_SIZE
///     |                   /
///     |                  /  ← doubles on full buffer
///     |                 /
///     |                /
///     |               /
///     |              /
/// 512B|─────────────┴────────────────────────── INIT_BUF_SIZE
///     |             ↑
///     |    shrinks to half after 8 consecutive
///     |    small reads (< 25% capacity)
///     └──────────────────────────────────────→ Time
/// ```
///
/// - Initial size: 512B (INIT_BUF_SIZE)
/// - Maximum size: 8MB (MAX_BUF_SIZE)
/// - Expansion: doubles when buffer is completely filled
/// - Shrinking: halves after SHRINK_THRESHOLD (8) consecutive small reads
///
/// The counter-based shrinking prevents thrashing when data sizes fluctuate.
pub struct AsyncNormalCodec<T> {
    reader: T,
    buffer: Vec<u8>,
    need_resize: usize,
    shrink_count: u8,
}

const INIT_BUF_SIZE: usize = 512;
const MAX_BUF_SIZE: usize = 8 * 1024 * 1024;
const SHRINK_THRESHOLD: u8 = 8;

impl<T> AsyncNormalCodec<T>
where
    T: MyAsyncReadExt + Unpin,
{
    pub fn new(reader: T) -> Self {
        Self {
            reader,
            buffer: vec![0; INIT_BUF_SIZE],
            need_resize: INIT_BUF_SIZE,
            shrink_count: 0,
        }
    }

    #[inline]
    fn resize(&mut self) {
        let new_len = if self.need_resize >= MAX_BUF_SIZE {
            MAX_BUF_SIZE
        } else {
            self.need_resize
        };
        self.buffer.resize(new_len, 0);
    }

    #[inline]
    fn update_need_resize(&mut self, n: usize) {
        if n == self.buffer.len() {
            // Buffer full: double the size for next read
            self.need_resize = n * 2;
            self.shrink_count = 0;
        } else if n != 0 && n < self.buffer.len() / 4 && self.buffer.len() > INIT_BUF_SIZE {
            // Small read (< 25% capacity): increment shrink counter
            self.shrink_count = self.shrink_count.saturating_add(1);
            if self.shrink_count >= SHRINK_THRESHOLD {
                // After consecutive small reads, shrink to half (not directly to minimum)
                self.need_resize = (self.buffer.len() / 2).max(INIT_BUF_SIZE);
                self.shrink_count = 0;
            }
        } else {
            // Normal read: reset shrink counter
            self.shrink_count = 0;
        }
    }
}

impl<T: MyAsyncReadExt + Send + Unpin> MyAsyncCodecReader for AsyncNormalCodec<T> {
    type Item<'a>
        = &'a mut [u8]
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<Self::Item<'_>> {
        if self.need_resize != self.buffer.len() {
            self.resize()
        }
        let n = self
            .reader
            .read(&mut self.buffer)
            .await
            .map_err(|e| ProxyError::CodecRead { source: e })?;
        self.update_need_resize(n);
        Ok(&mut self.buffer[0..n])
    }

    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> crate::Result<DataSize> {
        let src = self.codec().await?;
        let n = src.len();
        if n == 0 {
            return Ok(0);
        }
        writer.write_all(src).await.context(IoSnafu {
            context: "codec",
            detail: "normal write".to_string(),
        })?;
        Ok(n as DataSize)
    }
}

// ============================================================================
// AsyncDecryptCodec
// ============================================================================

/// Decryption codec for encrypted streams.
///
/// Reads length-prefixed encrypted data, decrypts it, and returns plaintext.
///
/// # Wire Format
///
/// ```text
/// ┌──────────────┬──────────────┬─────────────────────┬────────────────┐
/// │  Checksum    │   Length     │   Ciphertext        │   Auth Tag     │
/// │  (4 bytes)   │  (4 bytes)   │    (N bytes)        │  (16 bytes)    │
/// └──────────────┴──────────────┴─────────────────────┴────────────────┘
/// ```
pub struct AsyncDecryptCodec<T, D> {
    codec_normal: AsyncNormalCodec<T>,
    decryptor: D,
}

impl<T: MyAsyncReadExt + Unpin, D: Decryptor + Unpin> AsyncDecryptCodec<T, D> {
    pub fn new(reader: T, decryptor: D) -> Self {
        Self {
            codec_normal: AsyncNormalCodec::new(reader),
            decryptor,
        }
    }
}

impl<T: MyAsyncReadExt + Send + Unpin, D: Decryptor + Send + Unpin + 'static> MyAsyncCodecReader
    for AsyncDecryptCodec<T, D>
{
    type Item<'a>
        = &'a mut [u8]
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<&mut [u8]> {
        let reader = &mut self.codec_normal.reader;
        let buffer = &mut self.codec_normal.buffer;

        // Read length-prefixed data
        let data_size = get_data_size(reader).await?;
        buffer.resize(data_size as usize, 0);
        reader.read_exact(buffer).await.context(IoSnafu {
            context: "decrypt_codec",
            detail: "read_exact".to_string(),
        })?;

        // Decrypt in-place
        self.decryptor
            .decrypt_with_tag(buffer)
            .map_err(|e| ProxyError::CodecDecrypt {
                detail: format!("{e}"),
            })
    }

    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> crate::Result<DataSize> {
        let data = self.codec().await?;
        writer.write_all(data).await.context(IoSnafu {
            context: "decrypt_write",
            detail: "write data".to_string(),
        })?;
        Ok(data.len() as DataSize)
    }
}

// ============================================================================
// AsyncEncryptCodec
// ============================================================================

/// Encryption codec for outgoing streams.
///
/// Reads plaintext, encrypts it, and writes length-prefixed ciphertext.
///
/// # Wire Format
///
/// ```text
/// ┌──────────────┬──────────────┬─────────────────────┬────────────────┐
/// │  Checksum    │   Length     │   Ciphertext        │   Auth Tag     │
/// │  (4 bytes)   │  (4 bytes)   │    (N bytes)        │  (16 bytes)    │
/// └──────────────┴──────────────┴─────────────────────┴────────────────┘
/// ```
pub struct AsyncEncryptCodec<T, E> {
    codec_normal: AsyncNormalCodec<T>,
    encryptor: E,
}

impl<T: MyAsyncReadExt + Unpin, E: Encryptor + Unpin> AsyncEncryptCodec<T, E> {
    pub fn new(reader: T, encryptor: E) -> Self {
        Self {
            codec_normal: AsyncNormalCodec::new(reader),
            encryptor,
        }
    }
}

impl<T: MyAsyncReadExt + Send + Unpin, E: Encryptor + Send + Unpin> MyAsyncCodecReader
    for AsyncEncryptCodec<T, E>
{
    type Item<'a>
        = (&'a [u8], Tag)
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<Self::Item<'_>> {
        let raw_data = self.codec_normal.codec().await?;
        if raw_data.is_empty() {
            return Ok((raw_data, Tag::from([0; TAG_LEN])));
        }

        // Encrypt in-place and get auth tag
        let tag = self
            .encryptor
            .encrypt(raw_data)
            .map_err(|e| ProxyError::CodecEncrypt {
                detail: format!("{}", e),
            })?;
        Ok((raw_data, tag))
    }

    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> crate::Result<DataSize> {
        let (data, tag) = self.codec().await?;
        if data.is_empty() {
            return Ok(0);
        }

        // Write length prefix, ciphertext, and tag
        let length = (data.len() + tag.as_ref().len()) as DataSize;
        set_data_size(writer, length).await?;
        writer.write_all(data).await.context(IoSnafu {
            context: "encrypt_write",
            detail: "write data".to_string(),
        })?;
        writer.write_all(tag.as_ref()).await.context(IoSnafu {
            context: "encrypt_write",
            detail: "write tag".to_string(),
        })?;
        Ok(length)
    }
}

// ============================================================================
// Copy Function
// ============================================================================

/// Copies data from a codec reader to a writer until EOF.
///
/// Returns the total number of bytes transferred.
pub async fn copy<R: MyAsyncCodecReader + Send + Unpin, W: MyAsyncWriteExt + Send + Unpin>(
    mut reader: R,
    mut writer: W,
) -> crate::Result<DataSize> {
    let mut length: DataSize = 0;
    loop {
        let n = reader.codec_and_write(&mut writer).await?;
        if n == 0 {
            break;
        }
        length += n;
    }
    Ok(length)
}
