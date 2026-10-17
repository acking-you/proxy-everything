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
use snafu::ResultExt;

use crate::crypto::{Decryptor, Encryptor};
use crate::error::{IoSnafu, ProxyError};
use crate::protocol::{
    DataSize, FrameReader, MAX_DATA_SIZE, current_checksum_key, set_data_size_with_key,
};
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

    /// Replay already-read bytes through the same codec as the remaining stream.
    pub fn prepend(
        self,
        prefix: Vec<u8>,
    ) -> AsyncReader<tokio::io::Chain<std::io::Cursor<Vec<u8>>, T>> {
        use tokio::io::AsyncReadExt;
        AsyncReader::new(std::io::Cursor::new(prefix).chain(self.0))
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
impl<T: tokio::io::AsyncReadExt + Send + Unpin> MyAsyncReadExt for AsyncReader<T> {
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
async fn write_and_flush<T: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut T,
    bytes: &[u8],
) -> std::io::Result<()> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncWriteExt + Send + Unpin> MyAsyncWriteExt for AsyncWriter<T> {
    async fn write_u32(&mut self, n: u32) -> std::result::Result<(), std::io::Error> {
        write_and_flush(&mut self.0, &n.to_be_bytes()).await
    }

    async fn write_all(&mut self, src: &[u8]) -> std::result::Result<(), std::io::Error> {
        write_and_flush(&mut self.0, src).await
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
        write_and_flush(self.0, &n.to_be_bytes()).await
    }

    async fn write_all(&mut self, src: &[u8]) -> std::result::Result<(), std::io::Error> {
        write_and_flush(self.0, src).await
    }

    async fn shutdown(&mut self) -> std::result::Result<(), std::io::Error> {
        self.0.shutdown().await
    }
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
/// 32MB|                    ┌─────────────────── MAX_BUF_SIZE
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
/// - Maximum size: 32MB (MAX_BUF_SIZE)
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
const MAX_BUF_SIZE: usize = 32 * 1024 * 1024;
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

    async fn read_with_limit(&mut self, limit: usize) -> crate::Result<&mut [u8]> {
        let next_len = self.need_resize.min(limit);
        if next_len != self.buffer.len() {
            self.buffer.resize(next_len, 0);
        }
        let n = self
            .reader
            .read(&mut self.buffer)
            .await
            .map_err(|e| ProxyError::CodecRead { source: e })?;
        self.update_need_resize(n);
        Ok(&mut self.buffer[0..n])
    }
}

impl<T: MyAsyncReadExt + Send + Unpin> MyAsyncCodecReader for AsyncNormalCodec<T> {
    type Item<'a>
        = &'a mut [u8]
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<Self::Item<'_>> {
        self.read_with_limit(MAX_BUF_SIZE).await
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
    frame: FrameReader<T, D>,
}

impl<T: MyAsyncReadExt + Send + Unpin, D: Decryptor + Send + Unpin> AsyncDecryptCodec<T, D> {
    pub fn new(reader: T, decryptor: D) -> Self {
        Self::with_limit(reader, decryptor, MAX_DATA_SIZE as usize)
    }

    pub fn with_limit(reader: T, decryptor: D, limit: usize) -> Self {
        Self {
            frame: FrameReader::with_decryptor(reader, Some(decryptor), limit),
        }
    }
}

impl<T: MyAsyncReadExt + Send + Unpin, D: Decryptor + Send + Unpin> MyAsyncCodecReader
    for AsyncDecryptCodec<T, D>
{
    type Item<'a>
        = &'a [u8]
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<&[u8]> {
        Ok(self.frame.read().await?.unwrap_or_default())
    }

    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> crate::Result<DataSize> {
        let data = self.codec().await?;
        if data.is_empty() {
            return Ok(0);
        }
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
    checksum_key: u32,
}

impl<T: MyAsyncReadExt + Unpin, E: Encryptor + Unpin> AsyncEncryptCodec<T, E> {
    pub fn new(reader: T, encryptor: E) -> Self {
        Self {
            codec_normal: AsyncNormalCodec::new(reader),
            encryptor,
            checksum_key: current_checksum_key(),
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
        // The legacy receiver bounds ciphertext plus tag, not just plaintext.
        let raw_data = self
            .codec_normal
            .read_with_limit(MAX_DATA_SIZE as usize - TAG_LEN)
            .await?;
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
        let checksum_key = self.checksum_key;
        let (data, tag) = self.codec().await?;
        if data.is_empty() {
            return Ok(0);
        }

        // Write length prefix, ciphertext, and tag
        let length = (data.len() + tag.as_ref().len()) as DataSize;
        set_data_size_with_key(writer, length, checksum_key).await?;
        writer.write_all(data).await.context(IoSnafu {
            context: "encrypt_write",
            detail: "write data".to_string(),
        })?;
        writer.write_all(tag.as_ref()).await.context(IoSnafu {
            context: "encrypt_write",
            detail: "write tag".to_string(),
        })?;
        Ok(data.len() as DataSize)
    }
}

// ============================================================================
// Copy Function
// ============================================================================

/// Copies data from a codec reader to a writer until EOF.
///
/// Returns the total number of bytes transferred.
pub async fn copy<R: MyAsyncCodecReader + Send + Unpin, W: MyAsyncWriteExt + Send + Unpin>(
    reader: R,
    writer: W,
) -> crate::Result<u64> {
    copy_with_observer(reader, writer, |_| {}).await
}

/// One transfer loop for client and server. The no-op observer compiles away;
/// metrics callers can observe progress without a second implementation.
pub async fn copy_with_observer<
    R: MyAsyncCodecReader + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
    F: FnMut(u64) + Send,
>(
    mut reader: R,
    mut writer: W,
    mut progress: F,
) -> crate::Result<u64> {
    let mut total = 0u64;
    loop {
        let n = reader.codec_and_write(&mut writer).await?;
        if n == 0 {
            break;
        }
        total += u64::from(n);
        progress(total);
    }
    // A secure stream may still need to send its authenticated EOF. A failed
    // shutdown must not turn an incomplete transfer into a reported success.
    writer.shutdown().await.map_err(|source| ProxyError::Io {
        context: "relay",
        detail: "half-close destination".into(),
        source,
    })?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn large_encrypted_transfers_respect_the_legacy_frame_limit() {
        use tokio::io::AsyncReadExt;

        let key = b"01234567890123456789012345678901";
        let length = 3 * MAX_BUF_SIZE as u64;
        let (sender, receiver) = tokio::io::duplex(64 * 1024);
        let sent = copy(
            AsyncEncryptCodec::new(
                AsyncReader::new(tokio::io::repeat(42).take(length)),
                crate::Aes256GcmEncryptor::try_new(key).unwrap(),
            ),
            AsyncWriter::new(sender),
        );
        let received = copy(
            AsyncDecryptCodec::new(
                AsyncReader::new(receiver),
                crate::Aes256GcmDecryptor::try_new(key).unwrap(),
            ),
            AsyncWriter::new(tokio::io::sink()),
        );
        let totals = tokio::try_join!(sent, received).unwrap();
        assert_eq!(totals, (length, length));
    }

    struct LargeTransfer(u8);
    impl MyAsyncCodecReader for LargeTransfer {
        type Item<'a> = ();

        async fn codec(&mut self) -> crate::Result<()> {
            unreachable!()
        }

        async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
            &mut self,
            _: &mut W,
        ) -> crate::Result<DataSize> {
            if self.0 == 0 {
                return Ok(0);
            }
            self.0 -= 1;
            Ok(1 << 30)
        }
    }

    #[tokio::test]
    async fn transfer_totals_do_not_wrap_or_saturate_at_four_gib() {
        let total = copy(LargeTransfer(5), AsyncWriter::new(Vec::new()))
            .await
            .unwrap();
        assert_eq!(total, 5u64 << 30);
    }
}
