use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use ring::aead::Tag;
use snafu::ResultExt;
use snafu::Snafu;

use crate::get_data_size;
use crate::set_data_size;
use crate::CodecSnafu;
use crate::DataSize;
use crate::Decryptor;
use crate::Encryptor;
use crate::MyAsyncCodecReader;
use crate::WriteDataInProxySnafu;
use crate::{MyAsyncReadExt, MyAsyncWriteExt};

pub struct AsyncReader<T>(T);
pub struct AsyncWriter<T>(T);

pub struct AsyncReaderWriterRef<'a, T>(&'a mut T);

/// For tokio
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

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncReadExt + Send + Unpin + 'static> MyAsyncReadExt for AsyncReader<T> {
    async fn read_u32(&mut self) -> crate::Result<u32, std::io::Error> {
        self.0.read_u32().await
    }

    async fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize, std::io::Error> {
        self.0.read(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> crate::Result<usize, std::io::Error> {
        self.0.read_exact(buf).await
    }
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncWriteExt + Send + Unpin> MyAsyncWriteExt for AsyncWriter<T> {
    async fn write_u32(&mut self, n: u32) -> crate::Result<(), std::io::Error> {
        self.0.write_u32(n).await
    }

    async fn write_all(&mut self, src: &[u8]) -> crate::Result<(), std::io::Error> {
        self.0.write_all(src).await
    }
}

#[cfg(feature = "tokio")]
impl<'a, T: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Send + Unpin> MyAsyncReadExt
    for AsyncReaderWriterRef<'a, T>
{
    async fn read_u32(&mut self) -> crate::Result<u32, std::io::Error> {
        self.0.read_u32().await
    }

    async fn read(&mut self, buf: &mut [u8]) -> crate::Result<usize, std::io::Error> {
        self.0.read(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> crate::Result<usize, std::io::Error> {
        self.0.read_exact(buf).await
    }
}

#[cfg(feature = "tokio")]
impl<'a, T: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Send + Unpin> MyAsyncWriteExt
    for AsyncReaderWriterRef<'a, T>
{
    async fn write_u32(&mut self, n: u32) -> crate::Result<(), std::io::Error> {
        self.0.write_u32(n).await
    }

    async fn write_all(&mut self, src: &[u8]) -> crate::Result<(), std::io::Error> {
        self.0.write_all(src).await
    }
}

#[derive(Debug, Snafu)]
pub enum CodecError {
    #[snafu(display("Normal reader errror"))]
    Normal { source: std::io::Error },
    #[snafu(display("Decrypt error: detail:{detail}"))]
    Decrypt { detail: String },
    #[snafu(display("Encrypt error: detail:{detail}"))]
    Encrypt { detail: String },
}

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
    type Item<'a> = &'a mut [u8]
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
            .context(NormalSnafu)
            .context(CodecSnafu)?;
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
        writer.write_all(src).await.context(WriteDataInProxySnafu {
            detail: "normal write",
        })?;
        Ok(n as DataSize)
    }
}

/// For decrypt codec
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
    type Item<'a> = &'a mut[u8]
    where
        Self: 'a;
    async fn codec(&mut self) -> crate::Result<&mut [u8]> {
        let reader = &mut self.codec_normal.reader;
        let buffer = &mut self.codec_normal.buffer;
        let data_size = get_data_size(reader).await?;
        buffer.resize(data_size as usize, 0);
        reader
            .read_exact(buffer)
            .await
            .context(WriteDataInProxySnafu {
                detail: "decrypt_codec:read_exact datasize",
            })?;
        self.decryptor
            .decrypt_with_tag(buffer)
            .map_err(|e| CodecError::Decrypt {
                detail: format!("{e}"),
            })
            .context(CodecSnafu)
    }

    async fn codec_and_write<W: MyAsyncWriteExt + Send + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> crate::Result<DataSize> {
        let data = self.codec().await?;
        writer
            .write_all(data)
            .await
            .context(WriteDataInProxySnafu {
                detail: "decrypt_write:write data",
            })?;
        Ok(data.len() as DataSize)
    }
}

/// For encrypt codec
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
    type Item<'a> = (&'a[u8],Tag)
    where
        Self: 'a;

    async fn codec(&mut self) -> crate::Result<Self::Item<'_>> {
        let raw_data = self.codec_normal.codec().await?;
        if raw_data.is_empty() {
            return Ok((raw_data, Tag::from([0; TAG_LEN])));
        }
        let tag = self
            .encryptor
            .encrypt(raw_data)
            .map_err(|e| CodecError::Encrypt {
                detail: format!("{}", e),
            })
            .context(CodecSnafu)?;
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
        let length = (data.len() + tag.as_ref().len()) as DataSize;
        set_data_size(writer, length).await?;
        writer
            .write_all(data)
            .await
            .context(WriteDataInProxySnafu {
                detail: "encrypt_write:write data",
            })?;
        writer
            .write_all(tag.as_ref())
            .await
            .context(WriteDataInProxySnafu {
                detail: "encrypt_write:write tag",
            })?;
        Ok(length)
    }
}

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
