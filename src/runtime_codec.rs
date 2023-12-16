use snafu::ResultExt;
use snafu::Snafu;

use crate::{MyAsyncCodecReader, MyAsyncReadExt, MyAsyncWriteExt};

pub struct AsyncReader<T>(T);
pub struct AsyncWriter<T>(T);

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
impl<T: tokio::io::AsyncReadExt + Unpin> MyAsyncReadExt for AsyncReader<T> {
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
impl<T: tokio::io::AsyncWriteExt + Unpin> MyAsyncWriteExt for AsyncWriter<T> {
    async fn write_u32(&mut self, n: u32) -> crate::Result<(), std::io::Error> {
        self.0.write_u32(n).await
    }

    async fn write(&mut self, src: &[u8]) -> crate::Result<usize, std::io::Error> {
        self.0.write(src).await
    }

    async fn write_all(&mut self, src: &[u8]) -> crate::Result<(), std::io::Error> {
        self.0.write_all(src).await
    }
}

#[repr(u8)]
pub enum Pattern {
    Normal,
    Decrypt,
    Encrypt,
}

#[derive(Debug, Snafu)]
pub enum CodecError {
    #[snafu(display("Normal reader errror"))]
    Normal { source: std::io::Error },
}

pub struct AsyncReaderCodec<const PATTERN: u8, T> {
    reader: T,
    buffer: Vec<u8>,
    need_resize: usize,
}

const INIT_BUF_SIZE: usize = 8 * 1024;
const MAX_BUF_SIZE: usize = 8 * 1024 * 1024;

impl<const PATTERN: u8, T> AsyncReaderCodec<PATTERN, T>
where
    T: MyAsyncReadExt + Unpin,
{
    pub fn new(reader: T) -> Self {
        Self {
            reader,
            buffer: vec![0; INIT_BUF_SIZE],
            need_resize: INIT_BUF_SIZE,
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
        //扩容
        if n == self.buffer.len() {
            self.need_resize = n * 2;
        }
        //缩容
        else if n != 0 && n < INIT_BUF_SIZE && self.need_resize > INIT_BUF_SIZE {
            self.need_resize = INIT_BUF_SIZE;
        }
    }

    async fn read_with_encrypt(&mut self) -> crate::Result<&[u8]> {
        todo!()
    }

    async fn read_with_decrypt(&mut self) -> crate::Result<&[u8]> {
        todo!()
    }

    async fn read_norlmal(&mut self) -> crate::Result<&[u8]> {
        if self.need_resize != self.buffer.len() {
            self.resize()
        }
        let n = self
            .reader
            .read(&mut self.buffer)
            .await
            .context(NormalSnafu)
            .map_err(|e| super::Error::Codec { source: e })?;
        self.update_need_resize(n);
        Ok(&self.buffer[0..n])
    }
}

macro_rules! make_codec {
    ($pattern:expr,$codec_method:ident,$new_func:ident) => {
        impl<T: MyAsyncReadExt + Unpin> MyAsyncCodecReader
            for AsyncReaderCodec<{ $pattern as u8 }, T>
        {
            async fn codec(&mut self) -> crate::Result<&[u8]> {
                self.$codec_method().await
            }
        }
        pub fn $new_func<T: MyAsyncReadExt + Unpin>(
            reader: T,
        ) -> AsyncReaderCodec<{ $pattern as u8 }, T> {
            AsyncReaderCodec::<{ $pattern as u8 }, _>::new(reader)
        }
    };
}

make_codec! {Pattern::Normal,read_norlmal,new_normal_codec}
make_codec! {Pattern::Encrypt,read_with_encrypt,new_encrypt_codec}
make_codec! {Pattern::Decrypt,read_with_decrypt,new_decrypt_codec}
