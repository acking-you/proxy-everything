//! Shared legacy-compatible message framing for control and datagram streams.

use super::{current_checksum_key, encode_data_size, validate_data_size};
use crate::crypto::{Decryptor, Encryptor};
use crate::{Aes256GcmDecryptor, Aes256GcmEncryptor, MyAsyncReadExt, MyAsyncWriteExt, ProxyError};

const PREFIX_LEN: usize = 8;

fn protocol_error(detail: &'static str) -> ProxyError {
    ProxyError::Protocol {
        detail: detail.into(),
    }
}

fn io_error(source: std::io::Error) -> ProxyError {
    ProxyError::ProtocolIo {
        detail: "message frame".into(),
        source,
    }
}

/// Cancellation-safe, bounded message reader using the existing wire framing.
pub struct FrameReader<R> {
    reader: R,
    decryptor: Option<Aes256GcmDecryptor>,
    checksum_key: u32,
    limit: usize,
    prefix: [u8; PREFIX_LEN],
    prefix_read: usize,
    body_read: usize,
    buffer: Vec<u8>,
    failed: bool,
}

impl<R: MyAsyncReadExt + Send + Unpin> FrameReader<R> {
    /// Snapshot the connection checksum and optional legacy payload key.
    /// `limit` bounds the wire body, including any authentication tag.
    pub fn new(reader: R, key: Option<&str>, limit: usize) -> crate::Result<Self> {
        let decryptor = key
            .map(|key| Aes256GcmDecryptor::try_new(key.as_bytes()))
            .transpose()
            .map_err(|_| protocol_error("invalid frame decryption key"))?;
        Ok(Self {
            reader,
            decryptor,
            checksum_key: current_checksum_key(),
            limit,
            prefix: [0; PREFIX_LEN],
            prefix_read: 0,
            body_read: 0,
            buffer: Vec::new(),
            failed: false,
        })
    }

    /// Progress belongs to this reader, so dropping the future is harmless.
    /// The returned plaintext borrows the reusable buffer until the next read.
    pub async fn read(&mut self) -> crate::Result<Option<&[u8]>> {
        if self.failed {
            return Err(protocol_error("message reader is closed after an error"));
        }
        match self.read_inner().await {
            Ok(Some(length)) => Ok(Some(&self.buffer[..length])),
            Ok(None) => Ok(None),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    async fn read_inner(&mut self) -> crate::Result<Option<usize>> {
        while self.prefix_read < PREFIX_LEN {
            let n = self
                .reader
                .read(&mut self.prefix[self.prefix_read..])
                .await
                .map_err(io_error)?;
            if n == 0 {
                if self.prefix_read == 0 {
                    return Ok(None);
                }
                return Err(io_error(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.prefix_read += n;
            if self.prefix_read == PREFIX_LEN {
                let checksum =
                    u32::from_be_bytes(self.prefix[..4].try_into().expect("fixed prefix"));
                let size = u32::from_be_bytes(self.prefix[4..].try_into().expect("fixed prefix"));
                let size = validate_data_size(checksum, size, self.checksum_key)? as usize;
                if size == 0 || size > self.limit {
                    return Err(protocol_error("invalid message frame size"));
                }
                self.buffer.resize(size, 0);
            }
        }
        while self.body_read < self.buffer.len() {
            let n = self
                .reader
                .read(&mut self.buffer[self.body_read..])
                .await
                .map_err(io_error)?;
            if n == 0 {
                return Err(io_error(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.body_read += n;
        }
        let length = match &mut self.decryptor {
            Some(decryptor) => decryptor
                .decrypt_with_tag(&mut self.buffer)
                .map_err(|_| protocol_error("message frame authentication failed"))?
                .len(),
            None => self.buffer.len(),
        };
        self.prefix_read = 0;
        self.body_read = 0;
        Ok(Some(length))
    }
}

/// Reusable message buffer with a single coalesced write per frame.
pub struct FrameWriter<W> {
    writer: W,
    encryptor: Option<Aes256GcmEncryptor>,
    checksum_key: u32,
    limit: usize,
    buffer: Vec<u8>,
    interrupted: bool,
}

impl<W: MyAsyncWriteExt + Send + Unpin> FrameWriter<W> {
    /// Snapshot the connection checksum and optional legacy payload key.
    /// `limit` bounds the wire body, including any authentication tag.
    pub fn new(writer: W, key: Option<&str>, limit: usize) -> crate::Result<Self> {
        let encryptor = key
            .map(|key| Aes256GcmEncryptor::try_new(key.as_bytes()))
            .transpose()
            .map_err(|_| protocol_error("invalid frame encryption key"))?;
        Ok(Self {
            writer,
            encryptor,
            checksum_key: current_checksum_key(),
            limit: limit.min(super::MAX_DATA_SIZE as usize),
            buffer: Vec::new(),
            interrupted: false,
        })
    }

    /// Serialize directly after the prefix, reusing the previous allocation.
    /// Append the payload to the returned buffer; retain its existing prefix.
    pub fn prepare(&mut self) -> crate::Result<&mut Vec<u8>> {
        if self.interrupted {
            return Err(protocol_error(
                "message writer is closed after an interrupted send",
            ));
        }
        self.buffer.clear();
        self.buffer.resize(PREFIX_LEN, 0);
        Ok(&mut self.buffer)
    }

    /// Encrypt and send the prepared frame. Cancellation makes this writer
    /// terminal, since a partial frame cannot safely be followed by another.
    pub async fn send(&mut self) -> crate::Result<()> {
        if self.interrupted {
            return Err(protocol_error(
                "message writer is closed after an interrupted send",
            ));
        }
        // A cancelled write_all may have emitted a partial frame. Poison the
        // writer until this entire send completes; never append a new frame.
        self.interrupted = true;
        let length = self.buffer.len().saturating_sub(PREFIX_LEN);
        let tag_len = if self.encryptor.is_some() { 16 } else { 0 };
        if length == 0 || length.saturating_add(tag_len) > self.limit {
            return Err(protocol_error("invalid outgoing message frame size"));
        }
        if let Some(encryptor) = &mut self.encryptor {
            let tag = encryptor
                .encrypt(&mut self.buffer[PREFIX_LEN..])
                .map_err(|_| protocol_error("message frame encryption failed"))?;
            self.buffer.extend_from_slice(tag.as_ref());
        }
        let length = (self.buffer.len() - PREFIX_LEN) as u32;
        self.buffer[..PREFIX_LEN].copy_from_slice(&encode_data_size(length, self.checksum_key));
        self.writer
            .write_all(&self.buffer)
            .await
            .map_err(io_error)?;
        self.interrupted = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::codec::{AsyncReader, AsyncWriter};

    #[derive(Default)]
    struct Capture {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl MyAsyncWriteExt for Capture {
        async fn write_u32(&mut self, n: u32) -> std::io::Result<()> {
            self.write_all(&n.to_be_bytes()).await
        }

        async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    async fn frames(key: Option<&str>, packets: &[&[u8]]) -> Vec<u8> {
        let mut writer = FrameWriter::new(Capture::default(), key, 1024).unwrap();
        for packet in packets {
            writer.prepare().unwrap().extend_from_slice(packet);
            writer.send().await.unwrap();
        }
        assert_eq!(writer.writer.writes, packets.len());
        writer.writer.bytes
    }

    #[tokio::test]
    async fn coalesced_frames_keep_the_historical_wire_format_and_counters() {
        for key in [None, Some("01234567890123456789012345678901")] {
            let packets: &[&[u8]] = &[b"first message", b"second message"];
            let wire = frames(key, packets).await;
            let mut input = wire.as_slice();
            let mut decryptor = key.map(|key| Aes256GcmDecryptor::try_new(key.as_bytes()).unwrap());
            for packet in packets {
                // Independent historical reader: two u32 fields then an
                // optional legacy AEAD body. Record layout must not change.
                let checksum = u32::from_be_bytes(input[..4].try_into().unwrap());
                let size = u32::from_be_bytes(input[4..8].try_into().unwrap()) as usize;
                assert_eq!(checksum, size as u32 ^ current_checksum_key());
                let mut body = input[8..8 + size].to_vec();
                let plain = match &mut decryptor {
                    Some(decryptor) => decryptor.decrypt_with_tag(&mut body).unwrap(),
                    None => body.as_mut_slice(),
                };
                assert_eq!(plain, *packet);
                input = &input[8 + size..];
            }
            assert!(input.is_empty());
            let mut reader =
                FrameReader::new(AsyncReader::new(wire.as_slice()), key, 1024).unwrap();
            for packet in packets {
                assert_eq!(reader.read().await.unwrap().unwrap(), *packet);
            }
            assert!(reader.read().await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_reads_keep_every_prefix_and_body_boundary() {
        for key in [None, Some("01234567890123456789012345678901")] {
            let wire = frames(key, &[b"fragmented", b"following"]).await;
            let first_length = 8 + 10 + if key.is_some() { 16 } else { 0 };
            for split in 1..first_length {
                let (mut sender, stream) = tokio::io::duplex(128);
                let mut reader = FrameReader::new(AsyncReader::new(stream), key, 1024).unwrap();
                sender.write_all(&wire[..split]).await.unwrap();
                assert!(futures::poll!(Box::pin(reader.read())).is_pending());
                sender.write_all(&wire[split..]).await.unwrap();
                assert_eq!(reader.read().await.unwrap().unwrap(), b"fragmented");
                assert_eq!(reader.read().await.unwrap().unwrap(), b"following");
            }
        }
    }

    #[tokio::test]
    async fn partial_frame_eof_and_invalid_lengths_are_terminal() {
        let wire = frames(None, &[b"body"]).await;
        for split in 1..wire.len() {
            let mut reader =
                FrameReader::new(AsyncReader::new(&wire[..split]), None, 1024).unwrap();
            assert!(reader.read().await.is_err());
            assert!(reader.read().await.is_err());
        }
        for length in [0, 1025, u32::MAX] {
            let prefix = encode_data_size(length, current_checksum_key());
            let mut reader =
                FrameReader::new(AsyncReader::new(prefix.as_slice()), None, 1024).unwrap();
            assert!(reader.read().await.is_err());
            assert_eq!(reader.buffer.capacity(), 0);
        }
    }

    #[tokio::test]
    async fn cancelled_frame_send_cannot_be_followed_by_a_new_message() {
        let (stream, _reader) = tokio::io::duplex(4);
        let mut writer = FrameWriter::new(AsyncWriter::new(stream), None, 1024).unwrap();
        writer
            .prepare()
            .unwrap()
            .extend_from_slice(b"partially emitted");
        assert!(futures::poll!(Box::pin(writer.send())).is_pending());
        assert!(writer.prepare().is_err());
        assert!(writer.send().await.is_err());
    }
}
