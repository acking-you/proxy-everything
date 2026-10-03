//! Version 2 authenticated transport. Both peers contribute fresh randomness;
//! HKDF separates directions and binds the complete handshake. No zero-RTT data
//! is accepted, so a captured request cannot be replayed after a server restart.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, hkdf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

pub const MAGIC: [u8; 4] = *b"PXY2";
const RECORD_LIMIT: usize = 16 * 1024;
const TAG_LEN: usize = 16;
const HELLO_LEN: usize = 40;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn crypto_error(_: ring::error::Unspecified) -> io::Error {
    invalid("v2 transport authentication failed")
}

/// An explicitly selected connection protocol. Legacy is retained only for
/// coordinated migration; authentication failures never trigger fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireProtocol {
    Legacy,
    V2,
}

static WIRE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Set the protocol for subsequent connections in the single-client FFI runtime.
/// Existing streams keep the protocol and keys chosen when they were created.
pub fn set_wire_protocol(protocol: WireProtocol) {
    WIRE_OVERRIDE.store(
        match protocol {
            WireProtocol::Legacy => 1,
            WireProtocol::V2 => 2,
        },
        std::sync::atomic::Ordering::Release,
    );
}

impl WireProtocol {
    pub fn configured() -> io::Result<Self> {
        match WIRE_OVERRIDE.load(std::sync::atomic::Ordering::Acquire) {
            1 => return Ok(Self::Legacy),
            2 => return Ok(Self::V2),
            _ => {}
        }
        match std::env::var("PROXY_WIRE_PROTOCOL").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("legacy") => Ok(Self::Legacy),
            Ok("v2") => Ok(Self::V2),
            _ => Err(invalid("PROXY_WIRE_PROTOCOL must be legacy or v2")),
        }
    }
}

/// TCP or an authenticated transport over TCP. Splitting retains partial record
/// progress in the stream, independently of the lifetime of a read future.
pub enum ProxyStream {
    Plain {
        stream: TcpStream,
        prefix: Vec<u8>,
        position: usize,
    },
    Secure(Box<SecureStream<TcpStream>>),
}
impl From<TcpStream> for ProxyStream {
    fn from(stream: TcpStream) -> Self {
        Self::Plain {
            stream,
            prefix: Vec::new(),
            position: 0,
        }
    }
}
impl ProxyStream {
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }

    pub fn into_split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        tokio::io::split(self)
    }

    pub fn legacy_with_prefix(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self::Plain {
            stream,
            prefix,
            position: 0,
        }
    }
}
impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain {
                stream,
                prefix,
                position,
            } => {
                if *position < prefix.len() && buf.remaining() > 0 {
                    let n = buf.remaining().min(prefix.len() - *position);
                    buf.put_slice(&prefix[*position..*position + n]);
                    *position += n;
                    Poll::Ready(Ok(()))
                } else {
                    Pin::new(stream).poll_read(cx, buf)
                }
            }
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_write(cx, buf),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_flush(cx),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain { stream, .. } => Pin::new(stream).poll_shutdown(cx),
            Self::Secure(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Send a versioned hello and wait for the server's fresh challenge.
/// The caller must bound the complete handshake, including the first header.
pub async fn connect_v2<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    key: &[u8],
    control: bool,
) -> io::Result<SecureStream<T>> {
    let mut hello = [0u8; HELLO_LEN];
    hello[..4].copy_from_slice(&MAGIC);
    hello[4] = 2;
    hello[5] = u8::from(control);
    SystemRandom::new()
        .fill(&mut hello[8..])
        .map_err(crypto_error)?;
    stream.write_all(&hello).await?;
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).await?;
    SecureStream::new(stream, key, &hello, &challenge, true)
}

/// Accept a v2 hello whose eight-byte preface was already consumed.
pub async fn accept_v2<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    key: &[u8],
    preface: [u8; 8],
) -> io::Result<(SecureStream<T>, bool)> {
    let mut hello = [0u8; HELLO_LEN];
    hello[..8].copy_from_slice(&preface);
    if hello[..4] != MAGIC || hello[4] != 2 || hello[5] > 1 || hello[6..8] != [0, 0] {
        return Err(invalid("unsupported v2 hello flags"));
    }
    stream.read_exact(&mut hello[8..]).await?;
    let mut challenge = [0u8; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(crypto_error)?;
    stream.write_all(&challenge).await?;
    Ok((
        SecureStream::new(stream, key, &hello, &challenge, false)?,
        hello[5] == 1,
    ))
}

struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}
fn derive(
    key: &[u8],
    hello: &[u8; HELLO_LEN],
    challenge: &[u8; 32],
    label: &[u8],
) -> io::Result<aead::LessSafeKey> {
    if key.len() != 32 {
        return Err(invalid("v2 transport needs a 32-byte secret key"));
    }
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&hello[8..]);
    salt[32..].copy_from_slice(challenge);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(key);
    let info = [b"proxy-everything-v2".as_slice(), &hello[..8], label];
    let mut material = [0u8; 32];
    prk.expand(&info, KeyLength)
        .map_err(crypto_error)?
        .fill(&mut material)
        .map_err(crypto_error)?;
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &material).map_err(crypto_error)?,
    ))
}
fn nonce(sequence: u64) -> aead::Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    aead::Nonce::assume_unique_for_key(nonce)
}
fn aad(sequence: u64, length: u32) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[..8].copy_from_slice(&sequence.to_be_bytes());
    aad[8..].copy_from_slice(&length.to_be_bytes());
    aad
}

/// Bounded authenticated records with separate direction keys, monotonic
/// counters, authenticated EOF, and terminal errors. Buffers own all partial
/// I/O progress so cancellation never resets a nonce or loses framing bytes.
pub struct SecureStream<T> {
    inner: T,
    seal: aead::LessSafeKey,
    open: aead::LessSafeKey,
    send_sequence: u64,
    recv_sequence: u64,
    outgoing: Vec<u8>,
    outgoing_position: usize,
    outgoing_plain: Vec<u8>,
    header: [u8; 4],
    header_position: usize,
    incoming: Vec<u8>,
    incoming_position: usize,
    plaintext: Vec<u8>,
    plaintext_position: usize,
    failed: bool,
    sent_eof: bool,
    received_eof: bool,
}
impl<T> SecureStream<T> {
    fn new(
        inner: T,
        key: &[u8],
        hello: &[u8; HELLO_LEN],
        challenge: &[u8; 32],
        client: bool,
    ) -> io::Result<Self> {
        let c2s = derive(key, hello, challenge, b"client-to-server")?;
        let s2c = derive(key, hello, challenge, b"server-to-client")?;
        let (seal, open) = if client { (c2s, s2c) } else { (s2c, c2s) };
        Ok(Self {
            inner,
            seal,
            open,
            send_sequence: 0,
            recv_sequence: 0,
            outgoing: Vec::new(),
            outgoing_position: 0,
            outgoing_plain: Vec::new(),
            header: [0; 4],
            header_position: 0,
            incoming: Vec::new(),
            incoming_position: 0,
            plaintext: Vec::new(),
            plaintext_position: 0,
            failed: false,
            sent_eof: false,
            received_eof: false,
        })
    }

    fn seal_record(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let sequence = self.send_sequence;
        // Reserve before sealing or writing; no retry can reuse this nonce.
        self.send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("v2 send counter exhausted"))?;
        let length = (plaintext.len() + TAG_LEN) as u32;
        self.outgoing.clear();
        self.outgoing.extend_from_slice(&length.to_be_bytes());
        self.outgoing.extend_from_slice(plaintext);
        let tag = self
            .seal
            .seal_in_place_separate_tag(
                nonce(sequence),
                aead::Aad::from(aad(sequence, length)),
                &mut self.outgoing[4..],
            )
            .map_err(crypto_error)?;
        self.outgoing.extend_from_slice(tag.as_ref());
        self.outgoing_position = 0;
        Ok(())
    }
}
impl<T: AsyncWrite + Unpin> SecureStream<T> {
    fn flush_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.outgoing_position < self.outgoing.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.outgoing[self.outgoing_position..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.outgoing_position += n;
        }
        Poll::Ready(Ok(()))
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for SecureStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("v2 transport is closed after an error")));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let result = (|| {
            if this.plaintext_position == this.plaintext.len() && !this.received_eof {
                while this.header_position < 4 {
                    let mut part = ReadBuf::new(&mut this.header[this.header_position..]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                    if part.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.header_position += part.filled().len();
                }
                let length = u32::from_be_bytes(this.header) as usize;
                if !(TAG_LEN..=RECORD_LIMIT + TAG_LEN).contains(&length) {
                    return Poll::Ready(Err(invalid("invalid v2 record length")));
                }
                this.incoming.resize(length, 0);
                while this.incoming_position < length {
                    let mut part = ReadBuf::new(&mut this.incoming[this.incoming_position..]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                    if part.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.incoming_position += part.filled().len();
                }
                let sequence = this.recv_sequence;
                this.recv_sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("v2 receive counter exhausted"))?;
                let plain = this
                    .open
                    .open_in_place(
                        nonce(sequence),
                        aead::Aad::from(aad(sequence, length as u32)),
                        &mut this.incoming,
                    )
                    .map_err(crypto_error)?;
                this.plaintext.clear();
                this.plaintext.extend_from_slice(plain);
                this.plaintext_position = 0;
                this.received_eof = plain.is_empty();
                this.header_position = 0;
                this.incoming_position = 0;
            }
            let n = buf
                .remaining()
                .min(this.plaintext.len() - this.plaintext_position);
            buf.put_slice(&this.plaintext[this.plaintext_position..this.plaintext_position + n]);
            this.plaintext_position += n;
            Poll::Ready(Ok(()))
        })();
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for SecureStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.sent_eof {
            return Poll::Ready(Err(invalid("v2 writer is closed")));
        }
        let result = (|| {
            if this.outgoing_plain.is_empty() {
                let n = RECORD_LIMIT.min(buf.len());
                if n == 0 {
                    return Poll::Ready(Ok(0));
                }
                this.seal_record(&buf[..n])?;
                this.outgoing_plain.extend_from_slice(&buf[..n]);
            } else if !buf.starts_with(&this.outgoing_plain) {
                // A cancelled write may resume only with the same unacknowledged
                // bytes. A different buffer must not silently lose data.
                return Poll::Ready(Err(invalid("v2 write resumed with different bytes")));
            }
            ready!(this.flush_record(cx))?;
            let n = this.outgoing_plain.len();
            this.outgoing_plain.clear();
            Poll::Ready(Ok(n))
        })();
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("v2 writer is closed")));
        }
        let result = (|| {
            ready!(this.flush_record(cx))?;
            Pin::new(&mut this.inner).poll_flush(cx)
        })();
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("v2 writer is closed")));
        }
        let result = (|| {
            ready!(this.flush_record(cx))?;
            if !this.sent_eof {
                this.seal_record(&[])?;
                this.sent_eof = true;
            }
            ready!(this.flush_record(cx))?;
            Pin::new(&mut this.inner).poll_shutdown(cx)
        })();
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    fn hello(seed: u8) -> [u8; HELLO_LEN] {
        let mut hello = [seed; HELLO_LEN];
        hello[..4].copy_from_slice(&MAGIC);
        hello[4] = 2;
        hello[5..8].fill(0);
        hello
    }
    async fn wire(data: &[u8], client: bool) -> Vec<u8> {
        let mut stream = SecureStream::new(Vec::new(), &KEY, &hello(1), &[2; 32], client).unwrap();
        stream.write_all(data).await.unwrap();
        stream.shutdown().await.unwrap();
        stream.inner
    }
    #[tokio::test]
    async fn direction_connection_and_challenge_are_separate_domains() {
        let bytes = wire(b"same plaintext", true).await;
        assert_ne!(bytes, wire(b"same plaintext", false).await);
        for (h, challenge, client, key) in [
            (hello(1), [2; 32], true, KEY),
            (hello(3), [2; 32], false, KEY),
            (hello(1), [3; 32], false, KEY),
            (hello(1), [2; 32], false, [8; 32]),
            (
                {
                    let mut h = hello(1);
                    h[5] = 1;
                    h
                },
                [2; 32],
                false,
                KEY,
            ),
        ] {
            let mut reader =
                SecureStream::new(bytes.as_slice(), &key, &h, &challenge, client).unwrap();
            assert!(reader.read_u8().await.is_err());
            assert!(
                reader.read_u8().await.is_err(),
                "authentication error must be terminal"
            );
        }
        let mut reader =
            SecureStream::new(bytes.as_slice(), &KEY, &hello(1), &[2; 32], false).unwrap();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"same plaintext");
    }
    #[tokio::test]
    async fn cancelled_partial_header_and_payload_reads_keep_progress() {
        let bytes = wire(b"fragmented payload", true).await;
        for split in [1, 3, 4, 7, bytes.len() - TAG_LEN - 4 - 1] {
            let (mut writer, reader) = tokio::io::duplex(128);
            let mut reader = SecureStream::new(reader, &KEY, &hello(1), &[2; 32], false).unwrap();
            writer.write_all(&bytes[..split]).await.unwrap();
            let mut byte = [0u8; 1];
            assert!(futures::poll!(Box::pin(reader.read(&mut byte))).is_pending());
            writer.write_all(&bytes[split..]).await.unwrap();
            let mut data = Vec::new();
            reader.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"fragmented payload");
        }
    }
    #[tokio::test]
    async fn cancelled_partial_write_resumes_without_a_second_seal() {
        let (writer, mut reader) = tokio::io::duplex(8);
        let mut writer = SecureStream::new(writer, &KEY, &hello(1), &[2; 32], true).unwrap();
        assert!(futures::poll!(Box::pin(writer.write_all(b"fragmented payload"))).is_pending());
        assert_eq!(writer.send_sequence, 1);
        let drain = tokio::spawn(async move {
            let mut v = Vec::new();
            reader.read_to_end(&mut v).await.unwrap();
            v
        });
        writer.write_all(b"fragmented payload").await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            drain.await.unwrap(),
            wire(b"fragmented payload", true).await
        );
    }
    #[tokio::test]
    async fn changed_buffer_after_cancel_fails_closed() {
        let (writer, _reader) = tokio::io::duplex(8);
        let mut writer = SecureStream::new(writer, &KEY, &hello(1), &[2; 32], true).unwrap();
        assert!(futures::poll!(Box::pin(writer.write_all(b"original payload"))).is_pending());
        assert!(writer.write_all(b"different payload").await.is_err());
        assert!(writer.write_all(b"original payload").await.is_err());
        assert_eq!(writer.send_sequence, 1);
    }
    #[tokio::test]
    async fn tampering_truncation_reordering_and_duplicate_records_fail() {
        let bytes = wire(b"secret", true).await;
        let first_length = 4 + 6 + TAG_LEN;
        let mut corrupt = bytes.clone();
        corrupt[5] ^= 1;
        let mut duplicate = bytes[..first_length].to_vec();
        duplicate.extend_from_slice(&bytes);
        let mut reordered = bytes[first_length..].to_vec();
        reordered.extend_from_slice(&bytes[..first_length]);
        // An authenticated EOF is valid on its own only at sequence zero.
        for data in [
            corrupt,
            bytes[..first_length].to_vec(),
            duplicate,
            reordered,
            vec![0xff; 4],
        ] {
            let mut reader =
                SecureStream::new(data.as_slice(), &KEY, &hello(1), &[2; 32], false).unwrap();
            assert!(reader.read_to_end(&mut Vec::new()).await.is_err());
        }
    }
    #[tokio::test]
    async fn large_stream_and_authenticated_half_close_round_trip() {
        let payload = vec![19; RECORD_LIMIT * 3 + 7];
        let bytes = wire(&payload, true).await;
        let mut reader =
            SecureStream::new(bytes.as_slice(), &KEY, &hello(1), &[2; 32], false).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(payload, output);
        assert_eq!(reader.recv_sequence, 5);
    }
    #[tokio::test]
    async fn counter_exhaustion_is_terminal() {
        let mut writer = SecureStream::new(Vec::new(), &KEY, &hello(1), &[2; 32], true).unwrap();
        writer.send_sequence = u64::MAX;
        assert!(writer.write_all(b"x").await.is_err());
        assert!(writer.inner.is_empty());
        assert!(writer.write_all(b"y").await.is_err());
    }
    #[tokio::test]
    async fn real_handshake_round_trip() {
        let (client, mut server) = tokio::io::duplex(128);
        let server = tokio::spawn(async move {
            let mut magic = [0; 8];
            server.read_exact(&mut magic).await.unwrap();
            assert_eq!(magic[..4], MAGIC);
            let (mut server, control) = accept_v2(server, &KEY, magic).await.unwrap();
            assert!(control);
            assert_eq!(server.read_u8().await.unwrap(), 42);
            server.write_u8(43).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let mut client = connect_v2(client, &KEY, true).await.unwrap();
        client.write_u8(42).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, [43]);
        server.await.unwrap();
    }
}
