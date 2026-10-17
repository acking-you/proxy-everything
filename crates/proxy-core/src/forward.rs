//! Generic bidirectional forwarding shared by client and server.
use crate::{
    Aes256GcmDecryptor, Aes256GcmEncryptor, MyAsyncCodecReader, MyAsyncReadExt, MyAsyncWriteExt,
    ProxyError, Result, codec,
};

// ============================================================================
// Codec Factory Functions
// ============================================================================

/// Creates a decryption codec for the given reader and key.
pub fn get_decryptor_codec<R: MyAsyncReadExt + Send + Unpin>(
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
/// Clean half-closes drain the other direction; an error cancels the peer.
pub async fn start_proxy<
    ClientCodec: MyAsyncCodecReader + Send + Unpin,
    ServerCodec: MyAsyncCodecReader + Send + Unpin,
    ClientWriter: MyAsyncWriteExt + Send + Unpin,
    ServerWriter: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    client_codec: ClientCodec,
    server_codec: ServerCodec,
    client_writer: ClientWriter,
    server_writer: ServerWriter,
) -> Result<()> {
    let (bytes_up, bytes_down) = relay_bidirectional(
        codec::copy(client_codec, server_writer),
        codec::copy(server_codec, client_writer),
    )
    .await?;
    tracing::info!(
        host = host.as_ref(),
        bytes_up,
        bytes_down,
        "proxy transfer completed"
    );
    Ok(())
}

/// A clean half-close drains the peer direction. Any error cancels it, while
/// retaining the failing direction and original I/O/authentication cause.
pub async fn relay_bidirectional<Up, Down>(up: Up, down: Down) -> Result<(u64, u64)>
where
    Up: std::future::Future<Output = Result<u64>>,
    Down: std::future::Future<Output = Result<u64>>,
{
    async fn direction<F: std::future::Future<Output = Result<u64>>>(
        transfer: F,
        direction: &'static str,
    ) -> Result<u64> {
        transfer.await.map_err(|source| ProxyError::Relay {
            direction,
            source: Box::new(source),
        })
    }
    tokio::try_join!(
        direction(up, "client->server"),
        direction(down, "server->client")
    )
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
    ClientReader: MyAsyncReadExt + Send + Unpin,
    ServerReader: MyAsyncReadExt + Send + Unpin,
    ClientWriter: MyAsyncWriteExt + Send + Unpin,
    ServerWriter: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    key: &impl AsRef<str>,
    client_reader: ClientReader,
    server_reader: ServerReader,
    client_writer: ClientWriter,
    server_writer: ServerWriter,
) -> Result<()> {
    tracing::info!(host = %host.as_ref(), "client encrypted proxy starting");
    start_proxy(
        host,
        get_encryptor_codec(key, client_reader)?,
        get_decryptor_codec(key, server_reader)?,
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
    ClientReader: MyAsyncReadExt + Send + Unpin,
    ServerReader: MyAsyncReadExt + Send + Unpin,
    ClientWriter: MyAsyncWriteExt + Send + Unpin,
    ServerWriter: MyAsyncWriteExt + Send + Unpin,
>(
    host: impl AsRef<str>,
    client_reader: ClientReader,
    server_reader: ServerReader,
    client_writer: ClientWriter,
    server_writer: ServerWriter,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{AsyncNormalCodec, AsyncWriter};

    struct Reader(bool);
    impl MyAsyncReadExt for Reader {
        async fn read_u32(&mut self) -> std::io::Result<u32> {
            unreachable!()
        }

        async fn read_exact(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            unreachable!()
        }

        async fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                Err(std::io::Error::from_raw_os_error(10054))
            } else {
                std::future::pending().await
            }
        }
    }

    #[tokio::test]
    async fn relay_returns_reset_with_direction_and_cancels_silent_peer() {
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            start_proxy(
                "example.test",
                AsyncNormalCodec::new(Reader(true)),
                AsyncNormalCodec::new(Reader(false)),
                AsyncWriter::new(Vec::new()),
                AsyncWriter::new(Vec::new()),
            ),
        )
        .await
        .expect("relay must cancel the silent direction")
        .unwrap_err();
        assert!(matches!(
            &error,
            ProxyError::Relay {
                direction: "client->server",
                ..
            }
        ));
        let mut cause: &(dyn std::error::Error + 'static) = &error;
        while let Some(source) = cause.source() {
            cause = source;
        }
        assert_eq!(
            cause
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(10054)
        );
    }
}
