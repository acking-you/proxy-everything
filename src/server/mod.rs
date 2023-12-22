#[cfg(feature = "monoio")]
use monoio::{
    io::{AsyncReadRentExt, Splitable},
    net::TcpStream,
};
use snafu::{ResultExt, Snafu};
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[derive(Debug, Snafu)]
pub enum ServerError {
    #[snafu(display("Io Error occur: {detail}"))]
    Io {
        detail: String,
        source: std::io::Error,
    },
    #[snafu(display("Decryption Error occur!,detail:{detail}"))]
    Decryption { detail: String },
    #[snafu(display("SerdeJson Error occur!"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("Server read header fail:{source}"))]
    ReadHeader { source: super::Error },
    #[snafu(display(
        "Exceeded the maximum supported header length({MAX_HEADER_SIZE}). size:{size}"
    ))]
    HeaderSize { size: DataSize },
    #[snafu(display("Proxy error happen!"))]
    Proxy { source: super::Error },
}

use crate::{
    codec::{AsyncReader, AsyncWriter},
    get_data_size, proxy_with_norlmal_codec, server_proxy_with_cryptor_codec, Aes256GcmCryption,
    DataSize, MyAsyncReadExt, ProxyHeader,
};

type Result<T> = std::result::Result<T, ServerError>;

pub const SERVER_PORT: u16 = 1081;
pub const MAX_HEADER_SIZE: DataSize = 8 * 128;

pub async fn handle_connect(conn: TcpStream) -> Result<()> {
    let (r, w) = conn.into_split();
    let (mut client_reader, client_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
    let msg_len = get_data_size(&mut client_reader)
        .await
        .context(ReadHeaderSnafu)?;
    if msg_len > MAX_HEADER_SIZE {
        HeaderSizeSnafu { size: msg_len }.fail()?
    }

    let mut buf = [0; MAX_HEADER_SIZE as usize];
    let real_buf = &mut buf[..msg_len as usize];
    client_reader.read_exact(real_buf).await.context(IoSnafu {
        detail: "Read Header(addr,tag)",
    })?;
    let mut cryption =
        Aes256GcmCryption::try_new_with_default_key().map_err(|e| ServerError::Decryption {
            detail: format!("{e}"),
        })?;

    let header = cryption
        .decrypt_with_tag(real_buf)
        .map_err(|e| ServerError::Decryption {
            detail: format!("{e}"),
        })?;

    let header: ProxyHeader = serde_json::from_slice(header).context(SerdeJsonSnafu)?;
    let dest_stream = TcpStream::connect((header.host.as_str(), header.port))
        .await
        .context(IoSnafu {
            detail: format!("Connect to `dest_server({})`", header),
        })?;
    let (r, w) = dest_stream.into_split();
    let (server_reader, server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));

    // 开始进行流量转发
    if let Some(key) = header.key.as_ref() {
        server_proxy_with_cryptor_codec(
            key,
            client_reader,
            server_reader,
            client_writer,
            server_writer,
        )
        .await
        .context(ProxySnafu)
    } else {
        proxy_with_norlmal_codec(client_reader, server_reader, client_writer, server_writer)
            .await
            .context(ProxySnafu)
    }
}
