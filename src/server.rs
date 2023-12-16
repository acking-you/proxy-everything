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
    copy, get_data_size, proxy_result_handle,
    runtime_codec::{new_normal_codec, AsyncReader, AsyncWriter},
    Address, Aes256GcmCryption, DataSize, MyAsyncReadExt,
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

    let addr = cryption
        .decrypt_with_tag(real_buf)
        .map_err(|e| ServerError::Decryption {
            detail: format!("{e}"),
        })?;

    let addr: Address = serde_json::from_slice(addr).context(SerdeJsonSnafu)?;
    let mut dest_stream = TcpStream::connect((addr.host.as_str(), addr.port))
        .await
        .context(IoSnafu {
            detail: format!("Connect to `dest_server({})`", addr),
        })?;
    let (r, w) = dest_stream.split();
    let (server_reader, server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));

    // 开始进行流量转发
    let client_to_server = copy(new_normal_codec(client_reader), server_writer);
    let server_to_client = copy(new_normal_codec(server_reader), client_writer);

    let (r1, r2) = futures::future::join(client_to_server, server_to_client).await;
    proxy_result_handle(r1, r2).context(ProxySnafu)
}
