use std::fmt::Debug;

use snafu::{Report, ResultExt, Snafu};
use tokio::net::TcpListener;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

use crate::MyAsyncWriteExt;
use crate::config::TURELY_PROXY_SERVER;

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

use crate::codec::{AsyncReader, AsyncWriter};
use crate::util::{
    GracefulShutdownManager, GracefulShutdownManagerImpl, ProxyTaskId, TaskIdGenerator,
};
use crate::{
    Aes256GcmCryption, DataSize, MyAsyncReadExt, ProxyHeader, get_data_size,
    proxy_with_norlmal_codec, server_proxy_with_cryptor_codec, set_data_size,
};

type Result<T> = std::result::Result<T, ServerError>;

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

    if let Some(truely_proxy_server) = TURELY_PROXY_SERVER.as_ref() {
        let truely_proxy_stream =
            TcpStream::connect(truely_proxy_server)
                .await
                .context(IoSnafu {
                    detail: format!("Connect to truely_proxy_server:{}", truely_proxy_server),
                })?;

        let (r, w) = truely_proxy_stream.into_split();
        let (server_reader, mut server_writer) = (AsyncReader::new(r), AsyncWriter::new(w));
        set_data_size(&mut server_writer, msg_len)
            .await
            .context(ProxySnafu)?;
        server_writer.write_all(real_buf).await.context(IoSnafu {
            detail: "Write To Truely Server Header(addr,tag)",
        })?;
        return proxy_with_norlmal_codec(
            truely_proxy_server,
            client_reader,
            server_reader,
            client_writer,
            server_writer,
        )
        .await
        .context(ProxySnafu);
    }

    let mut cryption =
        Aes256GcmCryption::try_new_with_default_key().map_err(|e| ServerError::Decryption {
            detail: format!("{e}"),
        })?;

    // get header
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

    // start forward
    if let Some(key) = header.key.as_ref() {
        server_proxy_with_cryptor_codec(
            header.host.as_str(),
            key,
            client_reader,
            server_reader,
            client_writer,
            server_writer,
        )
        .await
        .context(ProxySnafu)
    } else {
        proxy_with_norlmal_codec(
            header.host.as_str(),
            client_reader,
            server_reader,
            client_writer,
            server_writer,
        )
        .await
        .context(ProxySnafu)
    }
}

#[tracing::instrument]
pub async fn start_server(host: impl AsRef<str> + Debug, port: u16) {
    let listener = TcpListener::bind((host.as_ref(), port))
        .await
        .expect("start lisenter never fails");
    let mut manager = GracefulShutdownManagerImpl::new();
    if !manager.spawn_graceful_signals() {
        return;
    }
    let mut task_id = ProxyTaskId::new();
    let cancel_token = manager.cancellation_token();

    loop {
        tokio::select! {
            ret = listener.accept() => {
                let (client_socket, _) = match ret {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(accept_error = ?e, info = "pause 3s, and retry again");
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        continue;
                    }
                };
                manager.spawn(task_id.r#gen(), async move {
                    if let Err(e) = handle_connect(client_socket).await {
                        let report = Report::from_error(e).to_string();
                        tracing::warn!(handle_client_proxy_error = report);
                    }
                });
            }
            _ = cancel_token.cancelled() => {
                break;
            }
        }
    }
    tracing::info!("graceful shutdown, waiting for tasks to complete...");
    manager.wait().await;
}
