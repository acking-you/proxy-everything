//! Static codec dispatch after route selection; no plaintext native policy.
use std::borrow::Cow;

use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::secure_transport::ProxyStream;
use proxy_core::{client_proxy_with_cryptor_codec, proxy_with_normal_codec};
use snafu::ResultExt;
use tokio::io::{ReadHalf, WriteHalf};

use super::{Forwarder, ProxySnafu, Result, get_uri};

pub type TcpAsyncReader<T = ReadHalf<ProxyStream>> = AsyncReader<T>;
pub type TcpAsyncWriter<T = WriteHalf<ProxyStream>> = AsyncWriter<T>;

pub struct ForwardContext {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) need_proxy: bool,
    pub(super) msg_key: Option<Cow<'static, str>>,
}

pub struct TcpForwardImpl {
    pub(super) context: ForwardContext,
    pub(super) initial_request: Vec<u8>,
    pub(super) client_reader: TcpAsyncReader,
    pub(super) client_writer: TcpAsyncWriter,
    pub(super) server_reader: TcpAsyncReader,
    pub(super) server_writer: TcpAsyncWriter,
}

// ============================================================================
// Common Helper Functions
// ============================================================================

/// Splits a TcpStream into async reader and writer.
///
/// This is a convenience function that wraps the stream splitting
/// and adapter creation into a single call.
#[inline]
pub fn split_and_wrap(stream: impl Into<ProxyStream>) -> (TcpAsyncReader, TcpAsyncWriter) {
    let (r, w) = stream.into().into_split();
    (AsyncReader::new(r), AsyncWriter::new(w))
}

impl Forwarder for TcpForwardImpl {
    #[tracing::instrument(skip_all, fields(
        host = %self.context.host,
        port = self.context.port,
        proxied = self.context.need_proxy,
    ))]
    async fn forward(self) -> Result<()> {
        let TcpForwardImpl {
            context,
            initial_request,
            client_reader,
            client_writer,
            server_reader,
            server_writer,
        } = self;
        let client_reader = client_reader.prepend(initial_request);
        let ForwardContext {
            need_proxy,
            host,
            port,
            msg_key,
        } = context;

        tracing::debug!(
            host,
            port,
            need_proxy,
            legacy_payload_codec = msg_key.is_some()
        );

        // A missing legacy codec means a direct/external or already-v3 stream.
        let result = match msg_key {
            Some(key) => {
                client_proxy_with_cryptor_codec(
                    &host,
                    &key,
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await
            }
            None => {
                proxy_with_normal_codec(
                    &host,
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await
            }
        };
        result.with_context(|_| ProxySnafu {
            uri: get_uri(&host, port),
        })
    }
}
