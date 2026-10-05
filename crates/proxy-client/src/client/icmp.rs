//! Bridge the private local Echo extension to the authenticated proxy path.

use std::borrow::Cow;
use std::time::Duration;

use proxy_core::ProxyError;
use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::config::runtime;
use proxy_core::protocol::{FrameReader, FrameWriter};
use snafu::ResultExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{ExternalProxySnafu, Forwarder, ProxySnafu, Result, TcpAsyncReader, TcpAsyncWriter};

/// One bounded, sequential ICMP Echo flow over the configured native proxy.
pub struct EchoForwarder {
    local: TcpStream,
    reader: FrameReader<TcpAsyncReader>,
    writer: FrameWriter<TcpAsyncWriter>,
}

impl EchoForwarder {
    pub(super) async fn connect(
        mut local: TcpStream,
        host: &str,
        ipv6: bool,
        key: Option<Cow<'static, str>>,
    ) -> Result<Self> {
        let endpoint = runtime::server_endpoint();
        let remote = proxy_core::transport::get_icmp_proxy_stream(
            host,
            ipv6,
            &endpoint.host,
            endpoint.port,
            key.clone(),
        )
        .await
        .context(ExternalProxySnafu)?;
        let key = if remote.is_secure() { None } else { key };
        let (reader, writer) = remote.into_split();
        local
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(io_error)
            .context(ProxySnafu { uri: "ICMP Echo" })?;
        Ok(Self {
            local,
            reader: FrameReader::new(
                AsyncReader::new(reader),
                key.as_deref(),
                u16::MAX as usize + 16,
            )
            .context(ProxySnafu { uri: "ICMP Echo" })?,
            writer: FrameWriter::new(
                AsyncWriter::new(writer),
                key.as_deref(),
                u16::MAX as usize + 16,
            )
            .context(ProxySnafu { uri: "ICMP Echo" })?,
        })
    }
}

impl Forwarder for EchoForwarder {
    async fn forward(mut self) -> Result<()> {
        let mut request = Vec::new();
        loop {
            let exchange = async {
                tun2proxy::icmp::read_packet(&mut self.local, &mut request)
                    .await
                    .map_err(io_error)?;
                self.writer.prepare()?.extend_from_slice(&request);
                self.writer.send().await?;
                let reply = self
                    .reader
                    .read()
                    .await?
                    .filter(|reply| reply.len() >= 8)
                    .ok_or_else(|| ProxyError::Protocol {
                        detail: "ICMP Echo unavailable: upgrade the final server and check its \
                                 ICMP socket permissions"
                            .into(),
                    })?;
                tun2proxy::icmp::write_packet(&mut self.local, reply)
                    .await
                    .map_err(io_error)
            };
            match tokio::time::timeout(Duration::from_secs(20), exchange).await {
                Ok(Err(error)) if error.is_expected_disconnect() => return Ok(()),
                Ok(result) => result.context(ProxySnafu { uri: "ICMP Echo" })?,
                Err(_) => {
                    return Err(io_error(std::io::ErrorKind::TimedOut.into()))
                        .context(ProxySnafu { uri: "ICMP Echo" });
                }
            }
        }
    }
}

fn io_error(source: std::io::Error) -> ProxyError {
    ProxyError::Io {
        context: "icmp_echo",
        detail: "local Echo transport".into(),
        source,
    }
}
