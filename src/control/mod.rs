//! Control plane protocol for proxy management.
//!
//! Provides node discovery, metrics queries, and cluster management.
//!
//! # Protocol Flow
//!
//! ```text
//! ┌─────────────┐                              ┌─────────────┐
//! │   Client    │                              │   Server    │
//! │  (TUI/CLI)  │                              │  (Proxy)    │
//! └──────┬──────┘                              └──────┬──────┘
//!        │                                            │
//!        │  1. TCP Connect to server:port             │
//!        │ ──────────────────────────────────────────>│
//!        │                                            │
//!        │  2. Send ProxyHeader{host:"__control__"}   │
//!        │ ──────────────────────────────────────────>│
//!        │                                            │
//!        │  3. ControlRequest (JSON, optionally encrypted)
//!        │ ──────────────────────────────────────────>│
//!        │                                            │
//!        │  4. ControlResponse (JSON, optionally encrypted)
//!        │ <──────────────────────────────────────────│
//!        │                                            │
//!        │  ... repeat 3-4 for multiple requests ...  │
//!        │                                            │
//!        │  5. Close connection                       │
//!        │ ──────────────────────────────────────────>│
//!        ▼                                            ▼
//! ```
//!
//! # Wire Format
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │  [4-byte length][JSON payload][16-byte auth tag if enc]  │
//! └──────────────────────────────────────────────────────────┘
//! ```

use std::borrow::Cow;
use std::time::Duration;

use crate::client::{ClientError, get_tcp_proxy_stream};
use crate::codec::{AsyncReader, AsyncWriter};
use crate::metrics::{
    ConnectionRecord, Granularity, RealtimeSnapshot, TimeBucket, TopCategory, TrafficStats,
};
use crate::nodes::NodeInfo;
use crate::{Aes256GcmCryption, MyAsyncReadExt, MyAsyncWriteExt};
use crate::{ProxyError, get_data_size, set_data_size};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

pub const CONTROL_HOST: &str = "__control__";
pub const CONTROL_PORT: u16 = 0;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Snafu)]
pub enum ControlError {
    #[snafu(display("Control IO error: {detail}"))]
    Io {
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Control protocol error: {source}"))]
    Protocol { source: ProxyError },
    #[snafu(display("Control crypto error: {detail}"))]
    Crypto { detail: String },
    #[snafu(display("Control serde error: {source}"))]
    SerdeJson { source: serde_json::Error },
    #[snafu(display("Control client error: {source}"))]
    Client { source: ClientError },
    #[snafu(display("Connection timeout"))]
    Timeout,
}

pub type Result<T> = std::result::Result<T, ControlError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    pub token: Option<String>,
    #[serde(flatten)]
    pub op: ControlOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlOp {
    // Node management
    Ping,
    AddNode { addr: String },
    RemoveNode { node_id: String },
    ListNodes,
    SyncNodes { nodes: Vec<NodeInfo> },

    // Metrics queries
    GetRealtimeStats,
    GetRecentConnections { limit: u32 },
    GetTimeBuckets { granularity: Granularity, count: u32 },
    GetTopN { category: TopCategory, limit: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    pub error: Option<String>,
    pub result: Option<ControlResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResult {
    Pong,
    Ack,
    Nodes { nodes: Vec<NodeInfo> },
    RealtimeStats { stats: RealtimeSnapshot },
    Connections { connections: Vec<ConnectionRecord> },
    TimeBuckets { buckets: Vec<TimeBucket> },
    TopN { entries: Vec<TopNEntry> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopNEntry {
    pub key: String,
    pub stats: TrafficStats,
}

pub(crate) struct ControlCodec<R, W> {
    reader: R,
    writer: W,
    cryptor: Option<Aes256GcmCryption>,
}

impl<R, W> ControlCodec<R, W>
where
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
{
    pub fn new(reader: R, writer: W, session_key: Option<&str>) -> Result<Self> {
        let cryptor = if let Some(key) = session_key {
            Some(
                Aes256GcmCryption::try_new(key.as_bytes()).map_err(|e| ControlError::Crypto {
                    detail: e.to_string(),
                })?,
            )
        } else {
            None
        };
        Ok(Self {
            reader,
            writer,
            cryptor,
        })
    }

    pub async fn read_request(&mut self) -> Result<Option<ControlRequest>> {
        self.read_message().await
    }

    pub async fn read_response(&mut self) -> Result<Option<ControlResponse>> {
        self.read_message().await
    }

    pub async fn write_request(&mut self, request: &ControlRequest) -> Result<()> {
        self.write_message(request).await
    }

    pub async fn write_response(&mut self, response: &ControlResponse) -> Result<()> {
        self.write_message(response).await
    }

    async fn read_message<T>(&mut self) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let msg_len = match get_data_size(&mut self.reader).await {
            Ok(len) => len,
            Err(e) => {
                if let ProxyError::ProtocolIo { source, .. } = &e {
                    if source.kind() == std::io::ErrorKind::UnexpectedEof {
                        return Ok(None);
                    }
                }
                return Err(ControlError::Protocol { source: e });
            }
        };
        let mut buf = vec![0u8; msg_len as usize];
        self.reader.read_exact(&mut buf).await.context(IoSnafu {
            detail: "read control payload",
        })?;
        let payload = if let Some(cryptor) = self.cryptor.as_mut() {
            cryptor
                .decrypt_with_tag(&mut buf)
                .map_err(|e| ControlError::Crypto {
                    detail: e.to_string(),
                })?
        } else {
            buf.as_mut_slice()
        };
        let message = serde_json::from_slice(payload).context(SerdeJsonSnafu)?;
        Ok(Some(message))
    }

    async fn write_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let mut payload = serde_json::to_vec(message).context(SerdeJsonSnafu)?;
        if let Some(cryptor) = self.cryptor.as_mut() {
            let tag = cryptor
                .encrypt(&mut payload)
                .map_err(|e| ControlError::Crypto {
                    detail: e.to_string(),
                })?;
            payload.extend_from_slice(tag.as_ref());
        }
        set_data_size(&mut self.writer, payload.len() as u32)
            .await
            .context(ProtocolSnafu)?;
        self.writer.write_all(&payload).await.context(IoSnafu {
            detail: "write control payload",
        })?;
        Ok(())
    }
}

pub struct ControlClient {
    codec: ControlCodec<
        AsyncReader<tokio::net::tcp::OwnedReadHalf>,
        AsyncWriter<tokio::net::tcp::OwnedWriteHalf>,
    >,
}

impl ControlClient {
    pub async fn connect(
        server_host: &str,
        server_port: u16,
        session_key: Option<String>,
    ) -> Result<Self> {
        let msg_key = session_key.clone().map(Cow::Owned);
        let connect_fut = get_tcp_proxy_stream(
            CONTROL_HOST,
            CONTROL_PORT,
            server_host,
            server_port,
            msg_key,
            "control",
        );
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, connect_fut)
            .await
            .map_err(|_| ControlError::Timeout)?
            .context(ClientSnafu)?;
        let (reader, writer) = stream.into_split();
        let codec = ControlCodec::new(
            AsyncReader::new(reader),
            AsyncWriter::new(writer),
            session_key.as_deref(),
        )?;
        Ok(Self { codec })
    }

    pub async fn request(&mut self, request: ControlRequest) -> Result<ControlResponse> {
        self.codec.write_request(&request).await?;
        match self.codec.read_response().await? {
            Some(resp) => Ok(resp),
            None => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "control response closed".to_string(),
                },
            }),
        }
    }

    // Convenience methods
    pub async fn ping(&mut self, token: Option<String>) -> Result<ControlResponse> {
        self.request(ControlRequest {
            token,
            op: ControlOp::Ping,
        })
        .await
    }

    pub async fn list_nodes(&mut self, token: Option<String>) -> Result<Vec<NodeInfo>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::ListNodes,
            })
            .await?;
        match resp.result {
            Some(ControlResult::Nodes { nodes }) => Ok(nodes),
            _ => Ok(vec![]),
        }
    }

    pub async fn get_realtime_stats(
        &mut self,
        token: Option<String>,
    ) -> Result<Option<RealtimeSnapshot>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetRealtimeStats,
            })
            .await?;
        match resp.result {
            Some(ControlResult::RealtimeStats { stats }) => Ok(Some(stats)),
            _ => Ok(None),
        }
    }

    pub async fn get_recent_connections(
        &mut self,
        token: Option<String>,
        limit: u32,
    ) -> Result<Vec<ConnectionRecord>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetRecentConnections { limit },
            })
            .await?;
        match resp.result {
            Some(ControlResult::Connections { connections }) => Ok(connections),
            _ => Ok(vec![]),
        }
    }

    pub async fn get_time_buckets(
        &mut self,
        token: Option<String>,
        granularity: Granularity,
        count: u32,
    ) -> Result<Vec<TimeBucket>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetTimeBuckets { granularity, count },
            })
            .await?;
        match resp.result {
            Some(ControlResult::TimeBuckets { buckets }) => Ok(buckets),
            _ => Ok(vec![]),
        }
    }

    pub async fn get_top_n(
        &mut self,
        token: Option<String>,
        category: TopCategory,
        limit: u32,
    ) -> Result<Vec<TopNEntry>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetTopN { category, limit },
            })
            .await?;
        match resp.result {
            Some(ControlResult::TopN { entries }) => Ok(entries),
            _ => Ok(vec![]),
        }
    }
}

pub fn is_control_target(host: &str, port: u16) -> bool {
    host == CONTROL_HOST && port == CONTROL_PORT
}
