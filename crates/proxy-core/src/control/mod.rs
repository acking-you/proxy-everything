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
//! │  [checksum:u32][length:u32][JSON][optional 16-byte tag]  │
//! └──────────────────────────────────────────────────────────┘
//! ```

use std::borrow::Cow;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

use crate::codec::{AsyncReader, AsyncWriter};
use crate::metrics::{
    ConnectionRecord, Granularity, RealtimeSnapshot, TimeBucket, TopCategory, TrafficStats,
};
use crate::nodes::{NodeGroup, NodeInfo};
use crate::protocol::{FrameReader, FrameWriter, MAX_DATA_SIZE};
use crate::relay::{LoadBalanceAlgo, RelayConfig, RelayStatus, UpstreamTarget};
use crate::socks5::{Socks5Endpoint, Socks5Session, Socks5Status, Socks5Update};
use crate::transport::{TransportError, get_tcp_proxy_stream};
use crate::upstream::{Carrier, UpstreamAddress};
use crate::{MyAsyncReadExt, MyAsyncWriteExt, ProxyError};

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
    #[snafu(display("Control transport error: {source}"))]
    Transport { source: TransportError },
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
    AddNode {
        addr: String,
    },
    RemoveNode {
        node_id: String,
    },
    ListNodes,
    SyncNodes {
        nodes: Vec<NodeInfo>,
        #[serde(default)]
        blocked: Vec<String>,
    },

    // Group management
    CreateGroup {
        group_id: String,
        name: String,
    },
    DeleteGroup {
        group_id: String,
    },
    ListGroups,
    AddNodeToGroup {
        group_id: String,
        node_id: String,
    },
    RemoveNodeFromGroup {
        group_id: String,
        node_id: String,
    },

    // Relay configuration
    GetRelayConfig,
    SetRelayConfig {
        config: RelayConfig,
    },
    SetRelayEnabled {
        enabled: bool,
    },
    AddRelayTarget {
        target: UpstreamTarget,
    },
    RemoveRelayTarget {
        index: usize,
    },
    SetRelayAlgo {
        algo: LoadBalanceAlgo,
    },
    GetRelayStatus,

    // Managed, authenticated SOCKS5 listener. Existing wire variants are unchanged.
    GetSocks5Status,
    SetSocks5Enabled {
        enabled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listen: Option<std::net::SocketAddr>,
    },
    RotateSocks5Key,
    UpdateSocks5Config {
        update: Socks5Update,
    },
    ListSocks5Sessions,
    /// Close one session, every session from one client address, or all.
    CloseSocks5Sessions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<std::net::IpAddr>,
    },
    /// How a proxy user connects; absent while the listener is not running.
    GetSocks5Endpoint,
    /// The UDP port this node serves QUIC on; absent without a QUIC listener.
    GetQuicEndpoint,

    // Metrics queries
    GetRealtimeStats,
    GetRecentConnections,
    GetTimeBuckets {
        granularity: Granularity,
    },
    GetTopN {
        category: TopCategory,
    },
}

impl ControlOp {
    /// Reads a proxy user needs, allowed with the session key alone. Every
    /// other operation requires the admin token when one is configured.
    pub fn is_client_readable(&self) -> bool {
        matches!(
            self,
            Self::Ping
                | Self::ListNodes
                | Self::ListGroups
                | Self::GetSocks5Endpoint
                | Self::GetQuicEndpoint
        )
    }
}

/// Where a node accepts the QUIC carrier. Clients dial the host they reached
/// the node at, so its certificate must cover that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicEndpoint {
    pub port: u16,
}

impl QuicEndpoint {
    /// The QUIC address of the node reached at `host`, which may itself carry
    /// a `tcp://` or `quic://` scheme.
    pub fn upstream(&self, host: &str) -> std::io::Result<UpstreamAddress> {
        let mut address = UpstreamAddress::from_host(host, self.port)?;
        address.port = self.port;
        address.carrier = Carrier::Quic;
        Ok(address)
    }
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
    Groups { groups: Vec<NodeGroup> },
    RelayConfig { config: RelayConfig },
    RelayStatus { status: RelayStatus },
    Socks5Status { status: Socks5Status },
    Socks5Sessions { sessions: Vec<Socks5Session> },
    Socks5SessionsClosed { closed: usize },
    Socks5Endpoint { endpoint: Option<Socks5Endpoint> },
    QuicEndpoint { endpoint: Option<QuicEndpoint> },
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

pub struct ControlCodec<R, W> {
    reader: FrameReader<R>,
    writer: FrameWriter<W>,
}

impl<R, W> ControlCodec<R, W>
where
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
{
    pub fn new(reader: R, writer: W, session_key: Option<&str>) -> Result<Self> {
        Ok(Self {
            reader: FrameReader::new(reader, session_key, MAX_DATA_SIZE as usize)
                .context(ProtocolSnafu)?,
            writer: FrameWriter::new(writer, session_key, MAX_DATA_SIZE as usize)
                .context(ProtocolSnafu)?,
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
        self.reader
            .read()
            .await
            .context(ProtocolSnafu)?
            .map(|payload| serde_json::from_slice(payload).context(SerdeJsonSnafu))
            .transpose()
    }

    async fn write_message<T: Serialize>(&mut self, message: &T) -> Result<()> {
        serde_json::to_writer(self.writer.prepare().context(ProtocolSnafu)?, message)
            .context(SerdeJsonSnafu)?;
        self.writer.send().await.context(ProtocolSnafu)
    }
}

pub struct ControlClient {
    codec: ControlCodec<
        AsyncReader<tokio::io::ReadHalf<crate::secure_transport::ProxyStream>>,
        AsyncWriter<tokio::io::WriteHalf<crate::secure_transport::ProxyStream>>,
    >,
}

impl ControlClient {
    pub async fn connect(
        server_host: &str,
        server_port: u16,
        session_key: Option<String>,
    ) -> Result<Self> {
        // Explicit keys still authenticate against configured historical nodes.
        // Without one, encrypt the session using the same legacy header field.
        let session_key = Some(session_key.unwrap_or_else(crate::config::gen_random_key));
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
            .context(TransportSnafu)?;
        let session_key = if stream.is_secure() {
            None
        } else {
            session_key
        };
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
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "list nodes failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::Nodes { nodes }) => Ok(nodes),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for list_nodes".to_string(),
                },
            }),
        }
    }

    /// The node's SOCKS5 endpoint, or `None` when it is not serving one.
    pub async fn get_socks5_endpoint(&mut self) -> Result<Option<Socks5Endpoint>> {
        let resp = self
            .request(ControlRequest {
                token: None,
                op: ControlOp::GetSocks5Endpoint,
            })
            .await?;
        match resp.result {
            Some(ControlResult::Socks5Endpoint { endpoint }) if resp.ok => Ok(endpoint),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "unexpected response type for socks5 endpoint".into()),
                },
            }),
        }
    }

    /// The node's QUIC endpoint, or `None` when it has no QUIC listener. A node
    /// that predates the operation answers with an error.
    pub async fn get_quic_endpoint(&mut self) -> Result<Option<QuicEndpoint>> {
        let resp = self
            .request(ControlRequest {
                token: None,
                op: ControlOp::GetQuicEndpoint,
            })
            .await?;
        match resp.result {
            Some(ControlResult::QuicEndpoint { endpoint }) if resp.ok => Ok(endpoint),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "unexpected response type for quic endpoint".into()),
                },
            }),
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
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "get realtime stats failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::RealtimeStats { stats }) => Ok(Some(stats)),
            None => Ok(None),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_realtime_stats".to_string(),
                },
            }),
        }
    }

    pub async fn get_recent_connections(
        &mut self,
        token: Option<String>,
    ) -> Result<Vec<ConnectionRecord>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetRecentConnections,
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "get recent connections failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::Connections { connections }) => Ok(connections),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_recent_connections".to_string(),
                },
            }),
        }
    }

    pub async fn get_time_buckets(
        &mut self,
        token: Option<String>,
        granularity: Granularity,
    ) -> Result<Vec<TimeBucket>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetTimeBuckets { granularity },
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "get time buckets failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::TimeBuckets { buckets }) => Ok(buckets),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_time_buckets".to_string(),
                },
            }),
        }
    }

    pub async fn get_top_n(
        &mut self,
        token: Option<String>,
        category: TopCategory,
    ) -> Result<Vec<TopNEntry>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetTopN { category },
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp.error.unwrap_or_else(|| "get top n failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::TopN { entries }) => Ok(entries),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_top_n".to_string(),
                },
            }),
        }
    }

    pub async fn add_node(&mut self, token: Option<String>, addr: String) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::AddNode { addr },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp.error.unwrap_or_else(|| "add node failed".to_string()),
                },
            })
        }
    }

    pub async fn remove_node(&mut self, token: Option<String>, node_id: String) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::RemoveNode { node_id },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "remove node failed".to_string()),
                },
            })
        }
    }

    /// List all node groups configured on the server.
    pub async fn list_groups(&mut self, token: Option<String>) -> Result<Vec<NodeGroup>> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::ListGroups,
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "list groups failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::Groups { groups }) => Ok(groups),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for list_groups".to_string(),
                },
            }),
        }
    }

    /// Create a node group on the server.
    pub async fn create_group(
        &mut self,
        token: Option<String>,
        group_id: String,
        name: String,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::CreateGroup { group_id, name },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "create group failed".to_string()),
                },
            })
        }
    }

    /// Delete a node group from the server.
    pub async fn delete_group(&mut self, token: Option<String>, group_id: String) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::DeleteGroup { group_id },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "delete group failed".to_string()),
                },
            })
        }
    }

    /// Add a node to a group by id.
    pub async fn add_node_to_group(
        &mut self,
        token: Option<String>,
        group_id: String,
        node_id: String,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::AddNodeToGroup { group_id, node_id },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "add node to group failed".to_string()),
                },
            })
        }
    }

    /// Remove a node from a group by id.
    pub async fn remove_node_from_group(
        &mut self,
        token: Option<String>,
        group_id: String,
        node_id: String,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::RemoveNodeFromGroup { group_id, node_id },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "remove node from group failed".to_string()),
                },
            })
        }
    }

    /// Fetch the current relay configuration.
    pub async fn get_relay_config(&mut self, token: Option<String>) -> Result<RelayConfig> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetRelayConfig,
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "get relay config failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::RelayConfig { config }) => Ok(config),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_relay_config".to_string(),
                },
            }),
        }
    }

    /// Replace the relay configuration in a single request.
    pub async fn set_relay_config(
        &mut self,
        token: Option<String>,
        config: RelayConfig,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::SetRelayConfig { config },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "set relay config failed".to_string()),
                },
            })
        }
    }

    /// Enable or disable relay mode.
    pub async fn set_relay_enabled(&mut self, token: Option<String>, enabled: bool) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::SetRelayEnabled { enabled },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "set relay enabled failed".to_string()),
                },
            })
        }
    }

    /// Add a relay target to the current configuration.
    pub async fn add_relay_target(
        &mut self,
        token: Option<String>,
        target: UpstreamTarget,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::AddRelayTarget { target },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "add relay target failed".to_string()),
                },
            })
        }
    }

    /// Remove a relay target by index.
    pub async fn remove_relay_target(&mut self, token: Option<String>, index: usize) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::RemoveRelayTarget { index },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "remove relay target failed".to_string()),
                },
            })
        }
    }

    /// Switch the relay load-balancing algorithm.
    pub async fn set_relay_algo(
        &mut self,
        token: Option<String>,
        algo: LoadBalanceAlgo,
    ) -> Result<()> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::SetRelayAlgo { algo },
            })
            .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "set relay algo failed".to_string()),
                },
            })
        }
    }

    /// Fetch a relay status snapshot (health + connection counts).
    pub async fn get_relay_status(&mut self, token: Option<String>) -> Result<RelayStatus> {
        let resp = self
            .request(ControlRequest {
                token,
                op: ControlOp::GetRelayStatus,
            })
            .await?;
        if !resp.ok {
            return Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: resp
                        .error
                        .unwrap_or_else(|| "get relay status failed".to_string()),
                },
            });
        }
        match resp.result {
            Some(ControlResult::RelayStatus { status }) => Ok(status),
            _ => Err(ControlError::Protocol {
                source: ProxyError::Protocol {
                    detail: "unexpected response type for get_relay_status".to_string(),
                },
            }),
        }
    }
}

pub fn is_control_target(host: &str, port: u16) -> bool {
    host == CONTROL_HOST && port == CONTROL_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_endpoint_is_client_readable_with_a_stable_wire_shape() {
        assert!(ControlOp::GetQuicEndpoint.is_client_readable());
        let request: ControlRequest =
            serde_json::from_str(r#"{"token":null,"type":"get_quic_endpoint"}"#).unwrap();
        assert!(matches!(request.op, ControlOp::GetQuicEndpoint));
        for (endpoint, wire) in [
            (
                Some(QuicEndpoint { port: 10811 }),
                serde_json::json!({"type":"quic_endpoint","endpoint":{"port":10811}}),
            ),
            (
                None,
                serde_json::json!({"type":"quic_endpoint","endpoint":null}),
            ),
        ] {
            let result = ControlResult::QuicEndpoint { endpoint };
            assert_eq!(serde_json::to_value(&result).unwrap(), wire);
        }
    }

    #[test]
    fn quic_endpoint_keeps_the_reached_host_and_switches_the_carrier() {
        let endpoint = QuicEndpoint { port: 10811 };
        for host in [
            "proxy.example",
            "tcp://proxy.example:1081",
            "quic://proxy.example:9",
        ] {
            let address = endpoint.upstream(host).unwrap();
            assert_eq!(
                (address.host.as_str(), address.port, address.carrier),
                ("proxy.example", 10811, Carrier::Quic)
            );
        }
        assert_eq!(
            endpoint.upstream("2001:db8::1").unwrap().qualified_host(),
            "quic://[2001:db8::1]"
        );
    }
}
