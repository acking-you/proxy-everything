//! Control plane handling.

use std::sync::Arc;

use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::control::{
    ControlCodec, ControlOp, ControlRequest, ControlResponse, ControlResult, TopNEntry,
};
use proxy_core::metrics::current_time_ms;
use proxy_core::nodes::NodeInfo;
use proxy_core::util::error_report;
use snafu::ResultExt;

use super::discovery::broadcast_nodes;
use super::{ControlSnafu, Result, ServerContext};

pub(super) async fn handle_control_session(
    mut codec: ControlCodec<
        AsyncReader<tokio::net::tcp::OwnedReadHalf>,
        AsyncWriter<tokio::net::tcp::OwnedWriteHalf>,
    >,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    loop {
        let request = match codec.read_request().await.context(ControlSnafu)? {
            Some(req) => req,
            None => break,
        };
        let response = handle_control_request(request, ctx.clone());
        codec
            .write_response(&response)
            .await
            .context(ControlSnafu)?;
    }
    Ok(())
}

pub(super) fn handle_control_request(
    request: ControlRequest,
    ctx: Arc<ServerContext>,
) -> ControlResponse {
    if let Some(expected) = ctx.admin_token.as_ref()
        && request.token.as_deref() != Some(expected.as_str())
    {
        return ControlResponse {
            ok: false,
            error: Some("unauthorized".to_string()),
            result: None,
        };
    }

    match request.op {
        ControlOp::Ping => ControlResponse {
            ok: true,
            error: None,
            result: Some(ControlResult::Pong),
        },
        ControlOp::AddNode { addr } => {
            if ctx.self_node_id.is_none() {
                return ControlResponse {
                    ok: false,
                    error: Some(
                        "NODE_ADVERTISE_ADDR not set and bind address cannot be used for node sync"
                            .to_string(),
                    ),
                    result: None,
                };
            }
            ctx.nodes.unblock_peer(&addr);
            let node = NodeInfo {
                node_id: addr.clone(),
                addr,
                last_seen_ms: current_time_ms(),
            };
            ctx.nodes.upsert_peer(node);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {}", error_report(&err));
            }
            let ctx_clone = ctx.clone();
            tokio::spawn(async move {
                broadcast_nodes(ctx_clone).await;
            });
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::RemoveNode { node_id } => {
            if ctx.self_node_id.as_deref() == Some(node_id.as_str()) {
                return ControlResponse {
                    ok: false,
                    error: Some("cannot remove self node".to_string()),
                    result: None,
                };
            }
            ctx.nodes.block_peer(&node_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {}", error_report(&err));
            }
            let ctx_clone = ctx.clone();
            tokio::spawn(async move {
                broadcast_nodes(ctx_clone).await;
            });
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::ListNodes => {
            let nodes = ctx.nodes.list_all_nodes();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Nodes { nodes }),
            }
        }
        ControlOp::SyncNodes { nodes, blocked } => {
            ctx.nodes.merge_blocked(blocked);
            ctx.nodes.upsert_peers(nodes);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {}", error_report(&err));
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::GetRealtimeStats => {
            let stats = ctx.metrics.get_realtime_snapshot();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RealtimeStats { stats }),
            }
        }
        ControlOp::GetRecentConnections => {
            let connections = ctx.metrics.get_recent_connections(100);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Connections { connections }),
            }
        }
        ControlOp::GetTimeBuckets { granularity } => {
            let buckets = ctx.metrics.get_time_buckets(granularity, 60);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::TimeBuckets { buckets }),
            }
        }
        ControlOp::GetTopN { category } => {
            let entries = ctx
                .metrics
                .get_top_n(category, 100)
                .into_iter()
                .map(|(key, stats)| TopNEntry { key, stats })
                .collect();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::TopN { entries }),
            }
        }
        // Group management
        ControlOp::CreateGroup { group_id, name } => {
            if ctx.nodes.create_group(group_id, name) {
                if let Err(err) = ctx.nodes.save() {
                    tracing::warn!("save nodes failed: {}", error_report(&err));
                }
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("group already exists".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::DeleteGroup { group_id } => {
            ctx.nodes.delete_group(&group_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {}", error_report(&err));
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::ListGroups => {
            let groups = ctx.nodes.list_groups();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Groups { groups }),
            }
        }
        ControlOp::AddNodeToGroup { group_id, node_id } => {
            if ctx.nodes.add_node_to_group(&group_id, node_id) {
                if let Err(err) = ctx.nodes.save() {
                    tracing::warn!("save nodes failed: {}", error_report(&err));
                }
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("group not found".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::RemoveNodeFromGroup { group_id, node_id } => {
            ctx.nodes.remove_node_from_group(&group_id, &node_id);
            if let Err(err) = ctx.nodes.save() {
                tracing::warn!("save nodes failed: {}", error_report(&err));
            }
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        // Relay configuration
        ControlOp::GetRelayConfig => {
            let config = ctx.relay.get_config();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RelayConfig { config }),
            }
        }
        ControlOp::SetRelayConfig { config } => {
            ctx.relay.set_config(config);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::SetRelayEnabled { enabled } => {
            ctx.relay.set_enabled(enabled);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::AddRelayTarget { target } => {
            ctx.relay.add_target(target);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::RemoveRelayTarget { index } => {
            if ctx.relay.remove_target(index) {
                ControlResponse {
                    ok: true,
                    error: None,
                    result: Some(ControlResult::Ack),
                }
            } else {
                ControlResponse {
                    ok: false,
                    error: Some("invalid target index".to_string()),
                    result: None,
                }
            }
        }
        ControlOp::SetRelayAlgo { algo } => {
            ctx.relay.set_algo(algo);
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::Ack),
            }
        }
        ControlOp::GetRelayStatus => {
            let status = ctx.relay.get_status();
            ControlResponse {
                ok: true,
                error: None,
                result: Some(ControlResult::RelayStatus { status }),
            }
        }
    }
}
