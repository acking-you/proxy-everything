//! Node discovery and synchronization helpers.

use std::net::SocketAddr;
use std::sync::Arc;

use proxy_core::control::{ControlOp, ControlRequest};
use proxy_core::util::error_report;

use super::ServerContext;

pub(super) fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Some((socket.ip().to_string(), socket.port()));
    }
    if let Some(bracket_end) = addr.find("]:") {
        let host = addr.get(1..bracket_end)?;
        let port = addr.get(bracket_end + 2..)?.trim().parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    let idx = addr.rfind(':')?;
    let host = addr[..idx].trim();
    let port = addr[idx + 1..].trim().parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

pub(super) async fn broadcast_nodes(ctx: Arc<ServerContext>) {
    if let Some(id) = ctx.self_node_id.as_deref() {
        ctx.nodes.update_peer_seen(id);
    }
    let nodes = ctx.nodes.list_all_nodes();
    let blocked = ctx.nodes.blocked_list();
    for node in nodes.iter() {
        if ctx.self_node_id.as_deref() == Some(node.node_id.as_str()) {
            continue;
        }
        if ctx.nodes.is_self_addr(&node.addr) {
            continue;
        }
        let Some((host, port)) = split_host_port(&node.addr) else {
            tracing::warn!("invalid node addr: {}", node.addr);
            continue;
        };
        let session_key = ctx.control_session_key.clone();
        let mut client =
            match proxy_core::control::ControlClient::connect(&host, port, session_key).await {
                Ok(client) => client,
                Err(err) => {
                    tracing::debug!("sync connect {} failed: {}", node.addr, error_report(&err));
                    continue;
                }
            };
        let request = ControlRequest {
            token: ctx.admin_token.clone(),
            op: ControlOp::SyncNodes {
                nodes: nodes.clone(),
                blocked: blocked.clone(),
            },
        };
        match client.request(request).await {
            Ok(_) => {
                ctx.nodes.update_peer_seen(&node.node_id);
            }
            Err(err) => {
                tracing::debug!("sync nodes to {} failed: {}", node.addr, error_report(&err));
            }
        }
    }
    if let Err(err) = ctx.nodes.save() {
        tracing::warn!("save nodes failed: {}", error_report(&err));
    }
}
