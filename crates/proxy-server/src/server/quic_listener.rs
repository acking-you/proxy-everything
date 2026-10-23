//! Bounded connection and stream admission, sharing TCP's proxy session handler.
use std::sync::Arc;

use proxy_core::quic::{AuthenticatedConnection, DRAIN_TIMEOUT, EndpointOwner, MAX_CONNECTIONS};
use proxy_core::upstream::CarrierStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::ServerContext;
use super::connection::handle_connect;

pub(super) async fn run(
    endpoint: Arc<EndpointOwner>,
    ctx: Arc<ServerContext>,
    cancel: CancellationToken,
) {
    let connection_slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let stream_slots = Arc::new(Semaphore::new(512));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            incoming = endpoint.0.accept() => {
                let Some(incoming) = incoming else { break };
                if !incoming.remote_address_validated() {
                    let _ = incoming.retry();
                    continue;
                }
                let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let endpoint = endpoint.clone();
                let ctx = ctx.clone();
                let cancel = cancel.clone();
                let stream_slots = stream_slots.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let key = proxy_core::config::runtime::with_secret_key(|key, _| key.to_vec());
                    let connection = tokio::select! {
                        _ = cancel.cancelled() => return,
                        result = AuthenticatedConnection::accept(incoming, endpoint, &key) => match result {
                            Ok(connection) => connection,
                            Err(error) => { tracing::debug!(carrier = "quic", %error, "QUIC connection rejected"); return; }
                        }
                    };
                    let mut streams = JoinSet::new();
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break,
                            Some(_) = streams.join_next(), if !streams.is_empty() => {},
                            stream = connection.accept_stream() => {
                                let Ok(stream) = stream else { break };
                                let Ok(permit) = stream_slots.clone().try_acquire_owned() else { drop(stream); continue };
                                let ctx = ctx.clone();
                                streams.spawn(async move {
                                    let _permit = permit;
                                    let peer = stream.peer_addr();
                                    let _ = handle_connect(CarrierStream::Quic(Box::new(stream)), peer, ctx).await;
                                });
                            }
                        }
                    }
                    streams.abort_all();
                    while streams.join_next().await.is_some() {}
                    connection.close();
                });
            }
        }
    }
    endpoint.0.close(0u32.into(), b"shutdown");
    while connections.join_next().await.is_some() {}
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.0.wait_idle()).await;
}
