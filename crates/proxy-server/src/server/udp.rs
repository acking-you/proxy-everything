//! Remote half of a SOCKS5 UDP association.

use proxy_core::datagram::{
    DatagramTunnelReader, DatagramTunnelWriter, UDP_ASSOCIATION_READY,
    create_direct_datagram_relay, create_socks5_datagram_relay, parse_socks5_udp_packet,
    udp_association_idle_timeout,
};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::{MyAsyncReadExt, MyAsyncWriteExt, ProxyError};
use snafu::ResultExt;
use tokio::time::Instant;

use super::connection::TransferStats;
use super::{DatagramSnafu, Result};

pub(super) async fn proxy_udp_association<R, W>(
    client_reader: R,
    mut client_writer: W,
    key: Option<&str>,
    upstream_proxy: Option<&ExternalProxyTarget>,
) -> Result<TransferStats>
where
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
{
    let relay_result = match upstream_proxy {
        Some(proxy) => create_socks5_datagram_relay(proxy).await,
        None => create_direct_datagram_relay().await,
    };
    let relay = match relay_result {
        Ok(relay) => relay,
        Err(error) => {
            tracing::warn!(
                upstream = ?upstream_proxy.map(ExternalProxyTarget::display_url),
                %error,
                "failed to initialize remote UDP relay"
            );
            let _ = client_writer.write_all(&[1]).await;
            return Err(error).context(DatagramSnafu);
        }
    };
    // The client must not return a successful SOCKS5 UDP ASSOCIATE response
    // until the final server has allocated its UDP sockets or completed the
    // external SOCKS5 handshake. This byte also travels transparently through
    // proxy-server relay nodes before normal datagram framing begins.
    client_writer
        .write_all(&[UDP_ASSOCIATION_READY])
        .await
        .map_err(|source| ProxyError::Io {
            context: "udp_associate",
            detail: "send UDP association readiness".to_string(),
            source,
        })
        .context(DatagramSnafu)?;
    tracing::info!(
        upstream = %upstream_proxy
            .map(ExternalProxyTarget::display_url)
            .unwrap_or_else(|| "direct://internet".to_string()),
        datagram_encryption = key.is_some(),
        "remote UDP association is ready"
    );
    let mut tunnel_reader = DatagramTunnelReader::new(client_reader, key).context(DatagramSnafu)?;
    let mut tunnel_writer = DatagramTunnelWriter::new(client_writer, key).context(DatagramSnafu)?;
    let (mut relay_reader, relay_writer, _relay_guard) = relay.into_parts();

    let mut stats = TransferStats::default();
    let started = Instant::now();
    let idle_timeout = udp_association_idle_timeout();
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    // Datagram framing is independent in each direction. A single failed UDP
    // send is intentionally non-fatal, while loss of the reliable tunnel or
    // relay socket ends the association and is recorded in connection metrics.
    let close_reason = loop {
        tokio::select! {
            request = tunnel_reader.recv_ref() => {
                let request = match request {
                    Ok(request) => request,
                    Err(error) if error.is_expected_disconnect() => break "client_tunnel_closed",
                    Err(error) => return Err(error).context(DatagramSnafu),
                };
                let packet = match parse_socks5_udp_packet(request) {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::debug!(%error, "discarding malformed UDP tunnel request");
                        continue;
                    }
                };
                let payload_len = packet.payload.len() as u64;
                tracing::debug!(
                    direction = "tunnel_to_remote",
                    remote = ?packet.destination,
                    payload_bytes = payload_len,
                    "relaying UDP request from proxy client"
                );
                if let Err(error) = relay_writer.send(request).await {
                    tracing::debug!(
                        remote = ?packet.destination,
                        payload_bytes = payload_len,
                        %error,
                        "failed to relay one UDP request; association remains active"
                    );
                    continue;
                }
                stats.bytes_up = stats.bytes_up.saturating_add(payload_len);
                reset_idle(&mut idle_sleep, idle_timeout);
            }
            response = relay_reader.recv() => {
                let response = response.context(DatagramSnafu)?;
                let packet = match parse_socks5_udp_packet(&response) {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::debug!(%error, "discarding malformed UDP relay response");
                        continue;
                    }
                };
                let payload_len = packet.payload.len() as u64;
                tunnel_writer.send(&response).await.context(DatagramSnafu)?;
                tracing::debug!(
                    direction = "remote_to_tunnel",
                    remote = ?packet.destination,
                    payload_bytes = payload_len,
                    "relayed UDP response to proxy client"
                );
                stats.bytes_down = stats.bytes_down.saturating_add(payload_len);
                stats.latency_ms.get_or_insert(started.elapsed().as_millis() as u64);
                reset_idle(&mut idle_sleep, idle_timeout);
            }
            _ = &mut idle_sleep => {
                tracing::debug!(?idle_timeout, "remote UDP association expired after being idle");
                break "idle_timeout";
            }
        }
    };

    tracing::info!(
        close_reason,
        bytes_up = stats.bytes_up,
        bytes_down = stats.bytes_down,
        first_response_latency_ms = ?stats.latency_ms,
        "remote UDP association closed"
    );

    Ok(stats)
}

fn reset_idle(sleep: &mut std::pin::Pin<&mut tokio::time::Sleep>, timeout: std::time::Duration) {
    sleep.as_mut().reset(Instant::now() + timeout);
}
