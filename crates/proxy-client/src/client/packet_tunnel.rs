//! A packet tunnel hosted by the operating system, without device or route setup.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tokio_util::task::TaskTracker;
use tun2proxy::{ArgDns, ArgProxy, ArgUdpStrategy, Args, VirtualDnsState};

use super::{ClientConfig, ClientRuntimeConfig, run_client_with_listener_runtime_config};

pub const PACKET_MTU: u16 = 1500;
const QUEUE_CAPACITY: usize = 256;
pub const VIRTUAL_DNS: &str = "10.77.0.1";

/// Configuration passed by the containing app, with credentials read from the
/// shared Keychain by the extension. Paths are supplied separately by the host.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketTunnelConfig {
    pub server_host: String,
    pub server_port: u16,
    pub local_port: u16,
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub auto_proxy: bool,
    #[serde(default)]
    pub udp_enabled: bool,
    #[serde(default)]
    pub udp_direct_fallback: bool,
    #[serde(default = "legacy_fake_ip")]
    pub tun_fake_ip: bool,
    #[serde(default = "super::tun::default_dns_server")]
    pub tun_dns_server: std::net::IpAddr,
    #[serde(default)]
    pub reverse_geo: bool,
    #[serde(default)]
    pub need_codec_ips: Option<String>,
    #[serde(default)]
    pub force_codec: bool,
}

fn legacy_fake_ip() -> bool {
    true
}

impl PacketTunnelConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.server_host.trim().is_empty()
            || self.server_host.len() > 1024
            || self.server_host.chars().any(char::is_control)
            || self.server_port == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid upstream endpoint",
            ));
        }
        if self.session_key.as_ref().is_some_and(|key| key.len() != 32) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session key must contain exactly 32 bytes",
            ));
        }
        Ok(())
    }
}

/// Validate the IP envelope before copying it across the native boundary.
pub fn validate_packet(packet: &[u8]) -> io::Result<()> {
    let valid = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 15) * 4;
            header_len >= 20
                && header_len <= packet.len()
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
        }
        _ => false,
    };
    if !valid || packet.len() > usize::from(PACKET_MTU) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or oversized IP packet",
        ));
    }
    Ok(())
}

struct PacketDevice {
    input: mpsc::Receiver<Vec<u8>>,
    output: PollSender<Vec<u8>>,
}

impl AsyncRead for PacketDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.input.poll_recv(cx) {
            Poll::Ready(Some(packet)) if packet.len() <= buf.remaining() => {
                buf.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet read buffer is too small",
            ))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = validate_packet(buf) {
            return Poll::Ready(Err(error));
        }
        match self.output.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => Poll::Ready(
                self.output
                    .send_item(buf.to_vec())
                    .map(|()| buf.len())
                    .map_err(|_| io::ErrorKind::BrokenPipe.into()),
            ),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.output.close();
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketWrite {
    Queued,
    Congested,
    Closed,
}

/// All network tasks and packet queues belong to this one provider session.
/// Drop only after the native reader and writer have stopped using the handle.
pub struct PacketTunnelRuntime {
    runtime: Option<Runtime>,
    cancel: CancellationToken,
    tracker: TaskTracker,
    input: mpsc::Sender<Vec<u8>>,
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
    failure: Arc<Mutex<Option<String>>>,
    pub local_port: u16,
}

impl PacketTunnelRuntime {
    pub fn start(
        config: PacketTunnelConfig,
        cache_dir: PathBuf,
        runtime: Runtime,
    ) -> io::Result<Self> {
        config.validate()?;
        super::tun::install_tun_log_bridge();
        let listener = runtime.block_on(TcpListener::bind(("127.0.0.1", config.local_port)))?;
        let local_port = listener.local_addr()?.port();
        proxy_core::config::runtime::init_config(
            config.server_host,
            config.server_port,
            config.reverse_geo,
            config
                .need_codec_ips
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            config.session_key,
        );
        let virtual_dns = VirtualDnsState::default();
        runtime
            .block_on(virtual_dns.enable_persistence_in(cache_dir.clone()))
            .map_err(|error| io::Error::other(error.to_string()))?;
        let client_config = ClientRuntimeConfig {
            client: ClientConfig {
                enable_auto_proxy: config.auto_proxy,
                enable_udp: config.udp_enabled,
                cache_dir: Some(cache_dir),
            },
            upstream_proxy: None,
            tun: None,
            // NE exempts the provider's sockets in the kernel; no process
            // enumeration or userspace interface binding is needed for direct
            // decisions made by the existing auto-proxy implementation.
            force_proxy: None,
        };
        let (input, input_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (output_tx, output) = mpsc::channel(QUEUE_CAPACITY);
        let device = PacketDevice {
            input: input_rx,
            output: PollSender::new(output_tx),
        };
        let args = Args {
            proxy: ArgProxy::try_from(format!("socks5://127.0.0.1:{local_port}").as_str())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid loopback proxy")
                })?,
            setup: false,
            dns: if config.tun_fake_ip {
                ArgDns::Virtual
            } else {
                ArgDns::OverTcp
            },
            virtual_dns_portals: vec![VIRTUAL_DNS.parse().expect("constant IPv4 address")],
            dns_addr: config.tun_dns_server,
            ipv6_enabled: true,
            icmp_echo: true,
            udp_strategy: if config.udp_enabled {
                ArgUdpStrategy::Proxy
            } else if config.udp_direct_fallback {
                ArgUdpStrategy::Direct
            } else {
                ArgUdpStrategy::Block
            },
            mtu: PACKET_MTU,
            max_sessions: 4096,
            tcp_read_buffer_size: 64 * 1024,
            ..Args::default()
        };
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let failure = Arc::new(Mutex::new(None));
        let client_cancel = cancel.clone();
        let client_tracker = tracker.clone();
        let client_failure = failure.clone();
        tracker.spawn_on(
            async move {
                if config.force_codec {
                    run_client_with_listener_runtime_config::<true>(
                        listener,
                        client_cancel.clone(),
                        Some(client_tracker),
                        Some(client_config),
                    )
                    .await;
                } else {
                    run_client_with_listener_runtime_config::<false>(
                        listener,
                        client_cancel.clone(),
                        Some(client_tracker),
                        Some(client_config),
                    )
                    .await;
                }
                finish_worker(
                    &client_cancel,
                    &client_failure,
                    "proxy listener stopped unexpectedly".to_owned(),
                );
            },
            runtime.handle(),
        );
        let packet_cancel = cancel.clone();
        let packet_failure = failure.clone();
        tracker.spawn_on(
            async move {
                let result = tun2proxy::run_with_system_managed_network(
                    device,
                    PACKET_MTU,
                    args,
                    packet_cancel.clone(),
                    Some(virtual_dns),
                )
                .await;
                finish_worker(
                    &packet_cancel,
                    &packet_failure,
                    result.err().map_or_else(
                        || "packet forwarding stopped unexpectedly".to_owned(),
                        |error| error.to_string(),
                    ),
                );
            },
            runtime.handle(),
        );
        Ok(Self {
            runtime: Some(runtime),
            cancel,
            tracker,
            input,
            output: Mutex::new(output),
            failure,
            local_port,
        })
    }

    pub fn write_packet(&self, bytes: &[u8]) -> io::Result<PacketWrite> {
        validate_packet(bytes)?;
        if self.cancel.is_cancelled() {
            return Ok(PacketWrite::Closed);
        }
        Ok(match self.input.try_send(bytes.to_vec()) {
            Ok(()) => PacketWrite::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => PacketWrite::Congested,
            Err(mpsc::error::TrySendError::Closed(_)) => PacketWrite::Closed,
        })
    }

    /// Wait on a dedicated native reader thread. Timeout bounds cancellation
    /// latency without spinning or accumulating callbacks on a dispatch queue.
    pub fn read_packet(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let mut output = self
            .output
            .lock()
            .map_err(|_| io::Error::other("packet reader lock poisoned"))?;
        let runtime = self.runtime.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        runtime.block_on(async {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => Err(io::ErrorKind::BrokenPipe.into()),
                packet = output.recv() => packet.map(Some).ok_or(io::ErrorKind::BrokenPipe.into()),
                _ = tokio::time::sleep(timeout) => Ok(None),
            }
        })
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn last_error(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|error| error.clone())
    }
}

fn finish_worker(cancel: &CancellationToken, failure: &Mutex<Option<String>>, error: String) {
    if !cancel.is_cancelled() {
        if let Ok(mut failure) = failure.lock() {
            *failure = Some(error);
        }
        cancel.cancel();
    }
}

impl Drop for PacketTunnelRuntime {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tracker.close();
        if let Some(runtime) = self.runtime.take() {
            let stopped = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), self.tracker.wait()).await
            });
            if stopped.is_err() {
                tracing::warn!("packet tunnel tasks exceeded shutdown deadline");
            }
            // Dropping the runtime aborts any remaining tracked network work.
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn old_packet_configs_keep_fake_ip_and_explicit_dns_policy_round_trips() {
        let mut value =
            serde_json::json!({"serverHost": "proxy.test", "serverPort": 1081, "localPort": 0});
        let old: PacketTunnelConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(old.tun_fake_ip);
        value["tunFakeIp"] = false.into();
        value["tunDnsServer"] = "10.20.30.53".into();
        let current: PacketTunnelConfig = serde_json::from_value(value).unwrap();
        assert!(!current.tun_fake_ip);
        assert_eq!(current.tun_dns_server.to_string(), "10.20.30.53");
    }

    fn ipv4(marker: u8) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[4] = marker;
        packet
    }

    #[test]
    fn rejects_truncated_mismatched_and_oversized_packets() {
        assert!(validate_packet(&ipv4(0)).is_ok());
        assert!(validate_packet(&[]).is_err());
        assert!(validate_packet(&ipv4(0)[..19]).is_err());
        let mut bad = ipv4(0);
        bad[0] = 0x4f;
        assert!(validate_packet(&bad).is_err());
        let mut v6 = vec![0; 40];
        v6[0] = 0x60;
        assert!(validate_packet(&v6).is_ok());
        v6[5] = 1;
        assert!(validate_packet(&v6).is_err());
        let mut large = vec![0; 1501];
        large[0] = 0x45;
        large[2..4].copy_from_slice(&1501_u16.to_be_bytes());
        assert!(validate_packet(&large).is_err());
    }

    #[tokio::test]
    async fn reads_one_complete_packet_at_a_time_in_order() {
        let (tx, rx) = mpsc::channel(2);
        let (out, _) = mpsc::channel(2);
        let mut device = PacketDevice {
            input: rx,
            output: PollSender::new(out),
        };
        tx.send(ipv4(1)).await.unwrap();
        tx.send(ipv4(2)).await.unwrap();
        let mut buffer = [0; 128];
        for marker in [1, 2] {
            assert_eq!(device.read(&mut buffer).await.unwrap(), 20);
            assert_eq!(buffer[4], marker);
        }
        drop(tx);
        assert_eq!(device.read(&mut buffer).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn output_backpressure_wakes_when_consumer_drains() {
        let (_, rx) = mpsc::channel(1);
        let (out, mut reader) = mpsc::channel(1);
        let mut device = PacketDevice {
            input: rx,
            output: PollSender::new(out),
        };
        device.write_all(&ipv4(1)).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), device.write_all(&ipv4(2)))
                .await
                .is_err()
        );
        assert_eq!(reader.recv().await.unwrap()[4], 1);
        device.write_all(&ipv4(2)).await.unwrap();
        assert_eq!(reader.recv().await.unwrap()[4], 2);
        drop(reader);
        assert!(device.write_all(&ipv4(3)).await.is_err());
    }
}
