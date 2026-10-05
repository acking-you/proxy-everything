//! Real Echo probes at the final proxy exit. Only Echo requests are accepted.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use proxy_core::protocol::{FrameReader, FrameWriter};
use proxy_core::{MyAsyncReadExt, MyAsyncWriteExt};
use snafu::ResultExt;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};

use super::connection::TransferStats;
use super::{IoSnafu, ProxySnafu, Result, ServerError};

const FRAME_LIMIT: usize = u16::MAX as usize + 16;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
static ECHO_SLOTS: Semaphore = Semaphore::const_new(64);
static NEXT_PROBE: AtomicU32 = AtomicU32::new(1);

pub(super) async fn proxy_echo<R, W>(
    reader: R,
    writer: W,
    host: &str,
    family: u16,
    key: Option<&str>,
) -> Result<TransferStats>
where
    R: MyAsyncReadExt + Send + Unpin,
    W: MyAsyncWriteExt + Send + Unpin,
{
    let _permit = ECHO_SLOTS.try_acquire().map_err(|_| ServerError::Io {
        detail: "ICMP Echo capacity exhausted".into(),
        source: io::ErrorKind::WouldBlock.into(),
    })?;
    if family != 4 && family != 6 {
        return Err(ServerError::Io {
            detail: "invalid ICMP Echo family".into(),
            source: io::ErrorKind::InvalidInput.into(),
        });
    }
    let mut reader = FrameReader::new(reader, key, FRAME_LIMIT).context(ProxySnafu)?;
    let mut writer = FrameWriter::new(writer, key, FRAME_LIMIT).context(ProxySnafu)?;
    let mut probe = timeout(PROBE_TIMEOUT, EchoSocket::connect(host, family == 6))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|result| result)
        .context(IoSnafu {
            detail: "create remote ICMP Echo socket (check OS permissions)",
        })?;
    let mut stats = TransferStats::default();
    let started = Instant::now();
    loop {
        let request = match timeout(IDLE_TIMEOUT, reader.read()).await {
            Ok(result) => result.context(ProxySnafu)?,
            Err(_) => return Ok(stats),
        };
        let Some(request) = request else {
            return Ok(stats);
        };
        let exchange = async {
            let reply = probe.echo(request).await.context(IoSnafu {
                detail: "remote ICMP Echo probe",
            })?;
            stats.bytes_up += request.len() as u64;
            stats.bytes_down += reply.len() as u64;
            stats
                .latency_ms
                .get_or_insert(started.elapsed().as_millis() as u64);
            writer
                .prepare()
                .context(ProxySnafu)?
                .extend_from_slice(reply);
            writer.send().await.context(ProxySnafu)
        };
        timeout(PROBE_TIMEOUT, exchange)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
            .context(IoSnafu {
                detail: "ICMP Echo deadline",
            })??;
        // A timeout/error drops the entire socket and stream. A late reply
        // cannot be mistaken for a request on a replacement connection.
    }
}

struct EchoSocket {
    socket: UdpSocket,
    target: SocketAddr,
    kernel_identifier: Option<u16>,
    ipv4_header: bool,
    sent: u32,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,
}

impl EchoSocket {
    async fn connect(host: &str, ipv6: bool) -> io::Result<Self> {
        let target = tokio::net::lookup_host((host, 0))
            .await?
            .find(|address| {
                address.is_ipv6() == ipv6
                    && !address.ip().is_multicast()
                    && !address.ip().is_unspecified()
                    && address.ip() != std::net::Ipv4Addr::BROADCAST
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no unicast Echo target in requested address family",
                )
            })?;
        let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let protocol = if ipv6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        // Linux ping sockets need no raw-socket capability when allowed by
        // ping_group_range. Other systems can use their permitted raw socket.
        let (socket, datagram) = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
            Ok(socket) => (socket, true),
            Err(_) => (Socket::new(domain, Type::RAW, Some(protocol))?, false),
        };
        socket.set_nonblocking(true)?;
        socket.connect(&target.into())?;
        let kernel_identifier = if datagram && cfg!(any(target_os = "linux", target_os = "android"))
        {
            Some(
                socket
                    .local_addr()?
                    .as_socket()
                    .ok_or_else(|| io::Error::other("invalid ICMP socket address"))?
                    .port(),
            )
        } else {
            None
        };
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
            target,
            kernel_identifier,
            ipv4_header: !ipv6 && kernel_identifier.is_none(),
            sent: 0,
            outgoing: Vec::new(),
            incoming: Vec::new(),
        })
    }

    async fn echo(&mut self, request: &[u8]) -> io::Result<&[u8]> {
        let ipv6 = self.target.is_ipv6();
        if !(8..=u16::MAX as usize).contains(&request.len())
            || request[..2] != [if ipv6 { 128 } else { 8 }, 0]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only ICMP Echo requests are supported",
            ));
        }
        if self.sent == u16::MAX as u32 {
            return Err(io::Error::other(
                "ICMP socket sequence exhausted; reconnect",
            ));
        }
        self.sent += 1;
        let token = NEXT_PROBE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| io::Error::other("ICMP probe identifiers exhausted"))?;
        self.outgoing.clear();
        self.outgoing.extend_from_slice(request);
        self.outgoing[2..4].fill(0);
        self.outgoing[4..8].copy_from_slice(&token.to_be_bytes());
        if let Some(identifier) = self.kernel_identifier {
            self.outgoing[4..6].copy_from_slice(&identifier.to_be_bytes());
            self.outgoing[6..8].copy_from_slice(&(self.sent as u16).to_be_bytes());
        }
        // ICMPv6 sockets supply/check the pseudo-header checksum in the kernel.
        if !ipv6 {
            let checksum = internet_checksum::checksum(&self.outgoing);
            self.outgoing[2..4].copy_from_slice(&checksum);
        }
        if self.socket.send(&self.outgoing).await? != self.outgoing.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        // Include room for IPv4 options; never allocate from an untrusted
        // received IP length. The tunnel's request length was already bounded.
        self.incoming.resize(request.len() + 60, 0);
        loop {
            let (length, source) = self.socket.recv_from(&mut self.incoming).await?;
            if source.ip() != self.target.ip() {
                continue;
            }
            let Some(offset) = reply_offset(&self.incoming[..length], self.ipv4_header) else {
                continue;
            };
            let reply = &self.incoming[offset..length];
            if !matches_reply(reply, &self.outgoing, ipv6) {
                continue;
            }
            // Preserve the bytes actually received. Only the translated Echo
            // identifier/sequence and the TUN-side checksum need restoration.
            self.incoming[offset + 4..offset + 8].copy_from_slice(&request[4..8]);
            return Ok(&self.incoming[offset..length]);
        }
    }
}

fn reply_offset(packet: &[u8], ipv4_header: bool) -> Option<usize> {
    if !ipv4_header {
        return Some(0);
    }
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return None;
    }
    let offset = (packet[0] & 15) as usize * 4;
    let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    (offset >= 20 && offset <= packet.len() && length == packet.len()).then_some(offset)
}

fn matches_reply(reply: &[u8], request: &[u8], ipv6: bool) -> bool {
    reply.len() == request.len()
        && reply.len() >= 8
        && reply[..2] == [if ipv6 { 129 } else { 0 }, 0]
        && reply[4..] == request[4..]
        && (ipv6 || internet_checksum::checksum(reply) == [0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unrelated_truncated_and_corrupt_replies() {
        let request = [8, 0, 0, 0, 1, 2, 3, 4, 17];
        let mut reply = request;
        reply[0] = 0;
        let checksum = internet_checksum::checksum(&reply);
        reply[2..4].copy_from_slice(&checksum);
        assert!(matches_reply(&reply, &request, false));
        assert!(!matches_reply(&reply[..8], &request, false));
        reply[8] ^= 1;
        assert!(!matches_reply(&reply, &request, false));
        reply[8] ^= 1;
        reply[6] ^= 1;
        assert!(!matches_reply(&reply, &request, false));
        reply[6] ^= 1;
        reply[2] ^= 1;
        assert!(!matches_reply(&reply, &request, false));
    }

    #[test]
    fn validates_raw_ipv4_header_before_slicing() {
        let mut packet = [0; 36];
        packet[0] = 0x47; // Seven header words, including options.
        packet[2..4].copy_from_slice(&36u16.to_be_bytes());
        packet[9] = 1;
        assert_eq!(reply_offset(&packet, true), Some(28));
        assert_eq!(reply_offset(&packet[..35], true), None);
        packet[0] = 0x4f;
        assert_eq!(reply_offset(&packet, true), None);
        packet[0] = 0x41;
        assert_eq!(reply_offset(&packet, true), None);
    }

    #[tokio::test]
    async fn no_synthetic_response_and_no_identifier_reuse() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        socket.connect(address).await.unwrap();
        let mut probe = EchoSocket {
            socket,
            target: address,
            kernel_identifier: None,
            ipv4_header: false,
            sent: 0,
            outgoing: Vec::new(),
            incoming: Vec::new(),
        };
        let request = [8, 0, 0, 0, 1, 2, 3, 4, 17];
        // This controlled datagram peer intentionally never responds. Sending
        // a request must not produce an Echo reply by itself.
        assert!(
            timeout(Duration::from_millis(20), probe.echo(&request))
                .await
                .is_err()
        );
        let mut received = [0; 64];
        let (length, _) = target.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[8..length], &request[8..]);
        assert_eq!(internet_checksum::checksum(&received[..length]), [0, 0]);
        probe.sent = u16::MAX as u32;
        assert!(probe.echo(&request).await.is_err());
        assert!(probe.echo(&[3, 0, 0, 0, 0, 0, 0, 0]).await.is_err());
    }
}
