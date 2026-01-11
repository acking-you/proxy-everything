#[cfg(feature = "vpn")]
use anyhow::{Context, Result};
#[cfg(feature = "vpn")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "vpn")]
use std::os::unix::io::RawFd;
#[cfg(feature = "vpn")]
use std::sync::Arc;
#[cfg(feature = "vpn")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "vpn")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "vpn")]
use tokio::sync::RwLock;
#[cfg(feature = "vpn")]
use tokio::sync::mpsc;
#[cfg(feature = "vpn")]
use tokio_util::sync::CancellationToken;

#[cfg(feature = "vpn")]
pub struct TunDevice {
    fd: RawFd,
}

#[cfg(feature = "vpn")]
impl TunDevice {
    pub fn from_fd(fd: RawFd) -> Result<Self> {
        if fd < 0 {
            anyhow::bail!("Invalid file descriptor: {}", fd);
        }

        Ok(Self { fd })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(feature = "vpn")]
pub struct TunHandler {
    device: Arc<TunDevice>,
    protect_callback: Option<extern "C" fn(i32) -> bool>,
    cancel_token: CancellationToken,
    connections: Arc<RwLock<HashMap<FlowKey, mpsc::UnboundedSender<Vec<u8>>>>>,
}

#[cfg(feature = "vpn")]
impl TunHandler {
    pub fn new(
        fd: RawFd,
        protect_callback: Option<extern "C" fn(i32) -> bool>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let device = TunDevice::from_fd(fd).context("Failed to create TUN device")?;

        Ok(Self {
            device: Arc::new(device),
            protect_callback,
            cancel_token,
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn protect_socket(&self, fd: i32) -> bool {
        if let Some(callback) = self.protect_callback {
            callback(fd)
        } else {
            false
        }
    }

    pub async fn start(&self) -> Result<()> {
        use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};

        tracing::info!("TUN handler started with FD: {}", self.device.fd());

        let mut tun_file = unsafe {
            use std::os::unix::io::FromRawFd;
            tokio::fs::File::from_raw_fd(self.device.fd())
        };

        let (tun_write_tx, mut tun_write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut packet_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    tracing::info!("TUN handler cancelled");
                    break;
                }
                n = tun_file.read(&mut packet_buf) => {
                    let n = n.context("Failed to read from TUN device")?;
                    if n == 0 {
                        continue;
                    }

                    let packet = &packet_buf[..n];

                    // Parse IP packet
                    let ip_packet = match Ipv4Packet::new_checked(packet) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::debug!("Invalid IPv4 packet: {}", e);
                            continue;
                        }
                    };

                    let src_addr = ip_packet.src_addr();
                    let dst_addr = ip_packet.dst_addr();
                    let next_header = ip_packet.next_header();

                    match next_header {
                        IpProtocol::Tcp => {
                            let tcp_packet = match TcpPacket::new_checked(ip_packet.payload()) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::debug!("Invalid TCP packet: {}", e);
                                    continue;
                                }
                            };

                            let src_port = tcp_packet.src_port();
                            let dst_port = tcp_packet.dst_port();
                            let src_ip = std::net::Ipv4Addr::from(src_addr);
                            let dst_ip = std::net::Ipv4Addr::from(dst_addr);
                            let key: FlowKey = (src_ip, src_port, dst_ip, dst_port);

                            let existing_tx = {
                                let conns = self.connections.read().await;
                                conns.get(&key).cloned()
                            };

                            if let Some(packet_tx) = existing_tx {
                                let _ = packet_tx.send(packet.to_vec());
                                continue;
                            }

                            let (packet_tx, packet_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                            let _ = packet_tx.send(packet.to_vec());

                            // Spawn new connection handler
                            let protect_cb = self.protect_callback;
                            let conns_ref = self.connections.clone();
                            let tun_write_tx = tun_write_tx.clone();
                            let cancel_token = self.cancel_token.clone();
                            let dst_ipaddr = std::net::IpAddr::V4(dst_ip);

                            {
                                let mut conns = self.connections.write().await;
                                conns.insert(key, packet_tx);
                            }

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_tcp_connection(
                                    dst_ipaddr,
                                    dst_port,
                                    packet_rx,
                                    tun_write_tx,
                                    protect_cb,
                                    cancel_token,
                                )
                                .await
                                {
                                    tracing::error!("TCP connection error: {}", e);
                                }

                                // Remove from connections map
                                conns_ref.write().await.remove(&key);
                            });
                        }
                        IpProtocol::Udp => {
                            let udp_packet = match UdpPacket::new_checked(ip_packet.payload()) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::debug!("Invalid UDP packet: {}", e);
                                    continue;
                                }
                            };

                            let src_port = udp_packet.src_port();
                            let dst_port = udp_packet.dst_port();
                            let src_ip = std::net::Ipv4Addr::from(src_addr);
                            let dst_ip = std::net::Ipv4Addr::from(dst_addr);
                            let payload = udp_packet.payload().to_vec();

                            let protect_cb = self.protect_callback;
                            let tun_write_tx = tun_write_tx.clone();
                            let cancel_token = self.cancel_token.clone();
                            tokio::spawn(async move {
                                if let Err(err) = Self::handle_udp_datagram(
                                    src_ip,
                                    src_port,
                                    dst_ip,
                                    dst_port,
                                    payload,
                                    tun_write_tx,
                                    protect_cb,
                                    cancel_token,
                                )
                                .await
                                {
                                    tracing::debug!("UDP forward error: {}", err);
                                }
                            });
                        }
                        _ => {
                            tracing::debug!("Unsupported protocol: {:?}", next_header);
                        }
                    }
                }
                Some(out_packet) = tun_write_rx.recv() => {
                    tun_file
                        .write_all(&out_packet)
                        .await
                        .context("Failed to write to TUN device")?;
                }
            }
        }

        Ok(())
    }

    async fn handle_tcp_connection(
        host: std::net::IpAddr,
        port: u16,
        mut packet_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        tun_write_tx: mpsc::UnboundedSender<Vec<u8>>,
        protect_callback: Option<extern "C" fn(i32) -> bool>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        use crate::codec::{AsyncReader, AsyncWriter};
        use crate::config::runtime;
        use crate::{Aes256GcmCryption, MyAsyncWriteExt, ProxyHeader, set_data_size};

        tracing::info!("Handling TCP connection to {}:{}", host, port);

        // Get session key from runtime config
        let msg_key =
            runtime::with_secret_key(|key, _hash| String::from_utf8_lossy(key).to_string());

        // Connect to proxy server
        let server_host = runtime::server_host();
        let server_port = runtime::server_port();

        // Create in-memory stream between TUN-side TCP stack and proxy forwarding pipeline.
        let (proxy_end, tun_end) = tokio::io::duplex(64 * 1024);

        // Connect to proxy server with socket protection (must happen before connect).
        let mut proxy_stream = {
            use std::net::{IpAddr, SocketAddr};
            use tokio::net::TcpSocket;

            let ipaddr = match server_host.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => uni_stream::addr::get_ip_addrs(&server_host)
                    .await
                    .context("DNS resolve proxy server")?
                    .into_iter()
                    .next()
                    .context("Empty DNS records for proxy server")?,
            };

            let socket = match ipaddr {
                IpAddr::V4(_) => TcpSocket::new_v4().context("Create IPv4 socket")?,
                IpAddr::V6(_) => TcpSocket::new_v6().context("Create IPv6 socket")?,
            };

            #[cfg(unix)]
            if let Some(callback) = protect_callback {
                use std::os::unix::io::AsRawFd;
                let fd = socket.as_raw_fd();
                if !callback(fd) {
                    tracing::warn!("Failed to protect proxy socket {}", fd);
                }
            }

            let addr = SocketAddr::new(ipaddr, server_port);
            socket.connect(addr).await.context("Connect proxy server")?
        };

        // Send proxy header to proxy server.
        {
            use crate::codec::AsyncReaderWriterRef;
            use std::borrow::Cow;

            let proxy_header = ProxyHeader {
                host: host.to_string(),
                port,
                key: Some(Cow::Owned(msg_key.clone())),
            };

            let mut header_json =
                serde_json::to_string(&proxy_header).context("Serialize proxy header")?;
            let mut cryption = Aes256GcmCryption::try_new_with_default_key()
                .map_err(|e| anyhow::anyhow!("Create header cryption failed: {e:?}"))?;

            // SAFETY: encrypt header JSON in-place; bytes are used only for transmission.
            let (addr, tag, len) = unsafe {
                let addr = header_json.as_bytes_mut();
                let tag = cryption
                    .encrypt(addr)
                    .map_err(|e| anyhow::anyhow!("Encrypt proxy header failed: {e:?}"))?;
                let len = addr.len() + tag.as_ref().len();
                (addr, tag, len as u32)
            };

            let mut stream_ref = AsyncReaderWriterRef::new(&mut proxy_stream);
            set_data_size(&mut stream_ref, len)
                .await
                .context("Send header length")?;
            stream_ref
                .write_all(addr)
                .await
                .context("Send header payload")?;
            stream_ref
                .write_all(tag.as_ref())
                .await
                .context("Send header tag")?;
        }

        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
        use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
        use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
        use smoltcp::time::Instant as SmolInstant;
        use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

        let host_v4 = match host {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => anyhow::bail!("IPv6 TUN packets are not supported"),
        };

        struct ChannelDevice {
            rx_queue: VecDeque<Vec<u8>>,
            tx: mpsc::UnboundedSender<Vec<u8>>,
        }

        impl ChannelDevice {
            fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
                Self {
                    rx_queue: VecDeque::new(),
                    tx,
                }
            }

            fn push_rx(&mut self, pkt: Vec<u8>) {
                self.rx_queue.push_back(pkt);
            }
        }

        struct ChanRxToken {
            pkt: Vec<u8>,
        }

        impl RxToken for ChanRxToken {
            fn consume<R, F>(mut self, f: F) -> R
            where
                F: FnOnce(&mut [u8]) -> R,
            {
                f(&mut self.pkt)
            }
        }

        struct ChanTxToken {
            tx: mpsc::UnboundedSender<Vec<u8>>,
        }

        impl TxToken for ChanTxToken {
            fn consume<R, F>(self, len: usize, f: F) -> R
            where
                F: FnOnce(&mut [u8]) -> R,
            {
                let mut buf = vec![0u8; len];
                let result = f(&mut buf);
                let _ = self.tx.send(buf);
                result
            }
        }

        impl Device for ChannelDevice {
            type RxToken<'a>
                = ChanRxToken
            where
                Self: 'a;
            type TxToken<'a>
                = ChanTxToken
            where
                Self: 'a;

            fn receive(
                &mut self,
                _timestamp: SmolInstant,
            ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
                let pkt = self.rx_queue.pop_front()?;
                Some((
                    ChanRxToken { pkt },
                    ChanTxToken {
                        tx: self.tx.clone(),
                    },
                ))
            }

            fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
                Some(ChanTxToken {
                    tx: self.tx.clone(),
                })
            }

            fn capabilities(&self) -> DeviceCapabilities {
                let mut caps = DeviceCapabilities::default();
                caps.max_transmission_unit = 1500;
                caps.medium = Medium::Ip;
                caps
            }
        }

        let start_time = std::time::Instant::now();
        let mut device = ChannelDevice::new(tun_write_tx);

        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random::<u64>();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs.clear();
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(host_v4.into()), 32))
                .unwrap();
        });

        let tcp_rx_buf = SocketBuffer::new(vec![0u8; 64 * 1024]);
        let tcp_tx_buf = SocketBuffer::new(vec![0u8; 64 * 1024]);
        let mut tcp_socket = TcpSocket::new(tcp_rx_buf, tcp_tx_buf);
        tcp_socket.listen(port).context("Failed to listen")?;

        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(tcp_socket);

        tracing::info!("TCP connection established to {}:{}", host, port);

        // Start the encrypted proxy pipeline:
        // TUN (plaintext) <-> [start_proxy + encrypt/decrypt] <-> proxy server
        let proxy_task = {
            let (client_r, client_w) = tokio::io::split(proxy_end);
            let (server_r, server_w) = proxy_stream.into_split();

            let client_reader = AsyncReader::new(client_r);
            let client_writer = AsyncWriter::new(client_w);
            let server_reader = AsyncReader::new(server_r);
            let server_writer = AsyncWriter::new(server_w);

            let host = host.to_string();
            let msg_key = msg_key.clone();

            tokio::spawn(async move {
                crate::client_proxy_with_cryptor_codec(
                    &host,
                    &msg_key,
                    client_reader,
                    server_reader,
                    client_writer,
                    server_writer,
                )
                .await
            })
        };

        let (mut tun_read, mut tun_write) = tokio::io::split(tun_end);
        let mut tun_read_buf = vec![0u8; 16 * 1024];
        let mut pending_to_tun: Vec<u8> = Vec::new();
        let mut pending_to_tun_off: usize = 0;
        let mut pending_to_proxy: Vec<u8> = Vec::new();
        let mut pending_to_proxy_off: usize = 0;
        let mut tun_eof = false;

        loop {
            let now = SmolInstant::from_millis(start_time.elapsed().as_millis() as i64);

            while let Ok(pkt) = packet_rx.try_recv() {
                device.push_rx(pkt);
            }

            iface.poll(now, &mut device, &mut sockets);

            // Fast-path: push any pending proxy->app bytes into the TCP socket.
            if pending_to_tun_off < pending_to_tun.len() {
                let socket = sockets.get_mut::<TcpSocket>(tcp_handle);
                if socket.can_send() {
                    let sent = socket
                        .send_slice(&pending_to_tun[pending_to_tun_off..])
                        .unwrap_or(0);
                    if sent > 0 {
                        pending_to_tun_off += sent;
                        if pending_to_tun_off == pending_to_tun.len() {
                            pending_to_tun.clear();
                            pending_to_tun_off = 0;
                        } else if pending_to_tun_off >= 64 * 1024 {
                            pending_to_tun.drain(..pending_to_tun_off);
                            pending_to_tun_off = 0;
                        }
                    }
                }
            }

            // Drain app->proxy bytes from the TCP socket into pending buffer.
            {
                let mut app_buf = [0u8; 16 * 1024];
                loop {
                    let n = {
                        let socket = sockets.get_mut::<TcpSocket>(tcp_handle);
                        if !socket.can_recv() {
                            0
                        } else {
                            socket.recv_slice(&mut app_buf).unwrap_or(0)
                        }
                    };

                    if n == 0 {
                        break;
                    }

                    pending_to_proxy.extend_from_slice(&app_buf[..n]);
                }
            }

            iface.poll(now, &mut device, &mut sockets);

            // Exit once the TCP socket is fully closed.
            if !sockets.get::<TcpSocket>(tcp_handle).is_open() {
                break;
            }

            let poll_at = iface.poll_at(now, &sockets);
            let sleep = match poll_at {
                Some(deadline) if deadline > now => {
                    let delta_ms = (deadline - now).total_millis();
                    Some(tokio::time::sleep(std::time::Duration::from_millis(
                        delta_ms as u64,
                    )))
                }
                _ => None,
            };

            tokio::select! {
                _ = cancel_token.cancelled() => {
                    sockets.get_mut::<TcpSocket>(tcp_handle).close();
                    break;
                }
                Some(pkt) = packet_rx.recv() => {
                    device.push_rx(pkt);
                }
                read_res = tun_read.read(&mut tun_read_buf), if !tun_eof => {
                    let n = read_res.context("Failed to read from proxy pipeline")?;
                    if n == 0 {
                        tun_eof = true;
                        sockets.get_mut::<TcpSocket>(tcp_handle).close();
                    } else {
                        pending_to_tun.extend_from_slice(&tun_read_buf[..n]);
                    }
                }
                write_res = tun_write.write(&pending_to_proxy[pending_to_proxy_off..]), if pending_to_proxy_off < pending_to_proxy.len() => {
                    let n = write_res.context("Failed to write to proxy pipeline")?;
                    if n == 0 {
                        // EOF on the duplex stream write side.
                        tun_eof = true;
                        sockets.get_mut::<TcpSocket>(tcp_handle).close();
                    } else {
                        pending_to_proxy_off += n;
                        if pending_to_proxy_off == pending_to_proxy.len() {
                            pending_to_proxy.clear();
                            pending_to_proxy_off = 0;
                        } else if pending_to_proxy_off >= 64 * 1024 {
                            pending_to_proxy.drain(..pending_to_proxy_off);
                            pending_to_proxy_off = 0;
                        }
                    }
                }
                _ = async {
                    if let Some(s) = sleep {
                        s.await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {}
            }
        }

        // Ensure the proxy task finishes (dropping `tun_end` will cause EOF).
        drop(tun_write);
        drop(tun_read);
        let _ = proxy_task.await;

        Ok(())
    }

    async fn handle_udp_datagram(
        src_ip: std::net::Ipv4Addr,
        src_port: u16,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        payload: Vec<u8>,
        tun_write_tx: mpsc::UnboundedSender<Vec<u8>>,
        protect_callback: Option<extern "C" fn(i32) -> bool>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};
        use tokio::net::UdpSocket;

        if payload.is_empty() {
            return Ok(());
        }

        let socket = UdpSocket::bind(("0.0.0.0", 0))
            .await
            .context("Failed to bind UDP socket")?;

        // Protect the socket from VPN routing (must happen before connect).
        #[cfg(unix)]
        if let Some(callback) = protect_callback {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            if !callback(fd) {
                tracing::warn!("Failed to protect UDP socket {}", fd);
            }
        }

        socket
            .connect((dst_ip, dst_port))
            .await
            .context("Failed to connect UDP socket")?;

        tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            send_res = socket.send(&payload) => {
                send_res.context("Failed to send UDP payload")?;
            }
        }

        // Best-effort: wait briefly for a single response datagram (DNS, etc.).
        let mut recv_buf = vec![0u8; 8192];
        let recv_len = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            recv_res = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut recv_buf)) => {
                match recv_res {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e).context("UDP recv failed"),
                    Err(_) => return Ok(()), // timeout
                }
            }
        };

        if recv_len == 0 {
            return Ok(());
        }

        const IPV4_HEADER_LEN: usize = 20;
        const UDP_HEADER_LEN: usize = 8;

        let udp_len = (UDP_HEADER_LEN + recv_len) as u16;
        let ip_total_len = (IPV4_HEADER_LEN + udp_len as usize) as u16;

        let mut out_packet = vec![0u8; ip_total_len as usize];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut out_packet);
        ip_packet.set_version(4);
        ip_packet.set_header_len(IPV4_HEADER_LEN as u8);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_len(ip_total_len);
        ip_packet.set_ident(0);
        ip_packet.clear_flags();
        ip_packet.set_more_frags(false);
        ip_packet.set_dont_frag(true);
        ip_packet.set_frag_offset(0);
        ip_packet.set_hop_limit(64);
        ip_packet.set_next_header(IpProtocol::Udp);
        ip_packet.set_src_addr(dst_ip.into());
        ip_packet.set_dst_addr(src_ip.into());

        {
            let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
            udp_packet.set_src_port(dst_port);
            udp_packet.set_dst_port(src_port);
            udp_packet.set_len(udp_len);
            udp_packet.payload_mut()[..recv_len].copy_from_slice(&recv_buf[..recv_len]);
            udp_packet.fill_checksum(
                &IpAddress::Ipv4(dst_ip.into()),
                &IpAddress::Ipv4(src_ip.into()),
            );
        }

        ip_packet.fill_checksum();

        let _ = tun_write_tx.send(out_packet);
        Ok(())
    }
}

#[cfg(feature = "vpn")]
type FlowKey = (std::net::Ipv4Addr, u16, std::net::Ipv4Addr, u16);

#[cfg(not(feature = "vpn"))]
pub struct TunHandler;

#[cfg(not(feature = "vpn"))]
impl TunHandler {
    pub fn new(
        _fd: i32,
        _protect_callback: Option<extern "C" fn(i32) -> bool>,
        _cancel_token: CancellationToken,
    ) -> anyhow::Result<Self> {
        anyhow::bail!("VPN feature not enabled")
    }

    pub fn protect_socket(&self, _fd: i32) -> bool {
        false
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        anyhow::bail!("VPN feature not enabled")
    }
}
