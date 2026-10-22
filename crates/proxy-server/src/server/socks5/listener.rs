use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proxy_core::codec::{AsyncReader, AsyncWriter};
use proxy_core::datagram::{
    DatagramAddress, DatagramRelay, MAX_SOCKS5_UDP_DATAGRAM_SIZE, create_direct_datagram_relay,
    parse_socks5_udp_packet, udp_association_idle_timeout,
};
use proxy_core::secure_transport::ProxyStream;
use proxy_core::socks5::{self, Socks5Config, UdpClientEndpoint};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::super::connection::{
    ActiveConnection, TransferStats, proxy_with_metrics_normal, record_connection,
};
use super::super::{ServerContext, ServerError};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Verify a fixed-size MAC instead of comparing password bytes with an
/// early-exit string comparison. The MAC key is local to this generation.
pub(super) struct Authenticator {
    key: hmac::Key,
    expected: hmac::Tag,
}

impl Authenticator {
    pub(super) fn new(config: &Socks5Config) -> io::Result<Self> {
        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| io::Error::other("OS random generator failed"))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &random);
        let mut input = vec![config.username.len() as u8];
        input.extend_from_slice(config.username.as_bytes());
        input.extend_from_slice(config.password.as_bytes());
        let expected = hmac::sign(&key, &input);
        Ok(Self { key, expected })
    }

    async fn authenticate(&self, stream: &mut TcpStream) -> io::Result<()> {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = [0u8; 255];
        let count = usize::from(greeting[1]);
        if greeting[0] != 5 || count == 0 {
            stream.write_all(&[5, 0xff]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication required",
            ));
        }
        stream.read_exact(&mut methods[..count]).await?;
        if !methods[..count].contains(&2) {
            stream.write_all(&[5, 0xff]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 username/password method required",
            ));
        }
        stream.write_all(&[5, 2]).await?;
        let version = stream.read_u8().await?;
        let username_len = usize::from(stream.read_u8().await?);
        if version != 1 || username_len == 0 {
            stream.write_all(&[1, 1]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid SOCKS5 authentication",
            ));
        }
        let mut input = [0u8; 511];
        input[0] = username_len as u8;
        stream.read_exact(&mut input[1..1 + username_len]).await?;
        let password_len = usize::from(stream.read_u8().await?);
        stream
            .read_exact(&mut input[1 + username_len..1 + username_len + password_len])
            .await?;
        let accepted = password_len != 0
            && hmac::verify(
                &self.key,
                &input[..1 + username_len + password_len],
                self.expected.as_ref(),
            )
            .is_ok();
        stream.write_all(&[1, u8::from(!accepted)]).await?;
        if accepted {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ))
        }
    }
}

pub(super) async fn run(
    listener: Arc<TcpListener>,
    auth: Arc<Authenticator>,
    ctx: Arc<ServerContext>,
    cancel: CancellationToken,
) {
    let tasks = TaskTracker::new();
    let sessions = Arc::new(Semaphore::new(1024));
    let pending = Arc::new(Semaphore::new(128));
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            incoming = listener.accept() => match incoming {
                Ok((stream, peer)) => {
                    let (Ok(session), Ok(header)) = (sessions.clone().try_acquire_owned(), pending.clone().try_acquire_owned()) else {
                        tracing::debug!(%peer, "SOCKS5 connection limit reached");
                        continue;
                    };
                    let (ctx, auth, token) = (ctx.clone(), auth.clone(), cancel.clone());
                    tasks.spawn(async move {
                        let _session = session;
                        let _active = ActiveConnection::new(&ctx.metrics);
                        tokio::select! {
                            biased;
                            _ = token.cancelled() => {},
                            result = handle(stream, peer, &auth, ctx.clone(), header) => {
                                if let Err(error) = result {
                                    tracing::debug!(%peer, %error, "SOCKS5 connection closed");
                                }
                            }
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "SOCKS5 accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    cancel.cancel();
    tasks.close();
    tasks.wait().await;
}

enum Forward {
    Tcp(TcpStream),
    Udp {
        socket: UdpSocket,
        endpoint: UdpClientEndpoint,
        relay: Box<DatagramRelay>,
    },
}

async fn prepare(
    stream: &mut TcpStream,
    peer: SocketAddr,
    auth: &Authenticator,
    ctx: &ServerContext,
) -> io::Result<(socks5::Request, Forward)> {
    stream.set_nodelay(true)?;
    auth.authenticate(stream).await?;
    let request = match socks5::read_request(stream).await {
        Ok(request) => request,
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::Unsupported {
                8
            } else {
                1
            };
            let _ = socks5::write_reply(stream, code, ([0, 0, 0, 0], 0).into()).await;
            return Err(error);
        }
    };
    let forward = match request.command {
        socks5::CONNECT => {
            let (host, port) = destination(&request.address);
            let upstream = match proxy_core::transport::connect_tcp_host(&host, port).await {
                Ok(upstream) => upstream,
                Err(error) => {
                    let code = match error.kind() {
                        io::ErrorKind::PermissionDenied => 2,
                        io::ErrorKind::NetworkUnreachable => 3,
                        io::ErrorKind::HostUnreachable => 4,
                        io::ErrorKind::ConnectionRefused => 5,
                        io::ErrorKind::TimedOut => 6,
                        _ => 1,
                    };
                    let _ = socks5::write_reply(stream, code, ([0, 0, 0, 0], 0).into()).await;
                    return Err(error);
                }
            };
            upstream.set_nodelay(true)?;
            socks5::write_reply(stream, 0, upstream.local_addr()?).await?;
            Forward::Tcp(upstream)
        }
        socks5::UDP_ASSOCIATE => {
            let endpoint = match UdpClientEndpoint::new(&request.address, peer.ip()) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = socks5::write_reply(stream, 2, ([0, 0, 0, 0], 0).into()).await;
                    return Err(error);
                }
            };
            let socket = UdpSocket::bind(SocketAddr::new(stream.local_addr()?.ip(), 0)).await?;
            let relay = create_direct_datagram_relay()
                .await
                .map_err(io::Error::other)?;
            let mut bound = socket.local_addr()?;
            // NODE_ADVERTISE_ADDR/public-IP discovery also describes the UDP
            // endpoint behind a 1:1 NAT. Loopback clients retain loopback routing.
            if !peer.ip().is_loopback()
                && let Some(node) = ctx.nodes.get_self()
                && let Ok(advertised) = node.addr.parse::<SocketAddr>()
                && advertised.is_ipv4() == bound.is_ipv4()
            {
                bound.set_ip(advertised.ip());
            }
            socks5::write_reply(stream, 0, bound).await?;
            Forward::Udp {
                socket,
                endpoint,
                relay: Box::new(relay),
            }
        }
        _ => {
            socks5::write_reply(stream, 7, ([0, 0, 0, 0], 0).into()).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 command not supported",
            ));
        }
    };
    Ok((request, forward))
}

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    auth: &Authenticator,
    ctx: Arc<ServerContext>,
    header: tokio::sync::OwnedSemaphorePermit,
) -> io::Result<()> {
    let (request, forward) =
        tokio::time::timeout(SETUP_TIMEOUT, prepare(&mut stream, peer, auth, &ctx))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 setup deadline exceeded")
            })??;
    drop(header);
    let (host, port) = destination(&request.address);
    let started = proxy_core::metrics::current_time_ms();
    let trace_id = ctx.allocate_trace_id();
    tracing::info!(trace_id, %peer, host, port, command = request.command, "authenticated SOCKS5 connection ready");
    let result = match forward {
        Forward::Tcp(upstream) => {
            let (cr, cw) = ProxyStream::from(stream).into_split();
            let (sr, sw) = ProxyStream::from(upstream).into_split();
            proxy_with_metrics_normal(
                AsyncReader::new(cr),
                AsyncReader::new(sr),
                AsyncWriter::new(cw),
                AsyncWriter::new(sw),
            )
            .await
        }
        Forward::Udp {
            socket,
            endpoint,
            relay,
        } => udp(stream, socket, endpoint, *relay)
            .await
            .map_err(|source| ServerError::Io {
                detail: "SOCKS5 UDP relay".into(),
                source,
            }),
    };
    record_connection(
        &ctx,
        &peer.ip().to_string(),
        &host,
        port,
        started,
        trace_id,
        &result,
    );
    result.map(|_| ()).map_err(io::Error::other)
}

fn destination(address: &DatagramAddress) -> (String, u16) {
    match address {
        DatagramAddress::Ip(addr) => (addr.ip().to_string(), addr.port()),
        DatagramAddress::Domain(host, port) => (host.clone(), *port),
    }
}

async fn udp(
    mut control: TcpStream,
    socket: UdpSocket,
    mut endpoint: UdpClientEndpoint,
    relay: DatagramRelay,
) -> io::Result<TransferStats> {
    let (mut reader, writer, _guard) = relay.into_parts();
    let mut buffer = vec![0u8; MAX_SOCKS5_UDP_DATAGRAM_SIZE];
    let mut stats = TransferStats::default();
    let started = tokio::time::Instant::now();
    let timeout = udp_association_idle_timeout();
    let idle = tokio::time::sleep(timeout);
    tokio::pin!(idle);
    let mut closed = [0u8; 1];
    // Observe TCP closure even while resolving/sending an individual datagram.
    tokio::select! {
        result = control.read(&mut closed) => { result?; },
        result = async {
            loop {
                tokio::select! {
                    _ = &mut idle => break,
                    incoming = socket.recv_from(&mut buffer) => {
                        let (size, source) = incoming?;
                        let packet = &buffer[..size];
                        let Ok(parsed) = parse_socks5_udp_packet(packet) else { continue; };
                        if !endpoint.accept(source) { continue; }
                        if let Err(error) = writer.send(packet).await {
                            tracing::debug!(%error, "discarding failed SOCKS5 UDP send");
                            continue;
                        }
                        stats.bytes_up += parsed.payload.len() as u64;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                    }
                    response = reader.recv() => {
                        let response = response.map_err(io::Error::other)?;
                        if let Some(destination) = endpoint.get() {
                            socket.send_to(&response, destination).await?;
                            if let Ok(packet) = parse_socks5_udp_packet(&response) { stats.bytes_down += packet.payload.len() as u64; }
                            stats.latency_ms.get_or_insert(started.elapsed().as_millis() as u64);
                            idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                        }
                    }
                }
            }
            Ok::<_, io::Error>(())
        } => result?,
    }
    Ok(stats)
}
