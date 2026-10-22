use proxy_core::datagram::DatagramAddress;
use snafu::{ResultExt, Snafu};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::udp::UdpAssociation;
use super::{
    ForwardContext, Forwarder, ForwarderProvider, ServerConnection, SocksProxySnafu,
    TcpForwardImpl, split_and_wrap,
};

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Error in socks5 first shakehand,detail:{detail}"))]
    FirstRequest { detail: &'static str },
    #[snafu(display("Unsupported operate:{detail}"))]
    NotSupported { detail: &'static str },
    #[snafu(display("Unsupported operate:{detail} with atyp(`{atyp:#x}`)"))]
    NotSupportedHost { atyp: u8, detail: &'static str },
    #[snafu(display("Unsupported operate:{detail} with cmd(`{cmd:#x}`)"))]
    NotSupportedTransport { cmd: u8, detail: &'static str },
    #[snafu(display("Sock5 proxy io error occur: {detail}"))]
    Io {
        detail: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("Invalid proxy header({proxy})"))]
    InvliadProxy { proxy: &'static str },
}

type Result<T, E = SocksError> = std::result::Result<T, E>;

const SOCK5_VER: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const TCP_CONN: u8 = 0x01;
const UDP_ASSOCIATE: u8 = 0x03;
const COMMAND_NOT_SUPPORTED: u8 = 0x07;

pub enum SocksForwarder {
    Tcp(TcpForwardImpl),
    Udp(Box<UdpAssociation>),
    Echo(Box<super::icmp::EchoForwarder>),
}

impl Forwarder for SocksForwarder {
    async fn forward(self) -> super::Result<()> {
        match self {
            Self::Tcp(forwarder) => forwarder.forward().await,
            Self::Udp(forwarder) => (*forwarder).forward().await,
            Self::Echo(forwarder) => (*forwarder).forward().await,
        }
    }
}

enum SocksRequest {
    Connect { host: String, port: u16 },
    UdpAssociate { client_addr: DatagramAddress },
    Echo { host: String, ipv6: bool },
}

pub struct SocksProxierProvider;

impl ForwarderProvider for SocksProxierProvider {
    type Item = SocksForwarder;

    fn try_new(header_context: super::HeaderContext<'_>) -> super::Result<Self>
    where
        Self: std::marker::Sized,
    {
        if header_context.header.len() < 2 {
            FirstRequestSnafu {
                detail: "`VER` and `NMETHODS` not found",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }

        if header_context.header[0] != SOCK5_VER {
            NotSupportedSnafu {
                detail: "not sock5 version in first shakehand",
            }
            .fail()
            .context(SocksProxySnafu)?
        }
        let n = header_context.header[1];
        if header_context.header.len() - 2 < usize::from(n) {
            FirstRequestSnafu {
                detail: "`METHODS` not valid",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }
        if !header_context.header[2..2 + n as usize].contains(&NO_AUTH) {
            NotSupportedSnafu {
                detail: "only SOCKS5 no-authentication is supported for local clients",
            }
            .fail()
            .context(SocksProxySnafu)?;
        }
        Ok(Self)
    }

    async fn try_build_forwarder(
        self,
        mut proxy_context: super::ProxyContext<'_>,
    ) -> super::Result<Self::Item> {
        let request = tokio::time::timeout_at(
            proxy_context.handshake_deadline,
            read_request(&mut proxy_context.stream),
        )
        .await
        .map_err(|_| super::setup_timeout())?
        .context(SocksProxySnafu)?;
        match request {
            SocksRequest::Echo { host, ipv6 } => {
                tracing::info!(
                    host,
                    ipv6,
                    command = "ECHO",
                    "received SOCKS5 proxy request"
                );
                if !proxy_context
                    .stream
                    .peer_addr()
                    .context(IoSnafu {
                        detail: "read Echo client address",
                    })
                    .context(SocksProxySnafu)?
                    .ip()
                    .is_loopback()
                    || proxy_context.upstream_proxy.is_some()
                {
                    response_with_code(&mut proxy_context.stream, COMMAND_NOT_SUPPORTED)
                        .await
                        .context(SocksProxySnafu)?;
                    return NotSupportedTransportSnafu {
                        cmd: tun2proxy::icmp::SOCKS5_ECHO,
                        detail: "ICMP Echo requires the loopback endpoint and a native proxy \
                                 upstream",
                    }
                    .fail()
                    .context(SocksProxySnafu);
                }
                let forwarder =
                    super::icmp::EchoForwarder::connect(proxy_context.stream, &host, ipv6).await?;
                Ok(SocksForwarder::Echo(Box::new(forwarder)))
            }
            SocksRequest::Connect { host, port } => {
                tracing::info!(
                    host,
                    port,
                    command = "CONNECT",
                    "received SOCKS5 proxy request"
                );
                let ServerConnection {
                    stream: server_stream,
                    need_proxy,
                    msg_key,
                } = match proxy_context.connect(host.as_str(), port).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        // General server failure (RFC 1928); never signal a
                        // successful tunnel when opening the upstream failed.
                        let _ = response_with_code(&mut proxy_context.stream, 0x01).await;
                        return Err(error);
                    }
                };
                response(&mut proxy_context.stream)
                    .await
                    .context(SocksProxySnafu)?;

                let (client_reader, client_writer) = split_and_wrap(proxy_context.stream);
                let (server_reader, server_writer) = split_and_wrap(server_stream);
                Ok(SocksForwarder::Tcp(TcpForwardImpl {
                    initial_request: Vec::new(),
                    context: ForwardContext {
                        host,
                        port,
                        need_proxy,
                        msg_key,
                    },
                    client_reader,
                    client_writer,
                    server_reader,
                    server_writer,
                }))
            }
            SocksRequest::UdpAssociate { client_addr } => {
                tracing::info!(
                    ?client_addr,
                    command = "UDP ASSOCIATE",
                    "received SOCKS5 proxy request"
                );
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                let direct = proxy_context.direct_interface.is_some();
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                let direct = false;
                if !proxy_context.enable_udp && !direct {
                    tracing::warn!(
                        transport = "udp",
                        client_address = ?client_addr,
                        reason = "disabled_by_configuration",
                        "SOCKS5 UDP association rejected"
                    );
                    response_with_code(&mut proxy_context.stream, COMMAND_NOT_SUPPORTED)
                        .await
                        .context(SocksProxySnafu)?;
                    return NotSupportedTransportSnafu {
                        cmd: UDP_ASSOCIATE,
                        detail: "SOCKS5 UDP ASSOCIATE is disabled by configuration",
                    }
                    .fail()
                    .context(SocksProxySnafu);
                }
                let (mut association, relay_addr) = UdpAssociation::bind(
                    proxy_context.stream,
                    client_addr,
                    proxy_context.upstream_proxy,
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    proxy_context.direct_interface,
                )
                .await?;
                association.reply_success(relay_addr).await?;
                Ok(SocksForwarder::Udp(Box::new(association)))
            }
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<SocksRequest> {
    stream
        .write_all(&[SOCK5_VER, NO_AUTH])
        .await
        .context(IoSnafu {
            detail: "write SOCKS5 method selection",
        })?;
    let proxy_core::socks5::Request {
        command: cmd,
        address,
    } = proxy_core::socks5::read_request(stream)
        .await
        .context(IoSnafu {
            detail: "read SOCKS5 request",
        })?;
    match cmd {
        TCP_CONN | tun2proxy::icmp::SOCKS5_ECHO => {
            let (host, port) = match address {
                DatagramAddress::Ip(address) => (address.ip().to_string(), address.port()),
                DatagramAddress::Domain(host, port) => (host, port),
            };
            if cmd == TCP_CONN {
                Ok(SocksRequest::Connect { host, port })
            } else if port == 4 || port == 6 {
                Ok(SocksRequest::Echo {
                    host,
                    ipv6: port == 6,
                })
            } else {
                FirstRequestSnafu {
                    detail: "ICMP Echo family must be 4 or 6",
                }
                .fail()
            }
        }
        UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate {
            client_addr: address,
        }),
        _ => NotSupportedTransportSnafu {
            cmd,
            detail: "only TCP CONNECT and UDP ASSOCIATE are supported",
        }
        .fail(),
    }
}

/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// VER socks版本，这里为0x05
/// REP Relay field,内容取值如下 X’00’ succeeded
/// RSV 保留字段
/// ATYPE 地址类型
/// BND.ADDR 服务绑定的地址
/// BND.PORT 服务绑定的端口DST.PORT
async fn response(stream: &mut TcpStream) -> Result<()> {
    response_with_code(stream, 0x00).await
}

/// Send a complete SOCKS5 reply with an unspecified IPv4 bind address.
///
/// Rejected commands still require an RFC 1928 reply so clients can
/// distinguish a configured policy from a network timeout.
async fn response_with_code(stream: &mut TcpStream, reply_code: u8) -> Result<()> {
    proxy_core::socks5::write_reply(stream, reply_code, ([0, 0, 0, 0], 0).into())
        .await
        .context(IoSnafu {
            detail: "send SOCKS5 response",
        })
}

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    #[test]
    fn test_ip_display() {
        let buf: [u8; 16] = [0; 16]; // 假设 buf 包含了长度为 16 的字节数据，表示 IPv6 地址

        // 将 buf 中的字节数据转换为 Ipv6Addr 对象
        let ipv6_addr = Ipv6Addr::from(buf);

        // 将 Ipv6Addr 对象转换为字符串表示
        let ipv6_str = ipv6_addr.to_string();

        println!("IPv6 address: {}", ipv6_str);
    }
}
