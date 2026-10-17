use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::{io, ptr};

use tokio::net::TcpStream;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetBestRoute2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::*;

fn sockaddr(address: SocketAddr) -> SOCKADDR_INET {
    match address {
        SocketAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: address.port().to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                },
                ..Default::default()
            },
        },
        SocketAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.ip().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: address.scope_id(),
                },
            },
        },
    }
}

fn ip(address: SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: Windows sets the union discriminant; only the matching member is read.
    unsafe {
        match address.si_family {
            AF_INET => Some(Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()),
            AF_INET6 => Some(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte).into()),
            _ => None,
        }
    }
}

fn tcp_info(stream: &TcpStream) -> io::Result<TCP_INFO_v0> {
    let version: u32 = 0;
    let mut info = TCP_INFO_v0::default();
    let mut returned = 0;
    // SAFETY: the borrowed socket and typed, correctly sized buffers remain alive
    // for this synchronous, read-only query. No pending overlapped I/O is used.
    let status = unsafe {
        WSAIoctl(
            stream.as_raw_socket() as SOCKET,
            SIO_TCP_INFO,
            (&version as *const u32).cast(),
            size_of::<u32>() as u32,
            (&mut info as *mut TCP_INFO_v0).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: read this thread's error immediately after the failed call.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if returned < size_of::<TCP_INFO_v0>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short TCP_INFO_v0 result",
        ));
    }
    Ok(info)
}

fn bound_interface(stream: &TcpStream, ipv4: bool) -> io::Result<u32> {
    let mut index: u32 = 0;
    let mut len = size_of::<u32>() as i32;
    let (level, option) = if ipv4 {
        (IPPROTO_IP, IP_UNICAST_IF)
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF)
    };
    // SAFETY: getsockopt writes at most len bytes to the borrowed u32 buffer.
    let status = unsafe {
        getsockopt(
            stream.as_raw_socket() as SOCKET,
            level,
            option,
            (&mut index as *mut u32).cast(),
            &mut len,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: no intervening Winsock call has overwritten the thread error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    // getsockopt returns both interface indices in host byte order. The IPv4
    // setsockopt input uses network order, but its getter deliberately does not.
    Ok(index)
}

pub(super) fn record(connection_id: u64, observation: &'static str, stream: &TcpStream) {
    match tcp_info(stream) {
        Ok(info) => tracing::info!(
            connection_id,
            observation,
            tcp_state = info.State,
            tcp_connection_ms = info.ConnectionTimeMs,
            rtt_estimate_us = info.RttUs,
            min_sampled_rtt_us = info.MinRttUs,
            syn_retransmissions = info.SynRetrans,
            retransmitted_bytes = info.BytesRetrans,
            bytes_out = info.BytesOut,
            bytes_in = info.BytesIn,
            "connection diagnostic Windows TCP statistics"
        ),
        Err(error) => {
            tracing::info!(connection_id, observation, os_error = error.raw_os_error(), %error,
            "connection diagnostic TCP statistics unavailable")
        }
    }
    let (local, peer) = (stream.local_addr(), stream.peer_addr());
    let (Ok(local), Ok(peer)) = (local.as_ref(), peer.as_ref()) else {
        tracing::info!(connection_id, observation,
            local_addr_error = ?local.err(), peer_addr_error = ?peer.err(),
            "connection diagnostic route snapshot skipped; socket endpoint unavailable");
        return;
    };
    let bound = bound_interface(stream, peer.is_ipv4());
    let (source, destination) = (sockaddr(*local), sockaddr(*peer));
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut selected_source = SOCKADDR_INET::default();
    // SAFETY: all inputs are initialized SOCKADDR_INET values; both output
    // buffers match the Win32 ABI and remain valid for the synchronous call.
    let status = unsafe {
        GetBestRoute2(
            ptr::null(),
            bound.as_ref().copied().unwrap_or(0),
            &source,
            &destination,
            0,
            &mut row,
            &mut selected_source,
        )
    };
    if status != 0 {
        tracing::info!(connection_id, observation, win32_error = status,
            bound_interface = ?bound.as_ref().ok(),
            "connection diagnostic route snapshot unavailable");
        return;
    }
    let mut interface = MIB_IF_ROW2 {
        InterfaceIndex: row.InterfaceIndex,
        ..Default::default()
    };
    // SAFETY: InterfaceIndex identifies the queried row; GetIfEntry2 fills the
    // remaining fields in a properly sized buffer without changing the adapter.
    let interface_status = unsafe { GetIfEntry2(&mut interface) };
    let alias = (interface_status == 0).then(|| {
        let len = interface
            .Alias
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(interface.Alias.len());
        String::from_utf16_lossy(&interface.Alias[..len])
    });
    tracing::info!(
        connection_id, observation, bound_interface = ?bound.as_ref().ok(),
        bound_interface_query_error = ?bound.as_ref().err().and_then(io::Error::raw_os_error),
        route_interface_index = row.InterfaceIndex, route_interface_alias = ?alias,
        route_interface_query_error = interface_status,
        route_source = ?ip(selected_source), route_gateway = ?ip(row.NextHop),
        route_prefix = ?ip(row.DestinationPrefix.Prefix), route_prefix_len = row.DestinationPrefix.PrefixLength,
        route_loopback = row.Loopback, socket_peer_loopback = peer.ip().is_loopback(),
        "connection diagnostic route snapshot; actual packet interface requires capture"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bound_interface_is_reported_in_host_byte_order() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpSocket;

        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = tokio::net::TcpListener::bind(address).await.unwrap();
            let peer = listener.local_addr().unwrap();
            let destination = sockaddr(peer);
            let mut route = MIB_IPFORWARD_ROW2::default();
            let mut source = SOCKADDR_INET::default();
            // SAFETY: all buffers match the synchronous, read-only Win32 API.
            let status = unsafe {
                GetBestRoute2(
                    ptr::null(),
                    0,
                    ptr::null(),
                    &destination,
                    0,
                    &mut route,
                    &mut source,
                )
            };
            assert_eq!(status, 0);
            assert_ne!(route.InterfaceIndex, 0);

            let (socket, level, option, value) = if peer.is_ipv4() {
                (
                    TcpSocket::new_v4().unwrap(),
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    route.InterfaceIndex.to_be(),
                )
            } else {
                (
                    TcpSocket::new_v6().unwrap(),
                    IPPROTO_IPV6,
                    IPV6_UNICAST_IF,
                    route.InterfaceIndex,
                )
            };
            // SAFETY: this changes only the test's socket, binding it to the
            // loopback interface already selected for its loopback peer.
            let status = unsafe {
                setsockopt(
                    socket.as_raw_socket() as SOCKET,
                    level,
                    option,
                    (&value as *const u32).cast(),
                    size_of::<u32>() as i32,
                )
            };
            assert_eq!(status, 0);
            let mut client = socket.connect(peer).await.unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            assert_eq!(
                bound_interface(&client, peer.is_ipv4()).unwrap(),
                route.InterfaceIndex
            );
            client.write_all(b"bound loopback").await.unwrap();
            let mut received = [0; 14];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"bound loopback");
        }
    }

    #[tokio::test]
    async fn readonly_queries_preserve_loopback_socket_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = tokio::net::TcpListener::bind(address).await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut server, _) = listener.accept().await.unwrap();
            let before = (client.local_addr().unwrap(), client.peer_addr().unwrap());
            assert_eq!(ip(sockaddr(before.0)), Some(before.0.ip()));
            assert_eq!(bound_interface(&client, before.0.is_ipv4()).unwrap(), 0);
            assert!(tcp_info(&client).unwrap().Mss > 0);
            record(1, "test", &client);
            client.write_all(b"unchanged").await.unwrap();
            let mut data = [0; 9];
            server.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"unchanged");
            assert_eq!(
                (client.local_addr().unwrap(), client.peer_addr().unwrap()),
                before
            );
        }
    }
}
