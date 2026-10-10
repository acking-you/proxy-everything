//! Exercise DNS upgrades through packet capture and SOCKS on loopback only.
//! No real adapter, routing table, system DNS or user cache is accessed.
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgDns, ArgProxy, ArgUdpStrategy, Args, VirtualDnsState};

const CLIENT: [u8; 4] = [10, 77, 0, 2];
const PORTAL: [u8; 4] = [10, 77, 0, 1];
const QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_listener_forces_dns_through_remote_without_forcing_other_traffic() {
    use proxy_client::client::auto_proxy::PROXY_CACHE;
    use proxy_client::client::{ClientConfig, run_client_with_listener};
    use proxy_core::crypto::Aes256GcmCryption;
    use proxy_core::protocol::ProxyHeader;
    use tokio_util::task::TaskTracker;

    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "proxy-dns-routing-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir_all(&dir.0).unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        proxy_core::config::runtime::init_config(
            "127.0.0.1".into(),
            remote.local_addr().unwrap().port(),
            true,
            vec![],
            None,
        );
        let cancel = CancellationToken::new();
        let _guard = cancel.clone().drop_guard();
        let tracker = TaskTracker::new();
        tracker.spawn(run_client_with_listener::<false>(
            local,
            cancel.clone(),
            Some(tracker.clone()),
            Some(ClientConfig {
                enable_auto_proxy: true,
                enable_udp: false,
                cache_dir: Some(dir.0.clone()),
            }),
        ));

        for resolver in ["127.0.0.2", "::1"] {
            // Model an auto-proxy direct decision. Every real socket remains
            // loopback; the remote endpoint only decodes and answers the query.
            PROXY_CACHE.insert(resolver.to_owned(), false);
            let peer = async {
                for _ in 0..2 {
                    let (mut stream, _) = remote.accept().await.unwrap();
                    let mut prefix = [0; 8];
                    stream.read_exact(&mut prefix).await.unwrap();
                    let length = u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
                    assert!(length < 4096);
                    let mut header = vec![0; length];
                    stream.read_exact(&mut header).await.unwrap();
                    let mut cipher = Aes256GcmCryption::try_new_with_default_key().unwrap();
                    let header: ProxyHeader =
                        serde_json::from_slice(cipher.decrypt_with_tag(&mut header).unwrap())
                            .unwrap();
                    assert_eq!(header.host, resolver);
                    assert_eq!(header.port, 53);
                    assert!(header.key.is_none());
                    let length = stream.read_u16().await.unwrap() as usize;
                    let mut answer = vec![0; length];
                    stream.read_exact(&mut answer).await.unwrap();
                    assert_eq!(answer, QUERY);
                    answer[2..4].copy_from_slice(&[0x81, 0x80]);
                    stream.write_u16(length as u16).await.unwrap();
                    stream.write_all(&answer).await.unwrap();
                }
            };
            let args = Args {
                setup: false,
                proxy: ArgProxy::try_from(format!("socks5://{local_addr}").as_str()).unwrap(),
                dns: ArgDns::OverTcp,
                dns_addr: resolver.parse().unwrap(),
                udp_strategy: ArgUdpStrategy::Block,
                ..Args::default()
            };
            let (mut host, device) = tokio::io::duplex(65536);
            let tunnel_cancel = cancel.child_token();
            let tunnel = tracker.spawn(tun2proxy::run_with_system_managed_network(
                device,
                1500,
                args,
                tunnel_cancel.clone(),
                None,
            ));
            let application = async {
                assert_eq!(udp_dns(&mut host).await[3], 0x80);
                let mut framed = (QUERY.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(QUERY);
                assert_eq!(
                    tcp_exchange(&mut host, PORTAL, 53, 43001, &framed).await[5],
                    0x80
                );
            };
            tokio::join!(peer, application);
            tunnel_cancel.cancel();
            tunnel.await.unwrap().unwrap();
            PROXY_CACHE.remove(resolver);
        }

        // A non-DNS connection to the same direct-cached host still uses the
        // direct listener, rather than globally forcing all TUN destinations.
        // macOS does not assign 127.0.0.2 to lo0 without an explicit alias.
        let direct = TcpListener::bind("[::1]:0").await.unwrap();
        PROXY_CACHE.insert("::1".into(), false);
        let mut stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&direct.local_addr().unwrap().port().to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let (_direct_stream, _) = direct.accept().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), remote.accept())
                .await
                .is_err()
        );
        PROXY_CACHE.remove("::1");
        cancel.cancel();
        tracker.close();
        tracker.wait().await;
    })
    .await
    .expect("real listener DNS routing timed out");
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn packet(stream: &mut DuplexStream) -> Vec<u8> {
    let mut header = [0; 20];
    stream.read_exact(&mut header).await.unwrap();
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut result = vec![0; length];
    result[..20].copy_from_slice(&header);
    stream.read_exact(&mut result[20..]).await.unwrap();
    result
}

async fn udp_dns(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    PacketBuilder::ipv4(CLIENT, PORTAL, 64)
        .udp(43000, 53)
        .write(&mut bytes, QUERY)
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    loop {
        let reply = packet(stream).await;
        if let Some(TransportSlice::Udp(udp)) = SlicedPacket::from_ip(&reply).unwrap().transport {
            assert_eq!(udp.destination_port(), 43000);
            return udp.payload().to_vec();
        }
    }
}

async fn tcp_exchange(
    stream: &mut DuplexStream,
    destination: [u8; 4],
    port: u16,
    source_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    PacketBuilder::ipv4(CLIENT, destination, 64)
        .tcp(source_port, port, 100, 65535)
        .syn()
        .write(&mut bytes, &[])
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let ack = loop {
        let reply = packet(stream).await;
        if let Some(TransportSlice::Tcp(tcp)) = SlicedPacket::from_ip(&reply).unwrap().transport
            && tcp.destination_port() == source_port
            && tcp.syn()
            && tcp.ack()
        {
            break tcp.sequence_number().wrapping_add(1);
        }
    };
    bytes.clear();
    PacketBuilder::ipv4(CLIENT, destination, 64)
        .tcp(source_port, port, 101, 65535)
        .ack(ack)
        .write(&mut bytes, payload)
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut received = Vec::new();
    loop {
        let reply = packet(stream).await;
        if let Some(TransportSlice::Tcp(tcp)) = SlicedPacket::from_ip(&reply).unwrap().transport
            && tcp.destination_port() == source_port
            && !tcp.payload().is_empty()
        {
            received.extend_from_slice(tcp.payload());
            if port != 53
                || (received.len() >= 2
                    && received.len()
                        >= 2 + u16::from_be_bytes([received[0], received[1]]) as usize)
            {
                return received;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_fake_ip_proxies_udp_and_tcp_dns_and_preserves_cached_domains() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = TempDir(std::env::temp_dir().join(format!(
            "proxy-dns-test-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir_all(&dir.0).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut args = Args {
            setup: false,
            proxy: ArgProxy::try_from(
                format!("socks5://{}", listener.local_addr().unwrap()).as_str(),
            )
            .unwrap(),
            dns: ArgDns::Virtual,
            dns_addr: "192.0.2.53".parse().unwrap(),
            // DNS must work even when ordinary UDP forwarding is disabled.
            udp_strategy: ArgUdpStrategy::Block,
            ..Args::default()
        };

        // First run models the old release, with a persistent Fake-IP answer.
        let state = VirtualDnsState::default();
        state.enable_persistence_in(&dir.0).await.unwrap();
        let (mut host, device) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let _cancel_guard = cancel.clone().drop_guard();
        let old = tokio::spawn(tun2proxy::run_with_system_managed_network(
            device,
            1500,
            args.clone(),
            cancel.clone(),
            Some(state),
        ));
        let answer = udp_dns(&mut host).await;
        assert_eq!(&answer[..2], &QUERY[..2]);
        let fake_ip: [u8; 4] = answer[answer.len() - 4..].try_into().unwrap();
        assert_eq!(&fake_ip[..2], &[198, 19]);
        cancel.cancel();
        old.await.unwrap().unwrap();
        let journal = dir.0.join("tun-virtual-dns-v1.jsonl");
        let previous = std::fs::read(&journal).unwrap();

        // Upgrade reloads the mapping but disables creation of new Fake-IPs.
        let state = VirtualDnsState::default();
        assert_eq!(state.enable_persistence_in(&dir.0).await.unwrap(), 1);
        args.dns = ArgDns::OverTcp;
        let (mut host, device) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let _cancel_guard = cancel.clone().drop_guard();
        let upgraded = tokio::spawn(tun2proxy::run_with_system_managed_network(
            device,
            1500,
            args,
            cancel.clone(),
            Some(state),
        ));

        // A deterministic SOCKS server verifies destinations; it never dials
        // them. Both DNS queries must use TCP CONNECT to the upstream resolver.
        let socks = tokio::spawn(async move {
            for request in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 2];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[0], 5);
                let mut methods = vec![0; greeting[1] as usize];
                stream.read_exact(&mut methods).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..3], &[5, 1, 0]);
                if request < 2 {
                    assert_eq!(header[3], 1);
                    let mut destination = [0; 6];
                    stream.read_exact(&mut destination).await.unwrap();
                    assert_eq!(destination, [192, 0, 2, 53, 0, 53]);
                } else {
                    assert_eq!(header[3], 3);
                    let length = stream.read_u8().await.unwrap() as usize;
                    let mut domain = vec![0; length];
                    stream.read_exact(&mut domain).await.unwrap();
                    assert_eq!(domain, b"example.test");
                    assert_eq!(stream.read_u16().await.unwrap(), 443);
                }
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                if request < 2 {
                    let length = stream.read_u16().await.unwrap() as usize;
                    let mut query = vec![0; length];
                    stream.read_exact(&mut query).await.unwrap();
                    assert_eq!(query, QUERY);
                    query[2] = 0x81;
                    query[3] = 0x80;
                    query[7] = 2;
                    query.extend_from_slice(
                        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xcb\x00\x71\x07",
                    );
                    // Both UDP and native TCP replies must strip AAAA when
                    // no IPv6 capture routes exist, while keeping the A answer.
                    query.extend_from_slice(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10");
                    query.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                    stream.write_u16(query.len() as u16).await.unwrap();
                    stream.write_all(&query).await.unwrap();
                } else {
                    stream.write_all(b"cached-domain-ok").await.unwrap();
                }
            }
        });
        let real = udp_dns(&mut host).await;
        assert_eq!(&real[real.len() - 4..], &[203, 0, 113, 7]);
        let mut framed = (QUERY.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(QUERY);
        let real = tcp_exchange(&mut host, PORTAL, 53, 43001, &framed).await;
        assert_eq!(&real[real.len() - 4..], &[203, 0, 113, 7]);
        assert_eq!(
            tcp_exchange(&mut host, fake_ip, 443, 43002, &[]).await,
            b"cached-domain-ok"
        );
        socks.await.unwrap();
        cancel.cancel();
        upgraded.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read(journal).unwrap(),
            previous,
            "real DNS must not allocate new Fake-IPs"
        );
    })
    .await
    .expect("packet DNS upgrade timed out");
}
