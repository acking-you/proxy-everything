//! Node and external-proxy names follow the process-wide endpoint DNS policy
//! at the call sites that dial them. A separate test process, because the
//! policy is global. The resolver is a loopback fake; nothing here reaches a
//! public resolver.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{LazyLock, Once};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use proxy_core::relay::ExternalProxyTarget;
use proxy_core::transport::{
    get_tcp_external_proxy_stream, resolve_endpoint_addresses, set_endpoint_dns,
};
use proxy_core::upstream::UpstreamAddress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NODE: &str = "node.endpoint-dns.test";
const INJECTED: &str = "injected.endpoint-dns.test";
const PROXY: &str = "proxy.endpoint-dns.test";
const FORGED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);

/// Answers A questions for the names above with 127.0.0.1, preceded for
/// [`INJECTED`] by a forged answer the way an on-path injector races the
/// real resolver. Other types get NODATA and other names NXDOMAIN.
fn reply(request: &[u8]) -> Vec<Vec<u8>> {
    let request = Message::from_vec(request).unwrap();
    let question = request.queries[0].clone();
    let respond = |code: ResponseCode, answer: Option<Ipv4Addr>| {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.response_code = code;
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.queries = request.queries.clone();
        response.answers = answer
            .map(|address| Record::from_rdata(question.name.clone(), 60, RData::A(A(address))))
            .into_iter()
            .collect();
        response.to_vec().unwrap()
    };
    let name = question.name.to_string();
    let name = name.trim_end_matches('.');
    if ![NODE, INJECTED, PROXY].contains(&name) {
        return vec![respond(ResponseCode::NXDomain, None)];
    }
    if question.query_type != RecordType::A {
        return vec![respond(ResponseCode::NoError, None)];
    }
    let real = respond(ResponseCode::NoError, Some(Ipv4Addr::LOCALHOST));
    if name == INJECTED {
        vec![respond(ResponseCode::NoError, Some(FORGED)), real]
    } else {
        vec![real]
    }
}

static RESOLVER: LazyLock<SocketAddr> = LazyLock::new(|| {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0; 4096];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
            for datagram in reply(&buffer[..length]) {
                let _ = socket.send_to(&datagram, peer);
            }
        }
    });
    address
});

fn use_loopback_resolver() {
    static POLICY: Once = Once::new();
    POLICY.call_once(|| set_endpoint_dns(format!("udp://{}", *RESOLVER).parse().unwrap()));
}

#[tokio::test]
async fn native_nodes_are_dialled_at_the_address_the_policy_resolves() {
    use_loopback_resolver();
    let node = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = node.local_addr().unwrap().port();
    let address = UpstreamAddress::parse(&format!("{NODE}:{port}")).unwrap();

    let (connected, accepted) = tokio::join!(address.connect(), node.accept());
    connected.unwrap();
    accepted.unwrap();
    assert_eq!(
        *resolve_endpoint_addresses(NODE).await.unwrap(),
        [IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
}

#[tokio::test]
async fn an_injected_race_fails_closed_instead_of_dialling_either_answer() {
    use_loopback_resolver();
    let started = Instant::now();
    let Err(error) = UpstreamAddress::parse(&format!("{INJECTED}:1081"))
        .unwrap()
        .connect()
        .await
    else {
        panic!("a node behind an injected answer was connected");
    };
    assert!(
        error.to_string().contains("on-path injection suspected"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn external_proxies_are_resolved_under_the_endpoint_policy() {
    use_loopback_resolver();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let target = ExternalProxyTarget::parse(&format!("http://{PROXY}:{port}")).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let length = stream.read(&mut buffer).await.unwrap();
            assert_ne!(length, 0, "the client closed before finishing CONNECT");
            request.extend_from_slice(&buffer[..length]);
        }
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });

    get_tcp_external_proxy_stream(&target, "203.0.113.1", 443, "endpoint DNS test")
        .await
        .unwrap();
    let request = server.await.unwrap();
    assert!(request.starts_with("CONNECT 203.0.113.1:443 "), "{request}");
}
