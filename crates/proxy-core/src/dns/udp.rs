//! Plaintext DNS over UDP, with a check for racing forged responses.
//!
//! The GFW's injectors answer a matching query with forged responses but let
//! the query continue, so the real response arrives after them (CircumVolve
//! §2; Duan et al., "Hold-On", 2012). An exchange therefore keeps listening
//! for [`INJECTION_WINDOW`] after the first response that matches its query,
//! and discards everything if the responses disagree. This detects a race; it
//! authenticates nothing. A forgery that arrives alone, because the real
//! response is dropped or slower than the window, is accepted, and so is any
//! response from an attacker that can also drop packets. The source port, ID
//! and question checks only stop off-path guessing.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto::op::ResponseCode;
use snafu::ResultExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, Instant};

use super::wire::{self, Answer, Query, Rejection};
use super::{ExchangeError, SocketSnafu};

/// How long an exchange waits for disagreeing responses after the first one.
/// Injected responses come from the path and real ones from the resolver, so
/// the gap is at least the round trip beyond the injector.
const INJECTION_WINDOW: Duration = Duration::from_millis(300);
const RETRANSMIT_AFTER: Duration = Duration::from_secs(1);
/// Larger than the EDNS payload queries advertise.
const MAX_DATAGRAM: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    window: Duration,
    retransmit_after: Duration,
}

impl Timing {
    pub(crate) const DEFAULT: Self = Self {
        window: INJECTION_WINDOW,
        retransmit_after: RETRANSMIT_AFTER,
    };
}

/// What a matching response asserts, for comparing responses to one query.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Answer(Answer),
    Truncated,
    Failed(ResponseCode),
    BrokenAliases,
}

impl Outcome {
    fn agrees_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Answer(left), Self::Answer(right)) => left.same_data(right),
            _ => self == other,
        }
    }
}

/// What an observation window settled on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Settled {
    Answer(Answer),
    Truncated,
}

/// Collects the responses to one query and decides when to trust them.
#[derive(Debug)]
pub(crate) struct Observer {
    window: Duration,
    first: Option<(Instant, Outcome)>,
    conflicting: bool,
}

impl Observer {
    pub(crate) fn new(window: Duration) -> Self {
        Self {
            window,
            first: None,
            conflicting: false,
        }
    }

    /// Records a datagram. Ones that are not a response to `query` are ignored
    /// rather than treated as an attack: anyone can send them.
    pub(crate) fn observe(&mut self, query: &Query, datagram: &[u8], now: Instant) {
        let outcome = match wire::parse(query, datagram) {
            Ok(response) if response.truncated => Outcome::Truncated,
            Ok(response) => Outcome::Answer(response.answer),
            Err(Rejection::Failed(code)) => Outcome::Failed(code),
            Err(Rejection::BrokenAliases) => Outcome::BrokenAliases,
            Err(Rejection::Undecodable | Rejection::Unrelated) => return,
        };
        match &self.first {
            None => self.first = Some((now, outcome)),
            Some((_, first)) => self.conflicting |= !first.agrees_with(&outcome),
        }
    }

    fn has_response(&self) -> bool {
        self.first.is_some()
    }

    /// When the responses seen so far settle unless another one disagrees.
    fn settles_at(&self) -> Option<Instant> {
        self.first.as_ref().map(|(at, _)| *at + self.window)
    }

    /// The decision, once one can be made.
    pub(crate) fn verdict(&self, now: Instant) -> Option<Result<Settled, ExchangeError>> {
        if self.conflicting {
            return Some(Err(ExchangeError::Conflicting));
        }
        let (at, outcome) = self.first.as_ref()?;
        if now < *at + self.window {
            return None;
        }
        Some(match outcome {
            Outcome::Answer(answer) => Ok(Settled::Answer(answer.clone())),
            Outcome::Truncated => Ok(Settled::Truncated),
            Outcome::Failed(code) => Err(ExchangeError::Rcode { code: *code }),
            Outcome::BrokenAliases => Err(ExchangeError::BrokenAliases),
        })
    }
}

/// Resolves `query` at `server`, retrying over TCP when the answer is
/// truncated. TCP carries no injection check: an on-path attacker sees the
/// sequence numbers it would need to forge a segment.
pub(crate) async fn exchange(
    server: SocketAddr,
    query: &Query,
    timing: Timing,
    deadline: Instant,
) -> Result<Answer, ExchangeError> {
    match exchange_datagram(server, query, timing, deadline).await? {
        Settled::Answer(answer) => Ok(answer),
        Settled::Truncated => exchange_stream(server, query, deadline).await,
    }
}

async fn exchange_datagram(
    server: SocketAddr,
    query: &Query,
    timing: Timing,
    deadline: Instant,
) -> Result<Settled, ExchangeError> {
    let local: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    // A fresh socket per query gives each one a random ephemeral port, and
    // connecting it makes the kernel drop datagrams from other sources.
    let socket = UdpSocket::bind(local).await.context(SocketSnafu)?;
    socket.connect(server).await.context(SocketSnafu)?;
    socket.send(query.bytes()).await.context(SocketSnafu)?;

    let mut observer = Observer::new(timing.window);
    let mut retransmit_at = Some(Instant::now() + timing.retransmit_after);
    let mut receiving = true;
    let mut buffer = vec![0; MAX_DATAGRAM];
    loop {
        let wake = observer
            .settles_at()
            .or(retransmit_at)
            .map_or(deadline, |at| at.min(deadline));
        tokio::select! {
            received = socket.recv(&mut buffer), if receiving => match received {
                Ok(length) => observer.observe(query, &buffer[..length], Instant::now()),
                // A connected socket reports ICMP errors here. Before any
                // response that ends this attempt early; afterwards the
                // window still decides, and a repeating error must not spin.
                Err(error) if !observer.has_response() => {
                    return Err(ExchangeError::Socket { source: error });
                }
                Err(_) => receiving = false,
            },
            () = tokio::time::sleep_until(wake) => {}
        }
        let now = Instant::now();
        if let Some(verdict) = observer.verdict(now) {
            return verdict;
        }
        if now >= deadline {
            return Err(ExchangeError::TimedOut);
        }
        if !observer.has_response() && retransmit_at.is_some_and(|at| now >= at) {
            retransmit_at = None;
            socket.send(query.bytes()).await.context(SocketSnafu)?;
        }
    }
}

async fn exchange_stream(
    server: SocketAddr,
    query: &Query,
    deadline: Instant,
) -> Result<Answer, ExchangeError> {
    let exchange = async {
        let mut stream = TcpStream::connect(server).await?;
        let length = u16::try_from(query.bytes().len()).map_err(std::io::Error::other)?;
        let mut framed = Vec::with_capacity(2 + query.bytes().len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(query.bytes());
        stream.write_all(&framed).await?;
        let length = stream.read_u16().await?;
        let mut message = vec![0; usize::from(length)];
        stream.read_exact(&mut message).await?;
        Ok(message)
    };
    let message = tokio::time::timeout_at(deadline, exchange)
        .await
        .map_err(|_| ExchangeError::TimedOut)?
        .context(SocketSnafu)?;
    // Over TCP a set TC bit cannot be resolved further; use what arrived.
    wire::parse(query, &message)
        .map(|response| response.answer)
        .map_err(ExchangeError::from)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::IpAddr;

    use hickory_proto::op::Message;
    use tokio::net::TcpListener;

    use super::*;
    use crate::dns::policy::QueryShape;
    use crate::dns::wire::tests::{
        addresses_reply, addresses_reply_to, name, response_to, response_to_request,
    };
    use crate::dns::wire::{Family, Layout};

    const REAL: [u8; 4] = [203, 0, 113, 10];
    const FORGED: [u8; 4] = [198, 51, 100, 66];

    pub(crate) fn fast() -> Timing {
        Timing {
            window: Duration::from_millis(50),
            retransmit_after: Duration::from_millis(200),
        }
    }

    /// A resolver on loopback that passes each query, numbered from zero, to
    /// `reply` and sends back every datagram it returns, in order.
    pub(crate) async fn fake_server<F>(reply: F) -> SocketAddr
    where
        F: Fn(usize, &[u8]) -> Vec<Vec<u8>> + Send + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0; MAX_DATAGRAM];
            for received in 0.. {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                for datagram in reply(received, &buffer[..length]) {
                    socket.send_to(&datagram, peer).await.unwrap();
                }
            }
        });
        address
    }

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::from(octets)
    }

    fn query(shape: QueryShape) -> Query {
        Query::new(
            &name("node.example"),
            Family::V4,
            0x5151,
            Layout::Plain(shape),
        )
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn addresses(answer: &Answer) -> Vec<IpAddr> {
        match answer {
            Answer::Addresses { addresses, .. } => addresses.clone(),
            Answer::Missing { .. } => Vec::new(),
        }
    }

    #[test]
    fn single_answer_settles_after_the_window() {
        let query = query(QueryShape::Standard);
        let start = Instant::now();
        let mut observer = Observer::new(Duration::from_millis(300));
        assert!(observer.verdict(start).is_none());
        observer.observe(&query, &addresses_reply(&query, &[ip(REAL)]), start);
        assert!(
            observer
                .verdict(start + Duration::from_millis(299))
                .is_none()
        );
        let verdict = observer
            .verdict(start + Duration::from_millis(300))
            .unwrap()
            .unwrap();
        let Settled::Answer(answer) = verdict else {
            panic!("expected an answer");
        };
        assert_eq!(addresses(&answer), [ip(REAL)]);
    }

    #[test]
    fn racing_forgery_discards_the_exchange() {
        let query = query(QueryShape::Standard);
        let start = Instant::now();
        let mut observer = Observer::new(Duration::from_millis(300));
        observer.observe(&query, &addresses_reply(&query, &[ip(FORGED)]), start);
        observer.observe(
            &query,
            &addresses_reply(&query, &[ip(REAL)]),
            start + Duration::from_millis(40),
        );
        // The conflict is final at once; neither answer is chosen.
        assert!(matches!(
            observer.verdict(start + Duration::from_millis(40)),
            Some(Err(ExchangeError::Conflicting))
        ));
    }

    #[test]
    fn duplicates_and_reordered_records_agree() {
        let query = query(QueryShape::Standard);
        let start = Instant::now();
        let mut observer = Observer::new(Duration::from_millis(300));
        let both = [ip(REAL), ip([203, 0, 113, 11])];
        observer.observe(&query, &addresses_reply(&query, &both), start);
        observer.observe(&query, &addresses_reply(&query, &[both[1], both[0]]), start);
        assert!(matches!(
            observer.verdict(start + Duration::from_secs(1)),
            Some(Ok(Settled::Answer(_)))
        ));
    }

    #[test]
    fn unrelated_datagrams_neither_start_nor_spoil_the_window() {
        let query = query(QueryShape::Standard);
        let other = Query::new(
            &name("other.example"),
            Family::V4,
            0x5151,
            Layout::Plain(QueryShape::Standard),
        );
        let start = Instant::now();
        let mut observer = Observer::new(Duration::from_millis(300));
        observer.observe(&query, b"\x51\x51garbage", start);
        observer.observe(&query, &addresses_reply(&other, &[ip(FORGED)]), start);
        assert!(observer.verdict(start + Duration::from_secs(1)).is_none());
        observer.observe(&query, &addresses_reply(&query, &[ip(REAL)]), start);
        observer.observe(
            &query,
            &addresses_reply(&other, &[ip(FORGED)]),
            start + Duration::from_millis(10),
        );
        assert!(matches!(
            observer.verdict(start + Duration::from_secs(1)),
            Some(Ok(Settled::Answer(_)))
        ));
    }

    #[test]
    fn a_forged_failure_racing_an_answer_is_a_conflict() {
        let query = query(QueryShape::Standard);
        let start = Instant::now();
        let refused = response_to(&query, ResponseCode::Refused, Vec::new())
            .to_vec()
            .unwrap();
        let mut observer = Observer::new(Duration::from_millis(300));
        observer.observe(&query, &refused, start);
        observer.observe(&query, &addresses_reply(&query, &[ip(REAL)]), start);
        assert!(matches!(
            observer.verdict(start),
            Some(Err(ExchangeError::Conflicting))
        ));

        let mut alone = Observer::new(Duration::from_millis(300));
        alone.observe(&query, &refused, start);
        assert!(matches!(
            alone.verdict(start + Duration::from_secs(1)),
            Some(Err(ExchangeError::Rcode {
                code: ResponseCode::Refused
            }))
        ));
    }

    #[tokio::test]
    async fn exchange_accepts_a_lone_answer() {
        let server = fake_server(|_, request| vec![addresses_reply_to(request, &[ip(REAL)])]).await;
        let answer = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap();
        assert_eq!(addresses(&answer), [ip(REAL)]);
    }

    #[tokio::test]
    async fn exchange_rejects_an_injected_race() {
        let server = fake_server(|_, request| {
            vec![
                addresses_reply_to(request, &[ip(FORGED)]),
                addresses_reply_to(request, &[ip([198, 51, 100, 67])]),
                addresses_reply_to(request, &[ip(REAL)]),
            ]
        })
        .await;
        let error = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::Conflicting), "{error}");
    }

    #[tokio::test]
    async fn exchange_skips_noise_before_the_answer() {
        let server = fake_server(|_, request| {
            let mut wrong_id = addresses_reply_to(request, &[ip(FORGED)]);
            wrong_id[0] ^= 0xFF;
            vec![
                b"not dns".to_vec(),
                wrong_id,
                addresses_reply_to(request, &[ip(REAL)]),
            ]
        })
        .await;
        let answer = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap();
        assert_eq!(addresses(&answer), [ip(REAL)]);
    }

    #[tokio::test]
    async fn exchange_retransmits_a_lost_query_once() {
        let server = fake_server(|count, request| {
            if count == 0 {
                Vec::new()
            } else {
                vec![addresses_reply_to(request, &[ip(REAL)])]
            }
        })
        .await;
        let answer = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap();
        assert_eq!(addresses(&answer), [ip(REAL)]);
    }

    #[tokio::test]
    async fn exchange_times_out_without_a_response() {
        let server = fake_server(|_, _| Vec::new()).await;
        let deadline = Instant::now() + Duration::from_millis(300);
        let error = exchange(server, &query(QueryShape::Standard), fast(), deadline)
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::TimedOut), "{error}");
    }

    #[tokio::test]
    async fn dual_question_queries_reach_the_server_intact() {
        let server = fake_server(|_, request| {
            let message = Message::from_vec(request).unwrap();
            assert_eq!(message.queries.len(), 2);
            assert!(message.edns.is_none());
            vec![addresses_reply_to(request, &[ip(REAL)])]
        })
        .await;
        let answer = exchange(server, &query(QueryShape::DualQuestion), fast(), deadline())
            .await
            .unwrap();
        assert_eq!(addresses(&answer), [ip(REAL)]);
    }

    #[tokio::test]
    async fn truncated_answer_is_retried_over_tcp() {
        // UDP and TCP ports are separate, so both can share the number.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0; MAX_DATAGRAM];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let mut truncated =
                response_to_request(&buffer[..length], ResponseCode::NoError, Vec::new());
            truncated.metadata.truncation = true;
            udp.send_to(&truncated.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut request = vec![0; usize::from(length)];
            stream.read_exact(&mut request).await.unwrap();
            let reply = addresses_reply_to(&request, &[ip(REAL), ip([203, 0, 113, 12])]);
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let server = SocketAddr::from(([127, 0, 0, 1], port));
        let answer = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap();
        assert_eq!(addresses(&answer), [ip(REAL), ip([203, 0, 113, 12])]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closed_port_fails_without_waiting_for_the_deadline() {
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = closed.local_addr().unwrap();
        drop(closed);
        let started = std::time::Instant::now();
        let error = exchange(server, &query(QueryShape::Standard), fast(), deadline())
            .await
            .unwrap_err();
        assert!(matches!(error, ExchangeError::Socket { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
