//! Endpoint name resolution that resists DNS pollution.
//!
//! Hostnames the client proxies are resolved by the server, inside the
//! encrypted session. The client's own route to the proxy is the exception:
//! node, relay and external-proxy hostnames are resolved locally before any
//! tunnel exists, by whatever resolver the network provides. On a censored
//! network that lookup is open to on-path injection (CircumVolve, CCS 2026,
//! §2): one forged answer sends the client to the wrong address, and the
//! cache keeps it there.
//!
//! [`EndpointDnsPolicy`] chooses the resolvers for exactly those lookups.
//! DNS-over-HTTPS authenticates the answer. Plaintext UDP resolvers get a
//! check that discards racing forged responses, and may opt into the paper's
//! two-question query shape. The default, `auto`, combines them: built-in
//! DNS-over-HTTPS servers first, and the platform resolver only while no
//! forged answer is seen on the path. Destination lookups are unaffected.
//! See `docs/endpoint-dns.md` for the threat model and its limits.

mod auto;
mod doh;
mod local;
mod policy;
mod udp;
mod wire;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub(crate) use auto::SystemResolver;
use futures::StreamExt;
use futures::future::Either;
use futures::stream::FuturesUnordered;
use hickory_proto::op::ResponseCode;
pub(crate) use local::{hosts_addresses, hosts_path};
pub use policy::{EndpointDnsPolicy, EndpointDnsSpec, ParsePolicyError};
use policy::{QueryShape, Resolver};
use snafu::Snafu;
use tokio::time::Instant;
pub(crate) use wire::is_routable_endpoint;
use wire::{Answer, Family, Layout, Query, QueryName};

/// How long an attempt runs alone before the next resolver joins it.
const HEDGE_DELAY: Duration = Duration::from_millis(500);
const MAX_IN_FLIGHT: usize = 2;
/// How long one address family may lag once the other has addresses.
const FAMILY_GRACE: Duration = Duration::from_millis(300);

/// Why one exchange with one resolver produced no answer.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub(crate) enum ExchangeError {
    #[snafu(display("cannot create the DNS-over-HTTPS client"))]
    HttpsClient { source: Arc<reqwest::Error> },
    #[snafu(display("DNS-over-HTTPS request failed"))]
    Https { source: reqwest::Error },
    #[snafu(display("DNS-over-HTTPS server answered HTTP {status}"))]
    HttpStatus { status: reqwest::StatusCode },
    #[snafu(display("DNS-over-HTTPS response is not application/dns-message"))]
    ContentType,
    #[snafu(display("DNS-over-HTTPS response is larger than any DNS message"))]
    Oversized,
    #[snafu(display("DNS socket failed"))]
    Socket { source: std::io::Error },
    #[snafu(display("no usable response before the deadline"))]
    TimedOut,
    #[snafu(display("malformed DNS response"))]
    Malformed,
    #[snafu(display("the response does not answer the query"))]
    Mismatched,
    #[snafu(display("resolver answered {code}"))]
    Rcode { code: ResponseCode },
    #[snafu(display("the response has a CNAME loop or an overlong CNAME chain"))]
    BrokenAliases,
    #[snafu(display("responses disagree; on-path injection suspected"))]
    Conflicting,
    #[snafu(display("only addresses no remote endpoint can have"))]
    Unroutable,
    #[snafu(display("answered with addresses outside the mainland that no other source confirms"))]
    Unconfirmed,
    #[snafu(display("the platform resolver failed"))]
    System { source: std::io::Error },
}

impl ExchangeError {
    /// Whether the failure says the resolver does not work from here, rather
    /// than something about the name that was asked.
    fn blames_resolver(&self) -> bool {
        match self {
            Self::HttpsClient { .. }
            | Self::Https { .. }
            | Self::HttpStatus { .. }
            | Self::ContentType
            | Self::Oversized
            | Self::Socket { .. }
            | Self::TimedOut
            | Self::Malformed
            | Self::Mismatched => true,
            Self::Rcode { .. }
            | Self::BrokenAliases
            | Self::Conflicting
            | Self::Unroutable
            | Self::Unconfirmed
            | Self::System { .. } => false,
        }
    }
}

impl From<wire::Rejection> for ExchangeError {
    fn from(rejection: wire::Rejection) -> Self {
        match rejection {
            wire::Rejection::Undecodable => Self::Malformed,
            wire::Rejection::Unrelated => Self::Mismatched,
            wire::Rejection::Failed(code) => Self::Rcode { code },
            wire::Rejection::BrokenAliases => Self::BrokenAliases,
        }
    }
}

/// What the network resolvers said about an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// IPv4 addresses first, then IPv6; `ttl` is the smallest record TTL.
    Addresses {
        addresses: Vec<IpAddr>,
        ttl: Duration,
    },
    /// The name has no address of either family.
    Missing { ttl: Option<Duration> },
}

/// Why no network resolver answered.
#[derive(Debug, Snafu)]
pub(crate) enum ResolveError {
    #[snafu(display("`{host}` is not a DNS name"))]
    InvalidName { host: String },
    #[snafu(display("no endpoint resolver answered: {failures}"))]
    Unanswered { failures: Failures },
}

impl ResolveError {
    pub(crate) fn kind(&self) -> std::io::ErrorKind {
        match self {
            Self::InvalidName { .. } => std::io::ErrorKind::InvalidInput,
            Self::Unanswered { failures } if failures.all_timed_out() => {
                std::io::ErrorKind::TimedOut
            }
            Self::Unanswered { .. } => std::io::ErrorKind::Other,
        }
    }
}

impl From<ResolveError> for std::io::Error {
    fn from(error: ResolveError) -> Self {
        Self::new(error.kind(), error)
    }
}

/// Each resolver's failure, labelled by its redacted form.
#[derive(Debug)]
pub(crate) struct Failures(Vec<(Arc<str>, ExchangeError)>);

impl Failures {
    fn all_timed_out(&self) -> bool {
        self.0
            .iter()
            .all(|(_, error)| matches!(error, ExchangeError::TimedOut))
    }
}

impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("the deadline passed before any attempt");
        }
        for (index, (resolver, error)) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{resolver}: {}", crate::util::error_report(error))?;
        }
        Ok(())
    }
}

static PLAINTEXT_CAPTURES: AtomicUsize = AtomicUsize::new(0);

/// Held while this machine answers the process's plaintext DNS itself instead
/// of delivering it, as a desktop TUN session does through its physical DNS
/// relay. The `auto` policy then skips its check for forged answers on the
/// path, which would only observe that relay.
#[derive(Debug)]
#[must_use = "the capture is over when this is dropped"]
pub struct PlaintextDnsCapture(());

impl PlaintextDnsCapture {
    pub fn begin() -> Self {
        PLAINTEXT_CAPTURES.fetch_add(1, Ordering::Relaxed);
        Self(())
    }
}

impl Drop for PlaintextDnsCapture {
    fn drop(&mut self) {
        PLAINTEXT_CAPTURES.fetch_sub(1, Ordering::Relaxed);
    }
}

fn plaintext_is_captured() -> bool {
    PLAINTEXT_CAPTURES.load(Ordering::Relaxed) > 0
}

/// The `auto` policy over one network, with what it has learned about it.
pub(crate) struct Automatic<B = auto::Network> {
    backend: B,
    memory: auto::Memory,
}

impl Automatic {
    /// The built-in resolvers, with `system` as the platform resolver.
    pub(crate) fn builtin(system: SystemResolver) -> Self {
        Self::over(auto::Network::builtin(system))
    }
}

impl<B: auto::Backend> Automatic<B> {
    fn over(backend: B) -> Self {
        Self {
            backend,
            memory: auto::Memory::new(),
        }
    }

    /// Resolves `host`, which is not an IP literal. `refresh` says that a
    /// connection to the previous answer failed. The record TTL is `None`
    /// when the answer's source reports none.
    pub(crate) async fn resolve(
        &self,
        host: &str,
        refresh: bool,
        deadline: Instant,
    ) -> std::io::Result<(Vec<IpAddr>, Option<Duration>)> {
        let public = QueryName::parse(host).filter(|name| !local::is_local_name(name.as_str()));
        let Some(name) = public else {
            // Nothing the public DNS can hold, so nothing a public resolver
            // should be told: only the platform resolver knows such names.
            let mut addresses = auto::Backend::system(&self.backend, host).await?;
            addresses.retain(|address| is_routable_endpoint(*address));
            return if addresses.is_empty() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    ExchangeError::Unroutable,
                ))
            } else {
                Ok((addresses, None))
            };
        };
        let accepted = auto::resolve(&self.backend, &self.memory, &name, refresh, deadline).await?;
        Ok((accepted.addresses, accepted.ttl))
    }
}

/// Resolves `host` through the policy's listed network resolvers. The caller
/// owns the system resolver, both alone and as a fallback.
pub(crate) async fn resolve(
    policy: &EndpointDnsPolicy,
    host: &str,
    deadline: Instant,
) -> Result<Resolution, ResolveError> {
    resolve_with(
        policy.listed(),
        host,
        deadline,
        udp::Timing::DEFAULT,
        doh::shared_client,
    )
    .await
}

async fn resolve_with<C>(
    resolvers: &[Resolver],
    host: &str,
    deadline: Instant,
    timing: udp::Timing,
    https_client: C,
) -> Result<Resolution, ResolveError>
where
    C: Fn() -> Result<reqwest::Client, ExchangeError>,
{
    let Some(name) = QueryName::parse(host) else {
        return InvalidNameSnafu { host }.fail();
    };
    let attempt = |index: usize| {
        let resolver = resolvers
            .get(index)
            .expect("race only starts indices below resolvers.len()");
        lookup(resolver, &name, timing, &https_client, deadline)
    };
    race(resolvers.len(), deadline, attempt)
        .await
        .map_err(|failures| ResolveError::Unanswered {
            failures: Failures(
                failures
                    .into_iter()
                    .map(|(index, error)| {
                        let label: Arc<str> = resolvers
                            .get(index)
                            .expect("race only reports indices it started")
                            .to_string()
                            .into();
                        (label, error)
                    })
                    .collect(),
            ),
        })
}

/// Starts attempts in order, the next one when the previous fails or has run
/// for [`HEDGE_DELAY`], with at most [`MAX_IN_FLIGHT`] running. The first
/// answer wins; losers are dropped, which cancels them.
async fn race<T, F, Fut>(
    count: usize,
    deadline: Instant,
    mut attempt: F,
) -> Result<T, Vec<(usize, ExchangeError)>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, ExchangeError>>,
{
    let mut pending = FuturesUnordered::new();
    let mut started = 0;
    let mut hedge_at = Instant::now();
    let mut failures = Vec::new();
    loop {
        let now = Instant::now();
        let may_start = started < count && now < deadline;
        if may_start && (pending.is_empty() || (pending.len() < MAX_IN_FLIGHT && now >= hedge_at)) {
            let index = started;
            let attempt = tokio::time::timeout_at(deadline, attempt(index));
            pending.push(
                async move { (index, attempt.await.unwrap_or(Err(ExchangeError::TimedOut))) },
            );
            started += 1;
            hedge_at = now + HEDGE_DELAY;
        }
        if pending.is_empty() {
            return Err(failures);
        }
        let hedge = may_start && pending.len() < MAX_IN_FLIGHT;
        tokio::select! {
            // A finished attempt beats the hedge timer on the same tick.
            biased;
            finished = pending.next() => match finished {
                Some((_, Ok(value))) => return Ok(value),
                Some((index, Err(error))) => {
                    failures.push((index, error));
                    hedge_at = Instant::now();
                }
                None => {}
            },
            () = tokio::time::sleep_until(hedge_at), if hedge => {}
        }
    }
}

#[derive(Clone, Copy)]
enum Transport<'a> {
    Https {
        client: &'a reqwest::Client,
        url: &'a url::Url,
    },
    Udp {
        server: SocketAddr,
        shape: QueryShape,
        timing: udp::Timing,
    },
}

/// Asks one resolver for both address families.
async fn lookup<C>(
    resolver: &Resolver,
    name: &QueryName,
    timing: udp::Timing,
    https_client: &C,
    deadline: Instant,
) -> Result<Resolution, ExchangeError>
where
    C: Fn() -> Result<reqwest::Client, ExchangeError>,
{
    let client;
    let transport = match resolver {
        Resolver::Https(url) => {
            client = https_client()?;
            Transport::Https {
                client: &client,
                url,
            }
        }
        Resolver::Udp { server, shape } => Transport::Udp {
            server: *server,
            shape: *shape,
            timing,
        },
    };
    let v4 = std::pin::pin!(exchange_family(
        resolver,
        transport,
        name,
        Family::V4,
        deadline
    ));
    let v6 = std::pin::pin!(exchange_family(
        resolver,
        transport,
        name,
        Family::V6,
        deadline
    ));
    let (first, rest) = match futures::future::select(v4, v6).await {
        Either::Left((first, rest)) | Either::Right((first, rest)) => (first, rest),
    };
    let second = if matches!(first.1, Ok(Answer::Addresses { .. })) {
        tokio::time::timeout(FAMILY_GRACE, rest).await.ok()
    } else {
        Some(rest.await)
    };
    let resolution = combine(first, second);
    if let Ok(resolution) = &resolution {
        tracing::debug!(host = name.as_str(), %resolver, ?resolution, "endpoint DNS answered");
    }
    resolution
}

async fn exchange_family(
    resolver: &Resolver,
    transport: Transport<'_>,
    name: &QueryName,
    family: Family,
    deadline: Instant,
) -> (Family, Result<Answer, ExchangeError>) {
    let result = match transport {
        Transport::Https { client, url } => {
            let query = Query::new(name, family, 0, Layout::Padded);
            doh::exchange(client, url, &query, deadline).await
        }
        Transport::Udp {
            server,
            shape,
            timing,
        } => {
            let query = Query::new(name, family, rand::random(), Layout::Plain(shape));
            udp::exchange(server, &query, timing, deadline).await
        }
    };
    if matches!(result, Err(ExchangeError::Conflicting)) {
        tracing::warn!(
            host = name.as_str(),
            %resolver,
            ?family,
            "endpoint DNS responses disagree; on-path injection suspected, discarding them"
        );
    }
    (family, result)
}

/// Merges the answers for both families. Disagreeing responses for either
/// family discredit the resolver for this name.
fn combine(
    first: (Family, Result<Answer, ExchangeError>),
    second: Option<(Family, Result<Answer, ExchangeError>)>,
) -> Result<Resolution, ExchangeError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut ttl = u32::MAX;
    let mut missing = 0;
    let mut negative_ttl: Option<u32> = None;
    let mut unroutable = false;
    let mut failure = None;
    for (family, result) in std::iter::once(first).chain(second) {
        match result {
            Ok(Answer::Addresses {
                addresses,
                ttl: answer_ttl,
            }) => {
                let routable: Vec<_> = addresses
                    .into_iter()
                    .filter(|address| is_routable_endpoint(*address))
                    .collect();
                if routable.is_empty() {
                    unroutable = true;
                    continue;
                }
                ttl = ttl.min(answer_ttl);
                match family {
                    Family::V4 => v4 = routable,
                    Family::V6 => v6 = routable,
                }
            }
            Ok(Answer::Missing { ttl, .. }) => {
                missing += 1;
                negative_ttl = match (negative_ttl, ttl) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (left, right) => left.or(right),
                };
            }
            Err(ExchangeError::Conflicting) => return Err(ExchangeError::Conflicting),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    let seconds = |ttl: u32| Duration::from_secs(ttl.into());
    if !v4.is_empty() || !v6.is_empty() {
        v4.append(&mut v6);
        return Ok(Resolution::Addresses {
            addresses: v4,
            ttl: seconds(ttl),
        });
    }
    if missing == 2 {
        return Ok(Resolution::Missing {
            ttl: negative_ttl.map(seconds),
        });
    }
    Err(failure.unwrap_or(if unroutable {
        ExchangeError::Unroutable
    } else {
        ExchangeError::TimedOut
    }))
}

/// Loopback resolvers and response builders for tests outside this module.
#[cfg(test)]
pub(crate) mod testing {
    pub(crate) use super::auto::Scope;
    pub(crate) use super::udp::tests::fake_server as fake_udp_resolver;
    pub(crate) use super::wire::tests::{addresses_reply_to, response_to_request};
    use super::*;

    /// A DNS-over-HTTPS server on loopback that answers each query with the
    /// message `reply` builds from it.
    pub(crate) async fn fake_https_resolver(
        reply: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> SocketAddr {
        doh::tests::fake_server(Arc::new(move |request: &[u8]| {
            doh::tests::dns_response(reply(request))
        }))
        .await
    }

    /// The `auto` policy over loopback: servers from [`fake_https_resolver`]
    /// as its authenticated resolvers, servers from [`fake_udp_resolver`] as
    /// its witnesses, and `system` as the platform resolver.
    pub(crate) fn loopback_automatic(
        resolvers: &[(SocketAddr, Scope)],
        witnesses: &[SocketAddr],
        system: SystemResolver,
    ) -> Automatic {
        let resolvers = resolvers
            .iter()
            .map(|(server, scope)| (Resolver::Https(doh::tests::url(*server)), *scope))
            .collect();
        Automatic::over(auto::Network::new(
            resolvers,
            witnesses.to_vec(),
            udp::tests::brief(),
            || Ok(doh::tests::trusting_client()),
            system,
            || false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::Message;
    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::dns::wire::tests::addresses_reply_to;

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x30));
    const FORGED: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));

    fn addresses(addresses: &[IpAddr], ttl: u32) -> Answer {
        Answer::Addresses {
            addresses: addresses.to_vec(),
            ttl,
        }
    }

    fn missing(ttl: Option<u32>) -> Answer {
        Answer::Missing {
            nxdomain: true,
            ttl,
        }
    }

    /// A reply with `v4` to A questions and `v6` to AAAA questions.
    fn by_family(request: &[u8], v4: &[IpAddr], v6: &[IpAddr]) -> Vec<u8> {
        let question = Message::from_vec(request).unwrap().queries[0].query_type;
        addresses_reply_to(request, if question == RecordType::A { v4 } else { v6 })
    }

    fn no_https() -> Result<reqwest::Client, ExchangeError> {
        panic!("no DoH resolver is configured")
    }

    #[test]
    fn families_are_merged_ipv4_first() {
        let merged = combine(
            (Family::V6, Ok(addresses(&[V6], 60))),
            Some((Family::V4, Ok(addresses(&[V4], 600)))),
        );
        assert_eq!(
            merged.unwrap(),
            Resolution::Addresses {
                addresses: vec![V4, V6],
                ttl: Duration::from_secs(60)
            }
        );
    }

    #[test]
    fn one_family_is_enough() {
        for second in [
            None,
            Some((Family::V6, Ok(missing(Some(5))))),
            Some((Family::V6, Err(ExchangeError::TimedOut))),
        ] {
            assert_eq!(
                combine((Family::V4, Ok(addresses(&[V4], 30))), second).unwrap(),
                Resolution::Addresses {
                    addresses: vec![V4],
                    ttl: Duration::from_secs(30)
                }
            );
        }
    }

    #[test]
    fn a_negative_answer_needs_both_families() {
        assert_eq!(
            combine(
                (Family::V4, Ok(missing(Some(30)))),
                Some((Family::V6, Ok(missing(Some(10)))))
            )
            .unwrap(),
            Resolution::Missing {
                ttl: Some(Duration::from_secs(10))
            }
        );
        assert!(matches!(
            combine(
                (Family::V4, Ok(missing(None))),
                Some((Family::V6, Err(ExchangeError::TimedOut)))
            ),
            Err(ExchangeError::TimedOut)
        ));
    }

    #[test]
    fn unroutable_answers_do_not_count() {
        let sinkhole = [IpAddr::V4(Ipv4Addr::UNSPECIFIED)];
        assert!(matches!(
            combine(
                (Family::V4, Ok(addresses(&sinkhole, 60))),
                Some((Family::V6, Ok(missing(None))))
            ),
            Err(ExchangeError::Unroutable)
        ));
        assert_eq!(
            combine((Family::V4, Ok(addresses(&[sinkhole[0], V4], 60))), None).unwrap(),
            Resolution::Addresses {
                addresses: vec![V4],
                ttl: Duration::from_secs(60)
            }
        );
    }

    #[test]
    fn injection_in_either_family_discredits_the_resolver() {
        assert!(matches!(
            combine(
                (Family::V6, Ok(addresses(&[V6], 60))),
                Some((Family::V4, Err(ExchangeError::Conflicting)))
            ),
            Err(ExchangeError::Conflicting)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn race_hedges_a_stalled_attempt() {
        let start = Instant::now();
        let result = race(2, start + Duration::from_secs(10), |index| async move {
            if index == 0 {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(index)
        })
        .await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(start.elapsed(), HEDGE_DELAY + Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn race_moves_on_at_once_after_a_failure() {
        let start = Instant::now();
        let result = race(2, start + Duration::from_secs(10), |index| async move {
            if index == 0 {
                Err(ExchangeError::Malformed)
            } else {
                Ok(index)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn race_runs_at_most_two_attempts_and_stops_at_the_deadline() {
        let start = Instant::now();
        let started = Cell::new(0);
        let result: Result<(), _> = race(4, start + Duration::from_secs(5), |_| {
            started.set(started.get() + 1);
            std::future::pending()
        })
        .await;
        let failures = result.unwrap_err();
        assert_eq!(started.get(), 2);
        let mut failed = failures.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        failed.sort_unstable();
        assert_eq!(failed, [0, 1]);
        assert!(
            failures
                .iter()
                .all(|(_, error)| matches!(error, ExchangeError::TimedOut))
        );
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn race_reports_every_failure_in_order() {
        let order = RefCell::new(Vec::new());
        let result: Result<(), _> = race(3, Instant::now() + Duration::from_secs(5), |index| {
            order.borrow_mut().push(index);
            async { Err(ExchangeError::Mismatched) }
        })
        .await;
        assert_eq!(result.unwrap_err().len(), 3);
        assert_eq!(*order.borrow(), [0, 1, 2]);
    }

    #[tokio::test]
    async fn injected_resolver_is_skipped_for_a_clean_one() {
        let injected = udp::tests::fake_server(|_, request| {
            vec![
                by_family(request, &[FORGED], &[]),
                by_family(request, &[V4], &[V6]),
            ]
        })
        .await;
        let clean =
            udp::tests::fake_server(|_, request| vec![by_family(request, &[V4], &[V6])]).await;
        let resolvers = [
            Resolver::Udp {
                server: injected,
                shape: QueryShape::Standard,
            },
            Resolver::Udp {
                server: clean,
                shape: QueryShape::Standard,
            },
        ];
        let deadline = Instant::now() + Duration::from_secs(5);
        let resolution = resolve_with(
            &resolvers,
            "Node.Example.",
            deadline,
            udp::tests::fast(),
            no_https,
        )
        .await
        .unwrap();
        assert_eq!(
            resolution,
            Resolution::Addresses {
                addresses: vec![V4, V6],
                ttl: Duration::from_secs(300)
            }
        );
    }

    #[tokio::test]
    async fn every_failure_is_reported_without_resolver_paths() {
        let injected = udp::tests::fake_server(|_, request| {
            vec![
                by_family(request, &[FORGED], &[]),
                by_family(request, &[V4], &[]),
            ]
        })
        .await;
        let doh = doh::tests::fake_server(Arc::new(|_: &[u8]| {
            hyper::Response::builder()
                .status(503)
                .body(http_body_util::Full::new(hyper::body::Bytes::new()))
                .unwrap()
        }))
        .await;
        let mut url = doh::tests::url(doh);
        url.set_path("/dns-query");
        url.set_query(Some("token=secret"));
        let resolvers = [
            Resolver::Udp {
                server: injected,
                shape: QueryShape::Standard,
            },
            Resolver::Https(url),
        ];
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = resolve_with(
            &resolvers,
            "node.example",
            deadline,
            udp::tests::fast(),
            || Ok(doh::tests::trusting_client()),
        )
        .await
        .unwrap_err();
        let report = error.to_string();
        assert!(
            report.contains(&format!("udp://{injected}: responses disagree")),
            "{report}"
        );
        assert!(
            report.contains(&format!(
                "https://{doh}: DNS-over-HTTPS server answered HTTP 503"
            )),
            "{report}"
        );
        assert!(!report.contains("secret"), "{report}");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn doh_resolver_answers_both_families() {
        let server = doh::tests::fake_server(Arc::new(|request: &[u8]| {
            doh::tests::dns_response(by_family(request, &[V4], &[V6]))
        }))
        .await;
        let resolvers = [Resolver::Https(doh::tests::url(server))];
        let deadline = Instant::now() + Duration::from_secs(5);
        let resolution = resolve_with(
            &resolvers,
            "node.example",
            deadline,
            udp::Timing::DEFAULT,
            || Ok(doh::tests::trusting_client()),
        )
        .await
        .unwrap();
        assert_eq!(
            resolution,
            Resolution::Addresses {
                addresses: vec![V4, V6],
                ttl: Duration::from_secs(300)
            }
        );
    }

    #[tokio::test]
    async fn names_are_validated_before_any_query() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = resolve_with(&[], "bad host", deadline, udp::Timing::DEFAULT, no_https)
            .await
            .unwrap_err();
        assert!(matches!(error, ResolveError::InvalidName { .. }));
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test(start_paused = true)]
    async fn names_only_this_network_knows_go_to_the_platform_resolver_alone() {
        use auto::tests::{Reply, Script};

        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let resolvers = [(auto::Scope::Global, vec![Reply::Addresses(10, vec![V4])])];
        let automatic = Automatic::over(Script::new(resolvers).system(5, &[local]));
        let deadline = Instant::now() + Duration::from_secs(5);
        for host in [
            "nas",
            "proxy.lan",
            "node.internal",
            "Printer.Local.",
            "bad host",
        ] {
            let answer = automatic.resolve(host, false, deadline).await.unwrap();
            assert_eq!(answer, (vec![local], None), "{host}");
        }
        assert!(automatic.backend.asked().is_empty());
        assert_eq!(automatic.backend.system_asked().len(), 5);

        // A public name is the authenticated resolvers' to answer.
        let answer = automatic
            .resolve("Node.Example.COM.", false, deadline)
            .await
            .unwrap();
        assert_eq!(answer, (vec![V4], Some(Duration::from_secs(120))));
        assert_eq!(automatic.backend.asked().len(), 1);
        assert!(automatic.backend.system_asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_local_name_with_only_unroutable_addresses_has_no_endpoint() {
        use auto::tests::{Reply, Script};

        let sinkhole = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let script = Script::new([(auto::Scope::Global, vec![Reply::Silent])]);
        let automatic = Automatic::over(script.system(5, &[sinkhole]));
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = automatic.resolve("nas", false, deadline).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn plaintext_capture_lasts_as_long_as_any_guard() {
        assert!(!plaintext_is_captured());
        let first = PlaintextDnsCapture::begin();
        let second = PlaintextDnsCapture::begin();
        drop(first);
        assert!(plaintext_is_captured());
        drop(second);
        assert!(!plaintext_is_captured());
    }
}
