//! The `auto` endpoint policy: authenticated resolvers first, and an
//! unauthenticated answer only while nothing on the path is seen forging it.
//!
//! A lookup races DNS-over-HTTPS servers of two kinds. *Global* ones resolve
//! from outside the mainland's border filter, so their answer is taken as it
//! is; on a censored network they are usually unreachable. *Mainland* ones
//! stay reachable there, and TLS keeps the path from changing what they say,
//! but their own upstream queries cross the same filter, so their caches hold
//! its forgeries for the names it targets. The forged addresses measured so
//! far are public ones outside the mainland (Hoang et al., USENIX Security
//! 2021, §5), which gives the rule: a mainland resolver's answer inside
//! mainland address space is accepted, and one outside it needs a second
//! opinion from beyond that cache. A plaintext witness or the platform
//! resolver naming one of the same addresses is one. Having no other answer
//! at all is the only other way such an answer is used.
//!
//! The witnesses are plaintext resolvers beyond the filter, asked once per
//! name. The filter's injectors race the real response instead of replacing
//! it (CircumVolve §4.2), so disagreeing responses mean the name is targeted
//! here. Then nothing unauthenticated is believed on its own: an address is
//! used only when the response that trailed the forgeries carries it too.
//! The paper's two-question query, which the injectors ignored when it was
//! measured, is sent for one more candidate. Without a corroborated address
//! the lookup fails rather than hand over a forged one.
//!
//! The platform resolver is the floor. It answers when no authenticated
//! resolver does, under the same verdict, and it is consulted again after a
//! connection to the resolved addresses failed, so an answer that is
//! authentic but unusable here (NAT64, split horizon) does no worse than the
//! platform resolver alone would have.
//!
//! None of this authenticates a plaintext answer. A path that drops the real
//! response, or whose forgeries all carry one address, shows a single story
//! and reads as clean; `auto` is then as exposed as the platform resolver.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures::future::{BoxFuture, Fuse, FutureExt};
use futures::stream::{FuturesUnordered, StreamExt};
use moka::sync::Cache;
use snafu::Snafu;
use tokio::time::Instant;

use super::policy::{ENCRYPTED_PRESET, QueryShape, Resolver, parse_https};
use super::udp::{self, Sighting};
use super::wire::{Family, Layout, Query, QueryName, is_routable_endpoint};
use super::{ExchangeError, Failures, Resolution};
use crate::geo::is_china_ip;

/// How long a resolver runs alone before the next one joins it. Shorter than
/// for a listed policy: here the first resolvers are expected to be
/// unreachable on exactly the networks that need the later ones.
const HEDGE_DELAY: Duration = Duration::from_millis(200);
const MAX_IN_FLIGHT: usize = 4;
/// The head start authenticated resolvers get before the platform resolver's
/// answer may stand alone.
const SYSTEM_AFTER: Duration = Duration::from_millis(600);
/// How long an authenticated answer waits for the platform resolver once it
/// wants that resolver's addresses: a re-resolution to add them to its own,
/// a mainland resolver's answer to be seconded by them. A platform resolver
/// that hangs, as one does behind a tunnel that is down, must not hold back
/// the answer that would bring the tunnel up.
const PLATFORM_WAIT: Duration = Duration::from_secs(1);
/// How long a resolver sits out after it failed or stalled, doubling with
/// each consecutive strike. The cap bounds how long a network change goes
/// unnoticed.
const BENCH_BASE: Duration = Duration::from_secs(30);
const BENCH_CAP: Duration = Duration::from_secs(10 * 60);
const VERDICT_CAPACITY: u64 = 1024;
const CLEAN_FOR: Duration = Duration::from_secs(10 * 60);
const UNOBSERVED_FOR: Duration = Duration::from_secs(2 * 60);
const INJECTED_FOR: Duration = Duration::from_secs(60);
/// The least time between two warnings of one kind; lookups repeat for as
/// long as the network stays the way it is.
const NOTICE_EVERY: Duration = Duration::from_secs(10 * 60);

const _: () = assert!(
    HEDGE_DELAY.as_millis() < SYSTEM_AFTER.as_millis(),
    "an authenticated resolver must be hedged before the platform resolver may answer alone"
);

/// DNS-over-HTTPS servers of mainland operators (AliDNS and DNSPod), by
/// address like the global ones, and alternating for the same reason.
const MAINLAND_PRESET: [&str; 4] = [
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
    "https://223.6.6.6/dns-query",
    "https://120.53.53.53/dns-query",
];

/// Plaintext resolvers beyond the border filter that also answer the
/// two-question query (CircumVolve Table 2).
const WITNESSES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
];

/// Where an authenticated resolver stands relative to the border filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Global,
    Mainland,
}

/// An authenticated resolver as the cascade sees it.
#[derive(Clone, Debug)]
pub(crate) struct Authenticated {
    /// For logs and errors; never a URL path.
    pub(crate) label: String,
    pub(crate) scope: Scope,
}

/// What a lookup asks of the network. Tests answer from memory.
pub(crate) trait Backend: Sync {
    /// The authenticated resolvers, in launch order.
    fn resolvers(&self) -> &[Authenticated];

    /// Both address families from resolver `index`.
    fn ask(
        &self,
        index: usize,
        name: &QueryName,
        deadline: Instant,
    ) -> impl Future<Output = Result<Resolution, ExchangeError>> + Send;

    /// The platform resolver's addresses for `host`.
    fn system(&self, host: &str) -> impl Future<Output = std::io::Result<Vec<IpAddr>>> + Send;

    /// Whether a plaintext query reaches the server it is addressed to. It
    /// does not while a TUN session on this machine answers such queries
    /// itself.
    fn can_witness(&self) -> bool;

    /// One plaintext A query of `shape` to every witness.
    fn witness(
        &self,
        name: &QueryName,
        shape: QueryShape,
    ) -> impl Future<Output = Vec<Sighting>> + Send;
}

/// What the plaintext path does to queries for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A witness answered, and none drew disagreeing responses. `seen` is
    /// what they answered with, stand-in addresses aside.
    Clean { seen: Vec<IpAddr> },
    /// No witness answered, or none can be reached.
    Unobserved,
    /// Responses disagreed. `held` is what the trailing ones said.
    Injected { held: Vec<IpAddr> },
}

/// Who vouches for an accepted answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Global,
    Mainland,
    System,
    /// Two independent observations, while forged answers are on the path.
    Corroborated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Accepted {
    pub(crate) addresses: Vec<IpAddr>,
    /// The record TTL, when the source reports one.
    pub(crate) ttl: Option<Duration>,
    pub(crate) source: Source,
}

/// Why a lookup produced no address.
#[derive(Debug, Snafu)]
pub(crate) enum Failure {
    #[snafu(display("no A or AAAA record"))]
    Missing,
    #[snafu(display(
        "forged DNS answers for this name are on the network path and no answer could be \
         confirmed; give the endpoint as an IP address, or set an endpoint DNS resolver this \
         network can reach ({failures})"
    ))]
    Forged { failures: Failures },
    #[snafu(display("no resolver answered: {failures}"))]
    Unanswered { failures: Failures },
}

impl Failure {
    pub(crate) fn kind(&self) -> std::io::ErrorKind {
        match self {
            Self::Missing => std::io::ErrorKind::NotFound,
            Self::Forged { .. } => std::io::ErrorKind::Other,
            Self::Unanswered { failures } if failures.all_timed_out() => {
                std::io::ErrorKind::TimedOut
            }
            Self::Unanswered { .. } => std::io::ErrorKind::Other,
        }
    }
}

impl From<Failure> for std::io::Error {
    fn from(failure: Failure) -> Self {
        Self::new(failure.kind(), failure)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Health {
    strikes: u32,
    benched_until: Option<Instant>,
}

#[derive(Clone, Copy)]
enum Notice {
    Injected,
    Corroborated,
    SystemFallback,
}

/// What earlier lookups learned about this network: which resolvers do not
/// answer here, and which names are being forged.
pub(crate) struct Memory {
    health: Mutex<Vec<Health>>,
    verdicts: Cache<String, (Verdict, Instant)>,
    notices: Mutex<[Option<Instant>; 3]>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every critical section is a few assignments; none can leave the value
    // half-updated.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Memory {
    pub(crate) fn new() -> Self {
        Self {
            health: Mutex::new(Vec::new()),
            verdicts: Cache::builder().max_capacity(VERDICT_CAPACITY).build(),
            notices: Mutex::new([None; 3]),
        }
    }

    /// Resolvers to launch, in order, and the benched ones left out.
    /// `everyone` ignores the bench.
    fn launch_order(
        &self,
        count: usize,
        now: Instant,
        everyone: bool,
    ) -> (VecDeque<usize>, Vec<usize>) {
        let health = lock(&self.health);
        let benched = |index: usize| {
            health
                .get(index)
                .and_then(|health| health.benched_until)
                .is_some_and(|until| now < until)
        };
        let (launch, sit_out): (Vec<usize>, Vec<usize>) =
            (0..count).partition(|index| everyone || !benched(*index));
        (launch.into(), sit_out)
    }

    fn penalize(&self, index: usize, now: Instant) {
        let mut health = lock(&self.health);
        if health.len() <= index {
            health.resize(index + 1, Health::default());
        }
        let entry = &mut health[index];
        entry.strikes = entry.strikes.saturating_add(1);
        let doublings = (entry.strikes - 1).min(16);
        let bench = BENCH_BASE.saturating_mul(1 << doublings).min(BENCH_CAP);
        entry.benched_until = Some(now + bench);
    }

    fn reward(&self, index: usize) {
        if let Some(entry) = lock(&self.health).get_mut(index) {
            *entry = Health::default();
        }
    }

    fn verdict(&self, name: &str, now: Instant) -> Option<Verdict> {
        let (verdict, until) = self.verdicts.get(name)?;
        (now < until).then_some(verdict)
    }

    fn remember(&self, name: &str, verdict: &Verdict, now: Instant) {
        let keep = match verdict {
            Verdict::Clean { .. } => CLEAN_FOR,
            Verdict::Unobserved => UNOBSERVED_FOR,
            Verdict::Injected { .. } => INJECTED_FOR,
        };
        self.verdicts
            .insert(name.to_owned(), (verdict.clone(), now + keep));
    }

    /// Whether a warning of this kind is due, and if so counts it as given.
    fn due(&self, notice: Notice, now: Instant) -> bool {
        let mut notices = lock(&self.notices);
        let last = &mut notices[notice as usize];
        if last.is_some_and(|last| now < last + NOTICE_EVERY) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Resolves `name` under the `auto` policy. `refresh` says a connection to
/// the previous answer failed: benches and remembered verdicts are ignored,
/// and the platform resolver's addresses are added to the answer.
pub(crate) async fn resolve<B: Backend>(
    backend: &B,
    memory: &Memory,
    name: &QueryName,
    refresh: bool,
    deadline: Instant,
) -> Result<Accepted, Failure> {
    Cascade::new(backend, memory, name, refresh, deadline)
        .run()
        .await
}

/// A side job of one lookup.
enum Stage<T> {
    Idle,
    Running,
    Done(T),
}

type Attempt<'a> = BoxFuture<'a, (usize, Result<Resolution, ExchangeError>)>;

/// An answer over an authenticated channel whose content the border filter
/// could still have written, into the resolver's own cache.
struct Unconfirmed {
    resolver: usize,
    addresses: Vec<IpAddr>,
    ttl: Duration,
    since: Instant,
}

struct Cascade<'a, B> {
    backend: &'a B,
    memory: &'a Memory,
    name: &'a QueryName,
    refresh: bool,
    started: Instant,
    deadline: Instant,

    /// Resolvers still to launch, and benched ones an escalation recalls.
    queue: VecDeque<usize>,
    benched: Vec<usize>,
    escalated: bool,
    attempts: FuturesUnordered<Attempt<'a>>,
    in_flight: Vec<(usize, Instant)>,
    hedge_at: Instant,
    /// Resolvers whose attempt failed in a way that is theirs to answer for.
    blamed: Vec<usize>,

    system_job: Fuse<BoxFuture<'a, std::io::Result<Vec<IpAddr>>>>,
    survey_job: Fuse<BoxFuture<'a, Vec<Sighting>>>,
    evasion_job: Fuse<BoxFuture<'a, Vec<Sighting>>>,
    /// `None` once the platform resolver has nothing usable.
    system: Stage<Option<Vec<IpAddr>>>,
    verdict: Stage<Verdict>,
    /// Addresses the two-question query drew without contest.
    evasion: Stage<Vec<IpAddr>>,

    /// The answer to return, and when it was settled on.
    primary: Option<(Accepted, Instant)>,
    /// Mainland resolvers' answers that point outside the mainland.
    unconfirmed: Vec<Unconfirmed>,
    /// An authenticated resolver reported that the name has no address.
    missing: bool,
    /// A global one did: the public DNS has nothing for this name.
    publicly_absent: bool,
    failures: Vec<(String, ExchangeError)>,
}

impl<'a, B: Backend> Cascade<'a, B> {
    fn new(
        backend: &'a B,
        memory: &'a Memory,
        name: &'a QueryName,
        refresh: bool,
        deadline: Instant,
    ) -> Self {
        let started = Instant::now();
        let (queue, benched) = memory.launch_order(backend.resolvers().len(), started, refresh);
        Self {
            backend,
            memory,
            name,
            refresh,
            started,
            deadline,
            queue,
            benched,
            escalated: false,
            attempts: FuturesUnordered::new(),
            in_flight: Vec::new(),
            hedge_at: started,
            blamed: Vec::new(),
            system_job: Fuse::terminated(),
            survey_job: Fuse::terminated(),
            evasion_job: Fuse::terminated(),
            system: Stage::Idle,
            verdict: Stage::Idle,
            evasion: Stage::Idle,
            primary: None,
            unconfirmed: Vec::new(),
            missing: false,
            publicly_absent: false,
            failures: Vec::new(),
        }
    }

    async fn run(mut self) -> Result<Accepted, Failure> {
        loop {
            let now = Instant::now();
            self.advance(now);
            if let Some(outcome) = self.settle(now) {
                return self.conclude(outcome, now);
            }
            let wake = self.next_wake(now);
            tokio::select! {
                // An authenticated answer that is ready is seen before
                // anything it would make unnecessary.
                biased;
                Some((index, result)) = self.attempts.next() => self.on_attempt(index, result),
                result = &mut self.system_job => self.on_system(result),
                sightings = &mut self.survey_job => self.on_survey(sightings),
                sightings = &mut self.evasion_job => self.on_evasion(sightings),
                () = tokio::time::sleep_until(wake) => {}
            }
        }
    }

    /// Applies what the last event changed and starts whatever the lookup
    /// now calls for.
    fn advance(&mut self, now: Instant) {
        if matches!(self.verdict, Stage::Idle) && self.awaits_verdict() {
            self.start_survey(now);
        }
        if self.primary.is_none()
            && let Some(answer) = self.judged_answer(now)
        {
            self.primary = Some((answer, now));
        }
        if self.primary.is_none() {
            if matches!(self.verdict, Stage::Done(Verdict::Injected { .. }))
                && matches!(self.evasion, Stage::Idle)
            {
                self.escalate();
            }
            self.launch_resolvers(now);
        }
        // An unconfirmed answer wants the platform resolver's as a second
        // opinion; otherwise that resolver waits for its turn.
        let system_wanted = self.refresh
            || (self.primary.is_none()
                && (self.system_may_stand_alone(now) || !self.unconfirmed.is_empty()));
        if matches!(self.system, Stage::Idle) && system_wanted {
            let (backend, name) = (self.backend, self.name);
            self.system_job = async move { backend.system(name.as_str()).await }
                .boxed()
                .fuse();
            self.system = Stage::Running;
        }
    }

    fn launch_resolvers(&mut self, now: Instant) {
        while let Some(&index) = self.queue.front() {
            let room = self.escalated
                || self.in_flight.is_empty()
                || (self.in_flight.len() < MAX_IN_FLIGHT && now >= self.hedge_at);
            if !room || now >= self.deadline {
                return;
            }
            self.queue.pop_front();
            let (backend, name, deadline) = (self.backend, self.name, self.deadline);
            self.attempts.push(
                async move {
                    let asked =
                        tokio::time::timeout_at(deadline, backend.ask(index, name, deadline));
                    (index, asked.await.unwrap_or(Err(ExchangeError::TimedOut)))
                }
                .boxed(),
            );
            self.in_flight.push((index, now));
            self.hedge_at = now + HEDGE_DELAY;
        }
    }

    /// Whether an answer on the table needs the path judged before use.
    fn awaits_verdict(&self) -> bool {
        let system_needs_it = match (&self.system, &self.primary) {
            (Stage::Done(Some(addresses)), None) => !unforgeable(addresses),
            (Stage::Done(Some(addresses)), Some((primary, _))) => addresses
                .iter()
                .any(|address| !primary.addresses.contains(address) && !beyond_forgery(*address)),
            (Stage::Idle | Stage::Running | Stage::Done(None), _) => false,
        };
        system_needs_it || (self.primary.is_none() && !self.unconfirmed.is_empty())
    }

    fn start_survey(&mut self, now: Instant) {
        if !self.refresh
            && let Some(verdict) = self.memory.verdict(self.name.as_str(), now)
        {
            self.verdict = Stage::Done(verdict);
        } else if !self.backend.can_witness() {
            self.verdict = Stage::Done(Verdict::Unobserved);
        } else {
            let (backend, name) = (self.backend, self.name);
            self.survey_job = backend.witness(name, QueryShape::Standard).boxed().fuse();
            self.verdict = Stage::Running;
        }
    }

    /// With forgeries on the path, every authenticated resolver is worth
    /// asking, benched or not, and the two-question query is worth sending.
    fn escalate(&mut self) {
        self.queue.extend(self.benched.drain(..));
        self.escalated = true;
        if self.backend.can_witness() {
            let (backend, name) = (self.backend, self.name);
            self.evasion_job = backend
                .witness(name, QueryShape::DualQuestion)
                .boxed()
                .fuse();
            self.evasion = Stage::Running;
        } else {
            self.evasion = Stage::Done(Vec::new());
        }
    }

    fn exhausted(&self) -> bool {
        self.queue.is_empty() && self.in_flight.is_empty()
    }

    fn system_may_stand_alone(&self, now: Instant) -> bool {
        self.missing || self.exhausted() || now >= self.started + SYSTEM_AFTER
    }

    fn on_attempt(&mut self, index: usize, result: Result<Resolution, ExchangeError>) {
        let now = Instant::now();
        self.in_flight.retain(|(launched, _)| *launched != index);
        let backend = self.backend;
        let resolver = &backend.resolvers()[index];
        match result {
            Ok(Resolution::Addresses { addresses, ttl }) => {
                self.memory.reward(index);
                let source = match resolver.scope {
                    Scope::Global => Source::Global,
                    Scope::Mainland if unforgeable(&addresses) => Source::Mainland,
                    Scope::Mainland => {
                        if !self.publicly_absent {
                            self.unconfirmed.push(Unconfirmed {
                                resolver: index,
                                addresses,
                                ttl,
                                since: now,
                            });
                        }
                        return;
                    }
                };
                if self.primary.is_none() {
                    let accepted = Accepted {
                        addresses,
                        ttl: Some(ttl),
                        source,
                    };
                    self.primary = Some((accepted, now));
                }
            }
            Ok(Resolution::Missing { .. }) => {
                self.memory.reward(index);
                self.missing = true;
                if resolver.scope == Scope::Global {
                    // The public DNS has no such name, so addresses a mainland
                    // resolver gives for it are not the public record.
                    self.publicly_absent = true;
                    self.unconfirmed.clear();
                }
            }
            Err(error) => {
                if error.blames_resolver() {
                    self.blamed.push(index);
                }
                self.failures.push((resolver.label.clone(), error));
                self.hedge_at = now;
            }
        }
    }

    fn on_system(&mut self, result: std::io::Result<Vec<IpAddr>>) {
        let failure = match result {
            Ok(mut addresses) => {
                addresses.retain(|address| is_routable_endpoint(*address));
                if !addresses.is_empty() {
                    self.system = Stage::Done(Some(addresses));
                    return;
                }
                ExchangeError::Unroutable
            }
            Err(source) => ExchangeError::System { source },
        };
        self.failures.push(("system".to_owned(), failure));
        self.system = Stage::Done(None);
    }

    fn on_survey(&mut self, sightings: Vec<Sighting>) {
        let now = Instant::now();
        let verdict = judge(sightings);
        self.memory.remember(self.name.as_str(), &verdict, now);
        if matches!(verdict, Verdict::Injected { .. }) && self.memory.due(Notice::Injected, now) {
            tracing::warn!(
                host = self.name.as_str(),
                "plaintext DNS responses for the endpoint disagree: forged answers are being \
                 injected on this network path, so only authenticated or corroborated answers are \
                 used"
            );
        }
        self.verdict = Stage::Done(verdict);
    }

    fn on_evasion(&mut self, sightings: Vec<Sighting>) {
        self.evasion = Stage::Done(uncontested(sightings));
    }

    /// The lookup's result, once nothing still running could improve it.
    fn settle(&mut self, now: Instant) -> Option<Result<Accepted, Failure>> {
        if let Some((primary, since)) = &self.primary {
            if !self.refresh || now >= (*since + PLATFORM_WAIT).min(self.deadline) {
                return Some(Ok(primary.clone()));
            }
            return match &self.system {
                Stage::Done(Some(addresses)) => self
                    .admitted_extras(primary, addresses)
                    .map(|extras| Ok(supplemented(primary, extras))),
                Stage::Done(None) => Some(Ok(primary.clone())),
                Stage::Idle | Stage::Running => None,
            };
        }
        if let Stage::Done(Some(addresses)) = &self.system
            && self.system_may_stand_alone(now)
            && (unforgeable(addresses)
                || matches!(
                    self.verdict,
                    Stage::Done(Verdict::Clean { .. } | Verdict::Unobserved)
                ))
        {
            return Some(Ok(Accepted {
                addresses: addresses.clone(),
                ttl: None,
                source: Source::System,
            }));
        }
        let system_has_nothing = matches!(self.system, Stage::Done(None));
        let idle = self.exhausted()
            && matches!(self.system, Stage::Done(_))
            && !matches!(self.verdict, Stage::Running)
            && !matches!(self.evasion, Stage::Running);
        if now >= self.deadline || idle || (self.publicly_absent && system_has_nothing) {
            return Some(Err(self.failure()));
        }
        None
    }

    /// The answer the verdict releases from those that had to wait for it.
    fn judged_answer(&self, now: Instant) -> Option<Accepted> {
        let platform = match &self.system {
            Stage::Done(Some(addresses)) => addresses.as_slice(),
            Stage::Idle | Stage::Running | Stage::Done(None) => &[],
        };
        let seen = match &self.verdict {
            Stage::Idle | Stage::Running => return None,
            Stage::Done(Verdict::Injected { held }) => return self.corroborated(held, platform),
            Stage::Done(Verdict::Clean { seen }) => seen.as_slice(),
            Stage::Done(Verdict::Unobserved) => &[],
        };
        // The path is not seen forging answers, but a mainland resolver's
        // cache is filled across the border filter wherever the client is.
        // Its answer is used when a source outside that cache gives one of
        // the same addresses, or when no such source has an address to give.
        let seconded = self
            .unconfirmed
            .iter()
            .find(|answer| shares(&answer.addresses, seen) || shares(&answer.addresses, platform));
        let alone = |answer: &&Unconfirmed| {
            let platform_is_silent = match &self.system {
                Stage::Done(None) => true,
                // A stand-in from a tunnel's own DNS says nothing of the name.
                Stage::Done(Some(addresses)) => addresses.iter().all(|a| is_placeholder(*a)),
                Stage::Idle | Stage::Running => {
                    now >= (answer.since + PLATFORM_WAIT).min(self.deadline)
                }
            };
            seen.is_empty() && platform_is_silent
        };
        seconded
            .or_else(|| self.unconfirmed.first().filter(alone))
            .map(|answer| Accepted {
                addresses: answer.addresses.clone(),
                ttl: Some(answer.ttl),
                source: Source::Mainland,
            })
    }

    /// With forged answers on the path, the addresses of the first candidate
    /// that the trailing response of a contested exchange carries too.
    fn corroborated(&self, held: &[IpAddr], platform: &[IpAddr]) -> Option<Accepted> {
        let evasion = match &self.evasion {
            Stage::Done(addresses) => addresses.as_slice(),
            Stage::Idle | Stage::Running => &[],
        };
        std::iter::once(evasion)
            .chain(
                self.unconfirmed
                    .iter()
                    .map(|answer| answer.addresses.as_slice()),
            )
            .chain(std::iter::once(platform))
            .map(|candidate| common(candidate, held))
            .find(|agreed| !agreed.is_empty())
            .map(|addresses| Accepted {
                addresses,
                ttl: None,
                source: Source::Corroborated,
            })
    }

    /// The platform resolver's addresses that may join `primary`, once that
    /// can be decided.
    fn admitted_extras(&self, primary: &Accepted, system: &[IpAddr]) -> Option<Vec<IpAddr>> {
        let extras = system
            .iter()
            .copied()
            .filter(|address| !primary.addresses.contains(address));
        let held: &[IpAddr] = match &self.verdict {
            Stage::Done(Verdict::Clean { .. } | Verdict::Unobserved) => {
                return Some(extras.collect());
            }
            Stage::Done(Verdict::Injected { held }) => held,
            Stage::Idle | Stage::Running if self.awaits_verdict() => return None,
            Stage::Idle | Stage::Running => &[],
        };
        Some(
            extras
                .filter(|address| beyond_forgery(*address) || held.contains(address))
                .collect(),
        )
    }

    fn failure(&mut self) -> Failure {
        let resolvers = self.backend.resolvers();
        let mut failures = std::mem::take(&mut self.failures);
        failures.extend(
            self.in_flight
                .iter()
                .map(|(index, _)| (resolvers[*index].label.clone(), ExchangeError::TimedOut)),
        );
        failures.extend(self.unconfirmed.iter().map(|answer| {
            let label = resolvers[answer.resolver].label.clone();
            (label, ExchangeError::Unconfirmed)
        }));
        let failures = Failures(failures);
        if matches!(self.verdict, Stage::Done(Verdict::Injected { .. })) && !self.publicly_absent {
            Failure::Forged { failures }
        } else if self.missing {
            Failure::Missing
        } else {
            Failure::Unanswered { failures }
        }
    }

    fn next_wake(&self, now: Instant) -> Instant {
        let mut wake = self.deadline;
        if self.primary.is_none() && !self.queue.is_empty() && self.in_flight.len() < MAX_IN_FLIGHT
        {
            wake = wake.min(self.hedge_at);
        }
        let system_at = self.started + SYSTEM_AFTER;
        if system_at > now {
            wake = wake.min(system_at);
        }
        match (&self.primary, self.unconfirmed.first()) {
            (Some((_, since)), _) => wake = wake.min(*since + PLATFORM_WAIT),
            // Only while it lies ahead: once it has passed, whatever the
            // answer still waits for arrives as an event.
            (None, Some(answer)) if answer.since + PLATFORM_WAIT > now => {
                wake = wake.min(answer.since + PLATFORM_WAIT);
            }
            (None, Some(_) | None) => {}
        }
        wake
    }

    /// Records what the lookup showed about the resolvers, and reports it.
    fn conclude(
        &self,
        outcome: Result<Accepted, Failure>,
        now: Instant,
    ) -> Result<Accepted, Failure> {
        // A resolver is benched for failing, or for staying silent past its
        // hedge, only in a lookup that something else answered. When nothing
        // answers, the network is down, and that says nothing about them.
        if outcome.is_ok() || self.missing {
            let stalled = self
                .in_flight
                .iter()
                .filter(|(_, launched)| now.duration_since(*launched) >= HEDGE_DELAY)
                .map(|(index, _)| *index);
            for index in self.blamed.iter().copied().chain(stalled) {
                self.memory.penalize(index, now);
            }
        }
        let host = self.name.as_str();
        match &outcome {
            Ok(accepted) => match accepted.source {
                Source::Global | Source::Mainland => tracing::debug!(
                    host,
                    source = ?accepted.source,
                    addresses = ?accepted.addresses,
                    "endpoint resolved by an authenticated resolver"
                ),
                Source::Corroborated if self.memory.due(Notice::Corroborated, now) => {
                    tracing::warn!(
                        host,
                        addresses = ?accepted.addresses,
                        "forged DNS answers for the endpoint are on this network path; using \
                         the addresses two independent observations agree on"
                    );
                }
                Source::System if !self.missing && self.memory.due(Notice::SystemFallback, now) => {
                    tracing::warn!(
                        host,
                        "no authenticated resolver gave a usable answer for the endpoint; using \
                         the platform resolver's, which this network could have forged"
                    );
                }
                Source::Corroborated | Source::System => tracing::debug!(
                    host,
                    source = ?accepted.source,
                    addresses = ?accepted.addresses,
                    "endpoint resolved without an authenticated answer"
                ),
            },
            Err(failure) => tracing::debug!(host, %failure, "endpoint lookup failed"),
        }
        outcome
    }
}

/// Whether the border filter's injectors never answer with `address`. Their
/// forgeries are public addresses outside the mainland, so one inside it, or
/// one that only a private network routes, was not theirs.
fn beyond_forgery(address: IpAddr) -> bool {
    let site_local = match address.to_canonical() {
        // RFC 1918 and the RFC 6598 shared space.
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            address.is_private() || (first == 100 && (64..128).contains(&second))
        }
        // RFC 4193 unique local addresses.
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    };
    site_local || is_placeholder(address) || is_china_ip(address)
}

/// Whether `address` lies in the RFC 2544 benchmarking range, 198.18.0.0/15,
/// which no network routes and fake-IP DNS hands out. A TUN on this machine
/// answers the platform resolver with one for whatever name it is asked, and
/// turns a connection to it back into a lookup of its own.
fn is_placeholder(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            first == 198 && (18..20).contains(&second)
        }
        IpAddr::V6(_) => false,
    }
}

fn unforgeable(addresses: &[IpAddr]) -> bool {
    addresses.iter().all(|address| beyond_forgery(*address))
}

/// The addresses of `candidate` that `held` carries too.
fn common(candidate: &[IpAddr], held: &[IpAddr]) -> Vec<IpAddr> {
    candidate
        .iter()
        .copied()
        .filter(|address| held.contains(address))
        .collect()
}

fn shares(answer: &[IpAddr], other: &[IpAddr]) -> bool {
    answer.iter().any(|address| other.contains(address))
}

fn supplemented(primary: &Accepted, extras: Vec<IpAddr>) -> Accepted {
    if extras.is_empty() {
        return primary.clone();
    }
    let mut addresses = primary.addresses.clone();
    addresses.extend(extras);
    Accepted {
        addresses,
        // The platform resolver reports no TTL for its part.
        ttl: None,
        source: primary.source,
    }
}

fn add_routable(into: &mut Vec<IpAddr>, addresses: Vec<IpAddr>) {
    for address in addresses {
        if is_routable_endpoint(address) && !into.contains(&address) {
            into.push(address);
        }
    }
}

/// Reads the standard query's sightings. One contested exchange is enough:
/// an honest path never answers one query two ways.
fn judge(sightings: Vec<Sighting>) -> Verdict {
    let mut held = Vec::new();
    let mut seen = Vec::new();
    let mut contested = false;
    let mut answered = false;
    for sighting in sightings {
        match sighting {
            Sighting::Silent => {}
            Sighting::Consistent(mut answer) => {
                answered = true;
                // A stand-in is what a tunnel on this machine answered in the
                // witness's place; it says nothing of the name.
                answer.retain(|address| !is_placeholder(*address));
                add_routable(&mut seen, answer);
            }
            Sighting::Contested { last } => {
                contested = true;
                add_routable(&mut held, last);
            }
        }
    }
    if contested {
        Verdict::Injected { held }
    } else if answered {
        Verdict::Clean { seen }
    } else {
        Verdict::Unobserved
    }
}

/// The addresses the two-question query drew, unless any exchange was
/// contested: then the injectors match this shape as well, and nothing it
/// returned is better than a standard query's first response.
fn uncontested(sightings: Vec<Sighting>) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for sighting in sightings {
        match sighting {
            Sighting::Silent => {}
            Sighting::Consistent(answer) => add_routable(&mut addresses, answer),
            Sighting::Contested { .. } => return Vec::new(),
        }
    }
    addresses
}

/// The platform resolver, as the caller provides it.
pub(crate) type SystemResolver = fn(String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>>;

/// The real network: DNS-over-HTTPS resolvers and plaintext witnesses.
pub(crate) struct Network {
    resolvers: Vec<Resolver>,
    described: Vec<Authenticated>,
    witnesses: Vec<SocketAddr>,
    watch: udp::Watch,
    https_client: fn() -> Result<reqwest::Client, ExchangeError>,
    system: SystemResolver,
    captured: fn() -> bool,
}

impl Network {
    /// The built-in resolvers, global and mainland alternating so that the
    /// first hedge already crosses to the other kind.
    pub(crate) fn builtin(system: SystemResolver) -> Self {
        let preset = |urls: [&str; 4], scope| {
            urls.map(|url| {
                let resolver = parse_https(url).expect("the built-in resolver URLs are valid");
                (resolver, scope)
            })
        };
        let global = preset(ENCRYPTED_PRESET, Scope::Global);
        let mainland = preset(MAINLAND_PRESET, Scope::Mainland);
        Self::new(
            global
                .into_iter()
                .zip(mainland)
                .flat_map(|(global, mainland)| [global, mainland])
                .collect(),
            WITNESSES.to_vec(),
            udp::Watch::DEFAULT,
            super::doh::shared_client,
            system,
            super::plaintext_is_captured,
        )
    }

    pub(super) fn new(
        resolvers: Vec<(Resolver, Scope)>,
        witnesses: Vec<SocketAddr>,
        watch: udp::Watch,
        https_client: fn() -> Result<reqwest::Client, ExchangeError>,
        system: SystemResolver,
        captured: fn() -> bool,
    ) -> Self {
        let described = resolvers
            .iter()
            .map(|(resolver, scope)| Authenticated {
                label: resolver.to_string(),
                scope: *scope,
            })
            .collect();
        Self {
            resolvers: resolvers
                .into_iter()
                .map(|(resolver, _)| resolver)
                .collect(),
            described,
            witnesses,
            watch,
            https_client,
            system,
            captured,
        }
    }
}

impl Backend for Network {
    fn resolvers(&self) -> &[Authenticated] {
        &self.described
    }

    async fn ask(
        &self,
        index: usize,
        name: &QueryName,
        deadline: Instant,
    ) -> Result<Resolution, ExchangeError> {
        super::lookup(
            &self.resolvers[index],
            name,
            udp::Timing::DEFAULT,
            &self.https_client,
            deadline,
        )
        .await
    }

    fn system(&self, host: &str) -> impl Future<Output = std::io::Result<Vec<IpAddr>>> + Send {
        (self.system)(host.to_owned())
    }

    fn can_witness(&self) -> bool {
        !(self.captured)()
    }

    async fn witness(&self, name: &QueryName, shape: QueryShape) -> Vec<Sighting> {
        let exchanges = self.witnesses.iter().map(|server| async move {
            let query = Query::new(name, Family::V4, rand::random(), Layout::Plain(shape));
            udp::sight(*server, &query, self.watch).await
        });
        futures::future::join_all(exchanges).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::{Message, ResponseCode};

    use super::*;
    use crate::dns::wire::tests::{addresses_reply_to, name};
    use crate::dns::{doh, udp};

    /// The node, which is outside the mainland like most are.
    const NODE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const NODE_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
    /// Another address of the same node, as a geographic DNS would give.
    const ELSEWHERE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    const FORGED: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66));
    const FORGED_AGAIN: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 67));
    /// A node inside the mainland.
    const DOMESTIC: IpAddr = IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29));
    const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));
    /// What a fake-IP DNS hands out in place of an address.
    const STAND_IN: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));
    /// What DNS64 makes of [`NODE`].
    const SYNTHESIZED: IpAddr = IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xcb00, 0x7107));
    const TTL: Duration = Duration::from_secs(120);
    const BUDGET: Duration = Duration::from_millis(4750);

    fn ms(milliseconds: u64) -> Duration {
        Duration::from_millis(milliseconds)
    }

    /// What a scripted resolver does with one question. Delays are in
    /// milliseconds.
    #[derive(Clone, Debug)]
    pub(crate) enum Reply {
        Addresses(u64, Vec<IpAddr>),
        Missing(u64),
        /// A failure that is the resolver's own.
        Broken(u64),
        /// A failure that is about the name.
        Refused(u64),
        Silent,
    }

    /// A network that answers from a script and records what it was asked.
    pub(crate) struct Script {
        resolvers: Vec<Authenticated>,
        /// Per resolver, the reply to each successive question; the last one
        /// repeats.
        replies: Vec<Vec<Reply>>,
        /// The platform resolver's delay and addresses; none is a failure.
        /// `None` never answers.
        system: Option<(u64, Vec<IpAddr>)>,
        survey: Vec<Sighting>,
        evasion: Vec<Sighting>,
        witness_after: u64,
        captured: bool,
        epoch: Instant,
        /// How many questions each resolver has had.
        turns: Mutex<Vec<usize>>,
        asked: Mutex<Vec<(usize, u64)>>,
        system_asked: Mutex<Vec<u64>>,
        surveys: AtomicUsize,
        evasions: AtomicUsize,
    }

    impl Script {
        /// Authenticated resolvers in launch order. The platform resolver
        /// fails, and no witness answers, until the script says otherwise.
        pub(crate) fn new(resolvers: impl IntoIterator<Item = (Scope, Vec<Reply>)>) -> Self {
            let (scopes, replies): (Vec<_>, Vec<_>) = resolvers.into_iter().unzip();
            Self {
                resolvers: scopes
                    .into_iter()
                    .enumerate()
                    .map(|(index, scope)| Authenticated {
                        label: format!("resolver-{index}"),
                        scope,
                    })
                    .collect(),
                turns: Mutex::new(vec![0; replies.len()]),
                replies,
                system: Some((10, Vec::new())),
                survey: vec![Sighting::Silent, Sighting::Silent],
                evasion: vec![Sighting::Silent, Sighting::Silent],
                witness_after: 300,
                captured: false,
                epoch: Instant::now(),
                asked: Mutex::new(Vec::new()),
                system_asked: Mutex::new(Vec::new()),
                surveys: AtomicUsize::new(0),
                evasions: AtomicUsize::new(0),
            }
        }

        pub(crate) fn system(mut self, after: u64, addresses: &[IpAddr]) -> Self {
            self.system = Some((after, addresses.to_vec()));
            self
        }

        fn system_never_answers(mut self) -> Self {
            self.system = None;
            self
        }

        fn survey(mut self, sightings: Vec<Sighting>) -> Self {
            self.survey = sightings;
            self
        }

        fn evasion(mut self, sightings: Vec<Sighting>) -> Self {
            self.evasion = sightings;
            self
        }

        fn captured(mut self) -> Self {
            self.captured = true;
            self
        }

        fn now(&self) -> u64 {
            self.epoch.elapsed().as_millis() as u64
        }

        /// Which resolvers were asked, and when, since the last call.
        pub(crate) fn asked(&self) -> Vec<(usize, u64)> {
            std::mem::take(&mut *lock(&self.asked))
        }

        /// When the platform resolver was asked, since the last call.
        pub(crate) fn system_asked(&self) -> Vec<u64> {
            std::mem::take(&mut *lock(&self.system_asked))
        }

        fn surveys(&self) -> usize {
            self.surveys.load(Ordering::SeqCst)
        }

        fn evasions(&self) -> usize {
            self.evasions.load(Ordering::SeqCst)
        }
    }

    impl Backend for Script {
        fn resolvers(&self) -> &[Authenticated] {
            &self.resolvers
        }

        async fn ask(
            &self,
            index: usize,
            _name: &QueryName,
            _deadline: Instant,
        ) -> Result<Resolution, ExchangeError> {
            lock(&self.asked).push((index, self.now()));
            let reply = {
                let turn = &mut lock(&self.turns)[index];
                let replies = &self.replies[index];
                let reply = replies[(*turn).min(replies.len() - 1)].clone();
                *turn += 1;
                reply
            };
            match reply {
                Reply::Addresses(after, addresses) => {
                    tokio::time::sleep(ms(after)).await;
                    Ok(Resolution::Addresses {
                        addresses,
                        ttl: TTL,
                    })
                }
                Reply::Missing(after) => {
                    tokio::time::sleep(ms(after)).await;
                    Ok(Resolution::Missing { ttl: None })
                }
                Reply::Broken(after) => {
                    tokio::time::sleep(ms(after)).await;
                    Err(ExchangeError::Malformed)
                }
                Reply::Refused(after) => {
                    tokio::time::sleep(ms(after)).await;
                    Err(ExchangeError::Rcode {
                        code: ResponseCode::ServFail,
                    })
                }
                Reply::Silent => std::future::pending().await,
            }
        }

        async fn system(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            lock(&self.system_asked).push(self.now());
            let Some((after, addresses)) = self.system.clone() else {
                return std::future::pending().await;
            };
            tokio::time::sleep(ms(after)).await;
            if addresses.is_empty() {
                Err(std::io::ErrorKind::NotFound.into())
            } else {
                Ok(addresses)
            }
        }

        fn can_witness(&self) -> bool {
            !self.captured
        }

        async fn witness(&self, _name: &QueryName, shape: QueryShape) -> Vec<Sighting> {
            let (count, sightings) = match shape {
                QueryShape::Standard => (&self.surveys, &self.survey),
                QueryShape::DualQuestion => (&self.evasions, &self.evasion),
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(ms(self.witness_after)).await;
            sightings.clone()
        }
    }

    /// A global and a mainland resolver, in the order the built-in ones
    /// alternate.
    fn pair(global: Reply, mainland: Reply) -> Script {
        Script::new([
            (Scope::Global, vec![global]),
            (Scope::Mainland, vec![mainland]),
        ])
    }

    fn contested(last: &[IpAddr]) -> Sighting {
        Sighting::Contested {
            last: last.to_vec(),
        }
    }

    fn consistent(answer: &[IpAddr]) -> Sighting {
        Sighting::Consistent(answer.to_vec())
    }

    async fn lookup_as(
        script: &Script,
        memory: &Memory,
        refresh: bool,
    ) -> (Result<Accepted, Failure>, Duration) {
        let started = Instant::now();
        let name = name("node.example.com");
        let outcome = resolve(script, memory, &name, refresh, started + BUDGET).await;
        (outcome, started.elapsed())
    }

    async fn lookup(script: &Script, memory: &Memory) -> (Result<Accepted, Failure>, Duration) {
        lookup_as(script, memory, false).await
    }

    fn accepted(addresses: &[IpAddr], ttl: Option<Duration>, source: Source) -> Accepted {
        Accepted {
            addresses: addresses.to_vec(),
            ttl,
            source,
        }
    }

    #[test]
    fn the_fixture_addresses_lie_where_the_tests_assume() {
        for outside in [NODE, NODE_V6, ELSEWHERE, FORGED, FORGED_AGAIN, SYNTHESIZED] {
            assert!(!beyond_forgery(outside), "{outside}");
        }
        for inside in [DOMESTIC, PRIVATE, STAND_IN] {
            assert!(beyond_forgery(inside), "{inside}");
        }
        assert!(is_placeholder(STAND_IN));
    }

    #[test]
    fn only_the_mainland_and_unrouted_networks_are_beyond_forgery() {
        for address in [
            "223.5.5.5",
            "2400:3200::1",
            "::ffff:223.5.5.5",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "198.19.255.254",
            "fd00::1",
        ] {
            assert!(beyond_forgery(address.parse().unwrap()), "{address}");
        }
        for address in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "2606:4700::1",
            "fe80::1",
        ] {
            assert!(!beyond_forgery(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn only_the_benchmarking_range_holds_stand_in_addresses() {
        for address in ["198.18.0.0", "198.19.255.255", "::ffff:198.18.0.1"] {
            assert!(is_placeholder(address.parse().unwrap()), "{address}");
        }
        for address in ["198.17.255.255", "198.20.0.0", "10.0.0.1", "2001:db8::1"] {
            assert!(!is_placeholder(address.parse().unwrap()), "{address}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_global_answer_is_taken_at_once_and_nothing_unauthenticated_is_asked() {
        let script = pair(
            Reply::Addresses(80, vec![NODE, NODE_V6]),
            Reply::Addresses(10, vec![DOMESTIC]),
        );
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE, NODE_V6], Some(TTL), Source::Global)
        );
        assert_eq!(took, ms(80));
        assert_eq!(script.asked(), [(0, 0)]);
        assert!(script.system_asked().is_empty());
        assert_eq!(script.surveys(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_resolver_is_hedged_and_then_benched_for_longer_each_time() {
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![DOMESTIC]));
        let memory = Memory::new();
        let domestic = accepted(&[DOMESTIC], Some(TTL), Source::Mainland);

        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap(), domestic);
        assert_eq!(took, HEDGE_DELAY + ms(50));
        assert_eq!(script.asked(), [(0, 0), (1, 200)]);
        // An address inside the mainland is not the border filter's, so it
        // needs neither a verdict nor a second opinion.
        assert_eq!(script.surveys(), 0);
        assert!(script.system_asked().is_empty());

        // The resolver that stalled is left out, so the next lookup is fast.
        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap(), domestic);
        assert_eq!(took, ms(50));
        assert_eq!(script.asked(), [(1, 250)]);

        // Its bench ends, it stalls again, and the next bench is twice as
        // long.
        tokio::time::sleep(BENCH_BASE).await;
        let (_, took) = lookup(&script, &memory).await;
        assert_eq!(took, HEDGE_DELAY + ms(50));
        assert_eq!(script.asked().first(), Some(&(0, 30_300)));
        tokio::time::sleep(BENCH_BASE).await;
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked().first().map(|(index, _)| *index), Some(1));
        tokio::time::sleep(BENCH_BASE).await;
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked().first().map(|(index, _)| *index), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_resolver_is_followed_at_once_and_benched() {
        let script = pair(Reply::Broken(10), Reply::Addresses(30, vec![DOMESTIC]));
        let memory = Memory::new();
        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap().source, Source::Mainland);
        assert_eq!(took, ms(40));
        assert_eq!(script.asked(), [(0, 0), (1, 10)]);

        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked(), [(1, 40)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_only_rejects_the_name_keeps_its_place() {
        let script = pair(Reply::Refused(10), Reply::Addresses(30, vec![DOMESTIC]));
        let memory = Memory::new();
        lookup(&script, &memory).await.0.unwrap();
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked(), [(0, 0), (1, 10), (0, 40), (1, 50)]);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_benched_by_a_lookup_that_nothing_answered() {
        // As when the network is down: every resolver fails, and so does the
        // platform's.
        let script = pair(Reply::Broken(10), Reply::Broken(10));
        let memory = Memory::new();
        let (outcome, took) = lookup(&script, &memory).await;
        let failure = outcome.unwrap_err();
        assert!(matches!(failure, Failure::Unanswered { .. }), "{failure}");
        assert_eq!(failure.kind(), std::io::ErrorKind::Other);
        let report = failure.to_string();
        for part in [
            "resolver-0: malformed DNS response",
            "resolver-1: malformed DNS response",
            "system: the platform resolver failed",
        ] {
            assert!(report.contains(part), "{report}");
        }
        // The platform resolver is asked as soon as the others are spent.
        assert_eq!(took, ms(30));
        assert_eq!(script.system_asked(), [20]);
        assert_eq!(script.asked(), [(0, 0), (1, 10)]);

        lookup(&script, &memory).await.0.unwrap_err();
        assert_eq!(script.asked(), [(0, 30), (1, 40)]);
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_four_resolvers_run_and_the_deadline_ends_the_lookup() {
        let script = Script::new((0..6).map(|index| {
            let scope = if index % 2 == 0 {
                Scope::Global
            } else {
                Scope::Mainland
            };
            (scope, vec![Reply::Silent])
        }))
        .system_never_answers();
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        let failure = outcome.unwrap_err();
        assert!(matches!(failure, Failure::Unanswered { .. }), "{failure}");
        assert_eq!(failure.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(took, BUDGET);
        assert_eq!(script.asked(), [(0, 0), (1, 200), (2, 400), (3, 600)]);
        assert_eq!(script.system_asked(), [600]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mainland_answer_outside_the_mainland_waits_for_a_witness_to_second_it() {
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![NODE, NODE_V6]))
            .survey(vec![consistent(&[NODE]), Sighting::Silent])
            .system_never_answers();
        let memory = Memory::new();
        let node = accepted(&[NODE, NODE_V6], Some(TTL), Source::Mainland);

        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap(), node);
        // The answer arrives at 250 ms, and the witnesses report 300 ms on.
        assert_eq!(took, ms(550));
        assert_eq!(script.surveys(), 1);
        assert_eq!(script.evasions(), 0);
        // The platform resolver is asked alongside, for a second opinion.
        assert_eq!(script.system_asked(), [250]);

        // What the witnesses saw is remembered, so the next lookup neither
        // waits for them nor repeats the plaintext query.
        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap(), node);
        assert_eq!(took, ms(50));
        assert_eq!(script.surveys(), 1);

        tokio::time::sleep(CLEAN_FOR).await;
        let (outcome, _) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap(), node);
        assert_eq!(script.surveys(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_platform_resolver_seconds_a_mainland_answer_when_no_witness_answers() {
        let script =
            pair(Reply::Silent, Reply::Addresses(50, vec![NODE])).system(20, &[ELSEWHERE, NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Mainland)
        );
        // Not before the witnesses had their chance to show forged answers.
        assert_eq!(took, ms(550));
    }

    #[tokio::test(start_paused = true)]
    async fn a_mainland_answer_is_used_alone_only_when_no_other_source_has_an_address() {
        // The platform resolver fails, and the witnesses are silent or know
        // no address for the name.
        for survey in [Sighting::Silent, consistent(&[])] {
            let alone = pair(Reply::Broken(10), Reply::Addresses(50, vec![NODE]))
                .survey(vec![survey, Sighting::Silent]);
            let (outcome, took) = lookup(&alone, &Memory::new()).await;
            assert_eq!(
                outcome.unwrap(),
                accepted(&[NODE], Some(TTL), Source::Mainland)
            );
            assert_eq!(took, ms(360));
        }

        // A witness with other addresses makes it one opinion of two, and
        // the one from inside the filter.
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![NODE]))
            .survey(vec![consistent(&[ELSEWHERE]), Sighting::Silent]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        let failure = outcome.unwrap_err();
        assert!(matches!(failure, Failure::Unanswered { .. }), "{failure}");
        assert!(
            failure
                .to_string()
                .contains("resolver-1: answered with addresses outside the mainland"),
            "{failure}"
        );
        assert_eq!(took, ms(360));
    }

    #[tokio::test(start_paused = true)]
    async fn a_platform_resolver_that_hangs_does_not_hold_back_a_mainland_answer() {
        // As behind a tunnel that is down: the platform resolver's query
        // enters the tunnel and nothing comes back. With the tunnel's own
        // DNS relay on the plaintext path, and without.
        for captured in [true, false] {
            let script =
                pair(Reply::Silent, Reply::Addresses(50, vec![NODE])).system_never_answers();
            let script = if captured { script.captured() } else { script };
            let (outcome, took) = lookup(&script, &Memory::new()).await;
            assert_eq!(
                outcome.unwrap(),
                accepted(&[NODE], Some(TTL), Source::Mainland)
            );
            // The answer arrives at 250 ms and waits for a second opinion.
            assert_eq!(took, ms(250) + PLATFORM_WAIT);
            assert_eq!(script.system_asked(), [250]);
            assert_eq!(script.surveys(), usize::from(!captured));
        }

        // Even then a witness that knows other addresses keeps it unused.
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![NODE]))
            .survey(vec![consistent(&[ELSEWHERE]), Sighting::Silent])
            .system_never_answers();
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert!(matches!(outcome, Err(Failure::Unanswered { .. })));
        assert_eq!(took, BUDGET);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mainland_answer_that_arrives_late_is_used_at_the_deadline() {
        let script = Script::new([
            (Scope::Global, vec![Reply::Silent]),
            (Scope::Mainland, vec![Reply::Addresses(4000, vec![NODE])]),
        ])
        .captured()
        .system_never_answers();
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Mainland)
        );
        assert_eq!(took, BUDGET);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stand_in_address_from_a_tunnel_does_not_outvote_a_mainland_answer() {
        // A TUN on this machine in fake-IP mode: the platform resolver gets
        // a stand-in for any name, and plaintext queries get the TUN's relay.
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![NODE]))
            .captured()
            .system(20, &[STAND_IN]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Mainland)
        );
        assert_eq!(took, ms(270));

        // With a real address beside it the platform resolver has an
        // opinion, and it is not the mainland resolver's.
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![FORGED]))
            .captured()
            .system(20, &[STAND_IN, NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[STAND_IN, NODE], None, Source::System)
        );
        assert_eq!(took, SYSTEM_AFTER);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stand_in_address_is_the_answer_when_no_authenticated_resolver_has_one() {
        // No worse than the platform resolver alone would be, and without a
        // verdict: nothing on the path forges an address no network routes.
        let script = pair(Reply::Broken(10), Reply::Broken(10)).system(20, &[STAND_IN]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[STAND_IN], None, Source::System)
        );
        assert_eq!(took, ms(40));
        assert_eq!(script.surveys(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mainland_answer_the_platform_resolver_contradicts_gives_way_to_it() {
        // A client outside the mainland whose network blocks the global
        // resolvers: the mainland resolver's cache holds the border filter's
        // forgery, which nothing on this client's own path shows.
        let script = pair(Reply::Silent, Reply::Addresses(50, vec![FORGED]))
            .survey(vec![consistent(&[NODE]), Sighting::Silent])
            .system(20, &[NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap(), accepted(&[NODE], None, Source::System));
        // The platform resolver's answer stands once the authenticated
        // resolvers have had their head start.
        assert_eq!(took, SYSTEM_AFTER);
    }

    #[tokio::test(start_paused = true)]
    async fn forged_answers_on_the_path_fail_the_lookup_rather_than_being_used() {
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![FORGED]))
            .survey(vec![contested(&[NODE]), Sighting::Silent])
            .system(20, &[FORGED_AGAIN]);
        let memory = Memory::new();
        let (outcome, took) = lookup(&script, &memory).await;
        let failure = outcome.unwrap_err();
        assert!(matches!(failure, Failure::Forged { .. }), "{failure}");
        assert_eq!(failure.kind(), std::io::ErrorKind::Other);
        assert!(
            failure.to_string().starts_with("forged DNS answers"),
            "{failure}"
        );
        // 60 ms for the answer, 300 ms for the witnesses, and 300 ms more for
        // the two-question query that the forgeries call for.
        assert_eq!(took, ms(660));
        assert_eq!((script.surveys(), script.evasions()), (1, 1));

        // The verdict is remembered, briefly: the next lookup goes straight
        // to the two-question query.
        let (outcome, took) = lookup(&script, &memory).await;
        assert!(matches!(outcome, Err(Failure::Forged { .. })));
        assert_eq!(took, ms(360));
        assert_eq!((script.surveys(), script.evasions()), (1, 2));

        tokio::time::sleep(INJECTED_FOR).await;
        lookup(&script, &memory).await.0.unwrap_err();
        assert_eq!(script.surveys(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_two_question_answer_is_used_when_the_trailing_response_agrees() {
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![FORGED]))
            .survey(vec![contested(&[NODE, ELSEWHERE]), Sighting::Silent])
            .evasion(vec![consistent(&[NODE, NODE_V6]), Sighting::Silent])
            .system(20, &[FORGED_AGAIN]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], None, Source::Corroborated)
        );
        assert_eq!(took, ms(660));
    }

    #[tokio::test(start_paused = true)]
    async fn a_two_question_answer_that_nothing_confirms_is_not_used() {
        // The injectors could answer this shape too, and alone.
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![FORGED]))
            .survey(vec![contested(&[NODE]), Sighting::Silent])
            .evasion(vec![consistent(&[FORGED_AGAIN]), Sighting::Silent]);
        let (outcome, _) = lookup(&script, &Memory::new()).await;
        assert!(matches!(outcome, Err(Failure::Forged { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn a_contested_two_question_exchange_discredits_that_query_shape() {
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![FORGED]))
            .survey(vec![contested(&[NODE]), Sighting::Silent])
            .evasion(vec![consistent(&[NODE]), contested(&[NODE])]);
        let (outcome, _) = lookup(&script, &Memory::new()).await;
        assert!(matches!(outcome, Err(Failure::Forged { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_the_trailing_response_confirms_needs_no_two_question_query() {
        // From a mainland resolver.
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![NODE, NODE_V6]))
            .survey(vec![contested(&[NODE]), contested(&[ELSEWHERE])]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        // Only the address both carry: the query was for IPv4 alone.
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], None, Source::Corroborated)
        );
        assert_eq!(took, ms(360));
        assert_eq!(script.evasions(), 0);

        // From the platform resolver.
        let script = pair(Reply::Broken(10), Reply::Broken(10))
            .survey(vec![contested(&[NODE]), Sighting::Silent])
            .system(20, &[FORGED, NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], None, Source::Corroborated)
        );
        assert_eq!(took, ms(340));
        assert_eq!(script.evasions(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_global_answer_stands_whatever_the_path_shows() {
        let script = pair(
            Reply::Addresses(900, vec![NODE]),
            Reply::Addresses(50, vec![FORGED]),
        )
        .survey(vec![contested(&[ELSEWHERE]), Sighting::Silent]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Global)
        );
        assert_eq!(took, ms(900));
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_inside_the_mainland_stands_whatever_the_path_shows() {
        let script = Script::new([
            (Scope::Mainland, vec![Reply::Addresses(50, vec![FORGED])]),
            (Scope::Mainland, vec![Reply::Addresses(400, vec![DOMESTIC])]),
        ])
        .survey(vec![contested(&[ELSEWHERE]), Sighting::Silent]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[DOMESTIC], Some(TTL), Source::Mainland)
        );
        // The second resolver is asked as soon as the first has answered.
        assert_eq!(took, ms(450));
        assert_eq!(script.asked(), [(0, 0), (1, 50)]);
    }

    #[tokio::test(start_paused = true)]
    async fn forged_answers_recall_benched_resolvers_and_lift_the_cap() {
        let script = Script::new([
            (
                Scope::Global,
                vec![Reply::Silent, Reply::Addresses(40, vec![NODE])],
            ),
            (
                Scope::Mainland,
                vec![
                    Reply::Addresses(50, vec![DOMESTIC]),
                    Reply::Addresses(50, vec![FORGED]),
                ],
            ),
            (Scope::Mainland, vec![Reply::Silent]),
            (Scope::Mainland, vec![Reply::Silent]),
            (Scope::Mainland, vec![Reply::Silent]),
            (Scope::Mainland, vec![Reply::Silent]),
            (Scope::Mainland, vec![Reply::Silent]),
        ])
        .survey(vec![contested(&[ELSEWHERE]), Sighting::Silent]);
        let memory = Memory::new();
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked(), [(0, 0), (1, 200)]);

        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap().source, Source::Global);
        // The forged answer at 50 ms, the verdict 300 ms later, and the
        // recalled resolver's answer 40 ms after that. Until the verdict
        // resolvers start one hedge apart; with it, all that are left start
        // together.
        assert_eq!(took, ms(390));
        assert_eq!(
            script.asked(),
            [
                (1, 250),
                (2, 300),
                (3, 500),
                (4, 600),
                (5, 600),
                (6, 600),
                (0, 600)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_platform_resolver_answers_when_no_authenticated_one_does() {
        // Outside the mainland the answer needs the path judged first.
        let script = pair(Reply::Broken(10), Reply::Broken(10))
            .survey(vec![consistent(&[ELSEWHERE]), Sighting::Silent])
            .system(30, &[NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap(), accepted(&[NODE], None, Source::System));
        assert_eq!(took, ms(350));
        assert_eq!(script.system_asked(), [20]);

        // A path nothing can be seen on judges nothing.
        let script = pair(Reply::Broken(10), Reply::Broken(10)).system(30, &[NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap(), accepted(&[NODE], None, Source::System));
        assert_eq!(took, ms(350));

        // Addresses the border filter never forges need no judgement.
        for address in [DOMESTIC, PRIVATE] {
            let script = pair(Reply::Broken(10), Reply::Broken(10)).system(30, &[address]);
            let (outcome, took) = lookup(&script, &Memory::new()).await;
            assert_eq!(outcome.unwrap(), accepted(&[address], None, Source::System));
            assert_eq!(took, ms(50));
            assert_eq!(script.surveys(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_platform_resolver_waits_for_the_authenticated_head_start() {
        let script = pair(Reply::Silent, Reply::Silent).system(50, &[DOMESTIC]);
        let memory = Memory::new();
        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[DOMESTIC], None, Source::System)
        );
        assert_eq!(took, SYSTEM_AFTER + ms(50));
        assert_eq!(script.system_asked(), [600]);

        // Both resolvers stalled while something else answered, so both sit
        // out and the platform resolver is asked without the wait.
        let (outcome, took) = lookup(&script, &memory).await;
        assert_eq!(outcome.unwrap().source, Source::System);
        assert_eq!(took, ms(50));
        assert_eq!(script.asked(), [(0, 0), (1, 200)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_captured_plaintext_path_is_not_asked_for_a_verdict() {
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![NODE]))
            .captured()
            .system(20, &[NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Mainland)
        );
        assert_eq!(took, ms(80));

        let script = pair(Reply::Broken(10), Reply::Broken(10))
            .captured()
            .system(30, &[NODE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap(), accepted(&[NODE], None, Source::System));
        assert_eq!(took, ms(50));
        assert_eq!((script.surveys(), script.evasions()), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_name_the_public_dns_lacks_fails_early_and_discredits_mainland_answers() {
        let script = pair(Reply::Missing(50), Reply::Addresses(10, vec![FORGED]));
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        let failure = outcome.unwrap_err();
        assert!(matches!(failure, Failure::Missing), "{failure}");
        assert_eq!(failure.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(took, ms(60));
        assert_eq!(script.system_asked(), [50]);
        assert_eq!(script.surveys(), 0);

        // A name only this network's resolver knows is still found.
        let script = pair(Reply::Missing(50), Reply::Silent).system(10, &[PRIVATE]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap(), accepted(&[PRIVATE], None, Source::System));
        assert_eq!(took, ms(60));
    }

    #[tokio::test(start_paused = true)]
    async fn a_mainland_resolver_that_lacks_the_name_does_not_end_the_lookup() {
        let script = Script::new([
            (Scope::Mainland, vec![Reply::Missing(30)]),
            (Scope::Global, vec![Reply::Addresses(100, vec![NODE])]),
        ]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert_eq!(outcome.unwrap().source, Source::Global);
        assert_eq!(took, ms(130));
        assert_eq!(script.asked(), [(0, 0), (1, 30)]);

        let script = Script::new([
            (Scope::Mainland, vec![Reply::Missing(30)]),
            (Scope::Global, vec![Reply::Broken(10)]),
        ]);
        let (outcome, took) = lookup(&script, &Memory::new()).await;
        assert!(matches!(outcome, Err(Failure::Missing)));
        assert_eq!(took, ms(40));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_connection_asks_everyone_again_and_adds_the_platform_addresses() {
        let script = Script::new([
            (
                Scope::Global,
                vec![Reply::Silent, Reply::Addresses(50, vec![NODE])],
            ),
            (Scope::Mainland, vec![Reply::Addresses(50, vec![DOMESTIC])]),
        ])
        .survey(vec![consistent(&[NODE]), Sighting::Silent])
        .system(20, &[NODE, SYNTHESIZED]);
        let memory = Memory::new();
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.asked(), [(0, 0), (1, 200)]);

        let (outcome, took) = lookup_as(&script, &memory, true).await;
        // No record TTL covers the platform resolver's part.
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE, SYNTHESIZED], None, Source::Global)
        );
        // The benched resolver is asked first, and the platform resolver
        // with it. Its extra address waits 300 ms for the witnesses.
        assert_eq!(script.asked(), [(0, 250)]);
        assert_eq!(script.system_asked(), [250]);
        assert_eq!(took, ms(320));
    }

    #[tokio::test(start_paused = true)]
    async fn platform_addresses_join_a_refreshed_answer_only_as_far_as_they_are_confirmed() {
        let script = pair(Reply::Addresses(50, vec![NODE]), Reply::Silent)
            .survey(vec![contested(&[ELSEWHERE]), Sighting::Silent])
            .system(20, &[FORGED, ELSEWHERE, DOMESTIC]);
        let (outcome, took) = lookup_as(&script, &Memory::new(), true).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE, ELSEWHERE, DOMESTIC], None, Source::Global)
        );
        assert_eq!(took, ms(320));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refreshed_answer_does_not_wait_long_for_the_platform_resolver() {
        let slow = pair(Reply::Addresses(50, vec![NODE]), Reply::Silent).system_never_answers();
        let (outcome, took) = lookup_as(&slow, &Memory::new(), true).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Global)
        );
        assert_eq!(took, ms(50) + PLATFORM_WAIT);

        let failing = pair(Reply::Addresses(50, vec![NODE]), Reply::Silent);
        let (outcome, took) = lookup_as(&failing, &Memory::new(), true).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Global)
        );
        assert_eq!(took, ms(50));

        // Nor for a verdict on addresses it already has.
        let same = pair(Reply::Addresses(50, vec![NODE]), Reply::Silent).system(20, &[NODE]);
        let (outcome, took) = lookup_as(&same, &Memory::new(), true).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], Some(TTL), Source::Global)
        );
        assert_eq!(took, ms(50));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_judges_the_path_again() {
        let script = pair(Reply::Broken(10), Reply::Addresses(50, vec![NODE]))
            .survey(vec![consistent(&[NODE]), Sighting::Silent]);
        let memory = Memory::new();
        lookup(&script, &memory).await.0.unwrap();
        lookup(&script, &memory).await.0.unwrap();
        assert_eq!(script.surveys(), 1);
        lookup_as(&script, &memory, true).await.0.unwrap();
        assert_eq!(script.surveys(), 2);
    }

    #[test]
    fn one_contested_exchange_outweighs_any_number_of_quiet_ones() {
        assert_eq!(judge(Vec::new()), Verdict::Unobserved);
        assert_eq!(
            judge(vec![Sighting::Silent, Sighting::Silent]),
            Verdict::Unobserved
        );
        assert_eq!(
            judge(vec![consistent(&[NODE]), consistent(&[ELSEWHERE, NODE])]),
            Verdict::Clean {
                seen: vec![NODE, ELSEWHERE]
            }
        );
        assert_eq!(
            judge(vec![consistent(&[]), Sighting::Silent]),
            Verdict::Clean { seen: Vec::new() }
        );
        assert_eq!(
            judge(vec![consistent(&[STAND_IN]), consistent(&[STAND_IN, NODE])]),
            Verdict::Clean { seen: vec![NODE] }
        );
        let unroutable = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            judge(vec![
                consistent(&[FORGED]),
                contested(&[NODE, unroutable]),
                contested(&[ELSEWHERE, NODE]),
            ]),
            Verdict::Injected {
                held: vec![NODE, ELSEWHERE]
            }
        );
    }

    #[test]
    fn two_question_answers_count_only_if_no_exchange_was_contested() {
        assert_eq!(
            uncontested(vec![
                consistent(&[NODE]),
                Sighting::Silent,
                consistent(&[NODE, ELSEWHERE])
            ]),
            [NODE, ELSEWHERE]
        );
        assert!(uncontested(vec![consistent(&[NODE]), contested(&[NODE])]).is_empty());
        assert!(uncontested(vec![Sighting::Silent]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn benches_double_up_to_a_cap_and_an_answer_clears_them() {
        let memory = Memory::new();
        let benched = |now| memory.launch_order(2, now, false).1;
        let start = Instant::now();
        assert!(benched(start).is_empty());

        let mut now = start;
        for expected in [30, 60, 120, 240, 480, 600, 600] {
            memory.penalize(1, now);
            let bench = Duration::from_secs(expected);
            assert_eq!(benched(now + bench - ms(1)), [1]);
            assert!(benched(now + bench).is_empty());
            now += bench;
        }
        assert_eq!(
            memory.launch_order(2, now - ms(1), true),
            (VecDeque::from([0, 1]), Vec::new())
        );

        memory.penalize(1, now);
        memory.reward(1);
        assert!(benched(now).is_empty());
        memory.penalize(1, now);
        assert!(benched(now + BENCH_BASE).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn warnings_of_one_kind_are_spaced_out() {
        let memory = Memory::new();
        let start = Instant::now();
        assert!(memory.due(Notice::Injected, start));
        assert!(!memory.due(Notice::Injected, start + NOTICE_EVERY - ms(1)));
        assert!(memory.due(Notice::SystemFallback, start));
        assert!(memory.due(Notice::Injected, start + NOTICE_EVERY));
    }

    fn no_system(_host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async { Err(std::io::ErrorKind::NotFound.into()) })
    }

    #[test]
    fn the_built_in_resolvers_alternate_and_never_show_a_path() {
        let network = Network::builtin(no_system);
        let scopes: Vec<_> = network
            .resolvers()
            .iter()
            .map(|resolver| resolver.scope)
            .collect();
        assert_eq!(
            scopes,
            [Scope::Global, Scope::Mainland].repeat(ENCRYPTED_PRESET.len())
        );
        let labels: Vec<_> = network
            .resolvers()
            .iter()
            .map(|resolver| resolver.label.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "https://1.1.1.1",
                "https://223.5.5.5",
                "https://8.8.8.8",
                "https://1.12.12.12",
                "https://[2606:4700:4700::1111]",
                "https://223.6.6.6",
                "https://[2001:4860:4860::8888]",
                "https://120.53.53.53",
            ]
        );
        // Every built-in resolver is named by address, so that reaching it
        // needs no lookup of its own, and every mainland one is in the
        // mainland.
        for (resolver, described) in network.resolvers.iter().zip(network.resolvers()) {
            let Resolver::Https(url) = resolver else {
                panic!("{resolver} is not a DNS-over-HTTPS resolver");
            };
            let address: IpAddr = match url.host().unwrap() {
                url::Host::Ipv4(address) => address.into(),
                url::Host::Ipv6(address) => address.into(),
                url::Host::Domain(domain) => panic!("{domain} needs a lookup"),
            };
            assert_eq!(
                is_china_ip(address),
                described.scope == Scope::Mainland,
                "{address}"
            );
        }
        assert!(WITNESSES.iter().all(|witness| !is_china_ip(witness.ip())));
    }

    /// A witness on loopback: a standard query draws a forged response and
    /// then the real one, and a two-question query the real one alone.
    async fn injected_witness() -> SocketAddr {
        udp::tests::fake_server(|_, request| {
            let real = addresses_reply_to(request, &[NODE]);
            if Message::from_vec(request).unwrap().queries.len() == 2 {
                vec![real]
            } else {
                vec![addresses_reply_to(request, &[FORGED]), real]
            }
        })
        .await
    }

    #[tokio::test]
    async fn the_network_backend_asks_over_https_and_watches_both_query_shapes() {
        let resolver = doh::tests::fake_server(Arc::new(|request: &[u8]| {
            doh::tests::dns_response(addresses_reply_to(request, &[NODE]))
        }))
        .await;
        let network = Network::new(
            vec![(Resolver::Https(doh::tests::url(resolver)), Scope::Mainland)],
            vec![injected_witness().await],
            udp::tests::brief(),
            || Ok(doh::tests::trusting_client()),
            no_system,
            || false,
        );
        let name = name("node.example.com");
        assert_eq!(network.resolvers()[0].label, format!("https://{resolver}"));
        assert!(network.can_witness());
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(matches!(
            network.ask(0, &name, deadline).await.unwrap(),
            Resolution::Addresses { addresses, .. } if addresses == [NODE]
        ));
        assert_eq!(
            network.witness(&name, QueryShape::Standard).await,
            [contested(&[NODE])]
        );
        assert_eq!(
            network.witness(&name, QueryShape::DualQuestion).await,
            [consistent(&[NODE])]
        );
    }

    #[tokio::test]
    async fn a_forged_cache_entry_is_replaced_by_what_the_evading_query_and_the_race_agree_on() {
        // The whole cascade over loopback sockets: the only reachable
        // resolver is a mainland one whose cache holds a forgery, and the
        // path to the witnesses races forged responses against real ones.
        let poisoned = doh::tests::fake_server(Arc::new(|request: &[u8]| {
            doh::tests::dns_response(addresses_reply_to(request, &[FORGED]))
        }))
        .await;
        let network = Network::new(
            vec![(Resolver::Https(doh::tests::url(poisoned)), Scope::Mainland)],
            vec![injected_witness().await],
            udp::tests::brief(),
            || Ok(doh::tests::trusting_client()),
            no_system,
            || false,
        );
        let name = name("node.example.com");
        let deadline = Instant::now() + Duration::from_secs(5);
        let outcome = resolve(&network, &Memory::new(), &name, false, deadline).await;
        assert_eq!(
            outcome.unwrap(),
            accepted(&[NODE], None, Source::Corroborated)
        );
    }
}
