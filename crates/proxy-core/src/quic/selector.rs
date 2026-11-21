//! Per-node primary/standby UDP ingress selection, decoupled from physical connection pooling.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::{fmt, io};

use arc_swap::ArcSwapOption;
use moka::sync::Cache;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::time::Instant;

use crate::upstream::{Carrier, UpstreamAddress};

/// Budget reserved for the first candidate within a dual-ingress acquisition.
pub(super) const FIRST_CANDIDATE_BUDGET: Duration = Duration::from_secs(4);
/// Minimum window a newly authenticated standby ingress remains preferred even
/// if the bounded connection cache evicts its slot before [`super::POOL_LINGER`].
const STANDBY_STICKY: Duration = Duration::from_secs(15);
const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(2);

const _: () = assert!(
    super::CONNECT_TIMEOUT.as_millis() > FIRST_CANDIDATE_BUDGET.as_millis(),
    "the first candidate slice must leave remaining acquisition budget for the alternate ingress",
);
const _: () = assert!(
    super::POOL_LINGER.as_millis() > STANDBY_STICKY.as_millis(),
    "idle pool eviction must occur after the standby sticky window so idle failback probes primary",
);

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Normalize a logical node host so configuration, selector state and runtime
/// upstream switches match regardless of ASCII case, trailing root dot or IPv6 brackets.
pub(super) fn normalize_node_host(host: &str) -> io::Result<Box<str>> {
    let trimmed = host.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.contains(['/', '?', '#', '@'])
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid_input("invalid QUIC node host"));
    }
    let bare = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed)
        .trim_end_matches('.');
    if bare.is_empty() || bare.contains(['[', ']']) {
        return Err(invalid_input("invalid QUIC node host"));
    }
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(ip.to_string().into_boxed_str());
    }
    match url::Host::parse(bare).map_err(|_| invalid_input("invalid QUIC node host"))? {
        url::Host::Domain(domain) => Ok(domain.into_boxed_str()),
        url::Host::Ipv4(ip) => Ok(ip.to_string().into_boxed_str()),
        url::Host::Ipv6(ip) => Ok(ip.to_string().into_boxed_str()),
    }
}

/// Validated standby UDP port for one logical QUIC node.
///
/// Both UDP ports belong to the same logical host, TLS certificate identity and
/// application credential; only the dialed UDP port differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandbyRule {
    host: Box<str>,
    primary_port: NonZeroU16,
    standby_port: NonZeroU16,
}

impl StandbyRule {
    pub fn new(host: &str, primary_port: u16, standby_port: u16) -> io::Result<Self> {
        let host = normalize_node_host(host)?;
        let primary_port = NonZeroU16::new(primary_port)
            .ok_or_else(|| invalid_input("QUIC primary port must be nonzero"))?;
        let standby_port = NonZeroU16::new(standby_port)
            .ok_or_else(|| invalid_input("QUIC standby port must be nonzero"))?;
        if primary_port == standby_port {
            return Err(invalid_input(
                "QUIC standby port must differ from primary port",
            ));
        }
        Ok(Self {
            host,
            primary_port,
            standby_port,
        })
    }

    /// Parse `host:primary=standby`, `[ipv6]:primary=standby` or `quic://host:primary=standby`.
    pub fn parse(entry: &str) -> io::Result<Self> {
        let entry = entry.trim();
        let (target, standby) = entry
            .split_once('=')
            .ok_or_else(|| invalid_input("QUIC standby rule requires host:primary=standby"))?;
        if standby.contains('=') {
            return Err(invalid_input(
                "QUIC standby rule requires host:primary=standby",
            ));
        }
        let target = target.trim();
        let standby_port = standby
            .trim()
            .parse::<u16>()
            .map_err(|_| invalid_input("invalid QUIC standby port"))?;
        let endpoint = UpstreamAddress::parse(target)
            .map_err(|_| invalid_input("invalid QUIC standby target; expected host:port"))?;
        if target.contains("://") && endpoint.carrier != Carrier::Quic {
            return Err(invalid_input("QUIC standby rule scheme must be quic"));
        }
        Self::new(&endpoint.host, endpoint.port, standby_port)
    }

    /// Parse comma-separated rules (`PROXY_QUIC_STANDBY`). An empty string clears standby rules.
    pub fn parse_list(raw: &str) -> io::Result<Vec<Self>> {
        if raw.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut rules = Vec::new();
        for item in raw.split(',') {
            rules.push(Self::parse(item)?);
        }
        let _ = build_standby_map(rules.iter().cloned())?;
        Ok(rules)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn primary_port(&self) -> NonZeroU16 {
        self.primary_port
    }

    pub fn standby_port(&self) -> NonZeroU16 {
        self.standby_port
    }
}

fn build_standby_map(
    rules: impl IntoIterator<Item = StandbyRule>,
) -> io::Result<HashMap<(Box<str>, u16), NonZeroU16>> {
    let mut map = HashMap::new();
    for rule in rules {
        if map
            .insert((rule.host, rule.primary_port.get()), rule.standby_port)
            .is_some()
        {
            return Err(invalid_input(
                "duplicate QUIC standby rule for the same node",
            ));
        }
    }
    Ok(map)
}

pub(super) struct StandbyTable {
    pub generation: u64,
    by_node: HashMap<(Box<str>, u16), NonZeroU16>,
}

impl StandbyTable {
    pub fn lookup(&self, normalized_host: &str, primary_port: u16) -> Option<NonZeroU16> {
        self.by_node.iter().find_map(|((host, port), standby)| {
            (*port == primary_port && host.as_ref() == normalized_host).then_some(*standby)
        })
    }
}

static STANDBY: ArcSwapOption<StandbyTable> = ArcSwapOption::const_empty();

/// Replace per-node QUIC standby ports for subsequent sessions.
///
/// Passing an empty iterator disables standby switching and restores single-port
/// dialing for new sessions without disturbing established connections.
pub fn configure_standby(rules: impl IntoIterator<Item = StandbyRule>) -> io::Result<()> {
    let by_node = build_standby_map(rules)?;
    STANDBY.rcu(|current| {
        Some(Arc::new(StandbyTable {
            generation: current.as_ref().map_or(0, |table| table.generation) + 1,
            by_node: by_node.clone(),
        }))
    });
    Ok(())
}

/// Current standby snapshot, lock-free after initialization. Without an explicit
/// [`configure_standby`], reads `PROXY_QUIC_STANDBY` once.
pub(super) fn standby() -> io::Result<Arc<StandbyTable>> {
    if let Some(table) = STANDBY.load_full() {
        return Ok(table);
    }
    let by_node = match std::env::var("PROXY_QUIC_STANDBY") {
        Ok(raw) => build_standby_map(StandbyRule::parse_list(&raw)?)?,
        Err(std::env::VarError::NotPresent) => HashMap::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(invalid_input("PROXY_QUIC_STANDBY must be valid UTF-8"));
        }
    };
    let table = Arc::new(StandbyTable {
        generation: 0,
        by_node,
    });
    let previous = STANDBY.compare_and_swap(&None::<Arc<StandbyTable>>, Some(Arc::clone(&table)));
    Ok(Option::clone(&previous).unwrap_or(table))
}

/// Classified reason a QUIC session acquisition failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Timeout,
    Unreachable,
    Tls,
    Authentication,
    AdmissionClosed,
    InvalidConfig,
}

impl FailureKind {
    /// Classify whether an alternate UDP ingress may be attempted.
    ///
    /// TLS, certificate, ALPN, application authentication and configuration
    /// rejections must surface directly without being masked by standby retry.
    pub const fn is_retryable(self) -> bool {
        match self {
            Self::Timeout | Self::Unreachable | Self::AdmissionClosed => true,
            Self::Tls | Self::Authentication | Self::InvalidConfig => false,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::Tls => "tls",
            Self::Authentication => "authentication",
            Self::AdmissionClosed => "admission_closed",
            Self::InvalidConfig => "invalid_config",
        }
    }

    fn default_io_kind(self) -> io::ErrorKind {
        match self {
            Self::Timeout => io::ErrorKind::TimedOut,
            Self::Unreachable => io::ErrorKind::ConnectionAborted,
            Self::Tls => io::ErrorKind::InvalidData,
            Self::Authentication => io::ErrorKind::PermissionDenied,
            Self::AdmissionClosed => io::ErrorKind::ConnectionAborted,
            Self::InvalidConfig => io::ErrorKind::InvalidInput,
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured QUIC dial failure carried inside [`io::Error`].
#[derive(Clone, Debug)]
pub struct ConnectError {
    kind: FailureKind,
    standby_attempted: bool,
    primary_failure: Option<FailureKind>,
    standby_failure: Option<FailureKind>,
    source: Option<Arc<io::Error>>,
}

impl ConnectError {
    pub fn kind(&self) -> FailureKind {
        self.kind
    }

    pub fn standby_attempted(&self) -> bool {
        self.standby_attempted
    }

    pub fn primary_failure(&self) -> Option<FailureKind> {
        self.primary_failure
    }

    pub fn standby_failure(&self) -> Option<FailureKind> {
        self.standby_failure
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.standby_attempted {
            return write!(
                f,
                "QUIC primary ({}) and standby ({}) UDP ingresses failed; TCP fallback is disabled",
                self.primary_failure
                    .map_or("not_attempted", FailureKind::as_str),
                self.standby_failure
                    .map_or("not_attempted", FailureKind::as_str),
            );
        }
        match self.kind {
            FailureKind::Timeout => {
                f.write_str("QUIC connection/stream deadline exceeded; TCP fallback is disabled")
            }
            FailureKind::Authentication => f.write_str("QUIC application authentication failed"),
            FailureKind::AdmissionClosed => {
                f.write_str("QUIC connection unavailable for new streams")
            }
            FailureKind::Tls => f.write_str("QUIC TLS verification failed"),
            FailureKind::Unreachable => {
                f.write_str("QUIC UDP ingress unreachable; TCP fallback is disabled")
            }
            FailureKind::InvalidConfig => f.write_str("invalid QUIC configuration"),
        }
    }
}

impl StdError for ConnectError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn StdError + 'static))
    }
}

/// Extract structured QUIC connection failure details when present.
pub fn connect_error(error: &io::Error) -> Option<&ConnectError> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ConnectError>())
}

/// Classify a QUIC [`io::Error`] without matching on error text.
pub fn classify_error(error: &io::Error) -> FailureKind {
    if let Some(typed) = connect_error(error) {
        return typed.kind();
    }
    match error.kind() {
        io::ErrorKind::TimedOut => FailureKind::Timeout,
        io::ErrorKind::PermissionDenied => FailureKind::Authentication,
        io::ErrorKind::InvalidInput => FailureKind::InvalidConfig,
        io::ErrorKind::InvalidData => FailureKind::Tls,
        _ => FailureKind::Unreachable,
    }
}

#[derive(Clone, Debug)]
pub(super) struct SharedDialError {
    pub kind: FailureKind,
    pub io_kind: io::ErrorKind,
    pub source: Option<Arc<io::Error>>,
}

impl SharedDialError {
    pub fn timeout() -> Self {
        Self {
            kind: FailureKind::Timeout,
            io_kind: io::ErrorKind::TimedOut,
            source: None,
        }
    }

    pub fn authentication_failed() -> Self {
        Self {
            kind: FailureKind::Authentication,
            io_kind: io::ErrorKind::PermissionDenied,
            source: None,
        }
    }

    pub fn admission_closed() -> Self {
        Self {
            kind: FailureKind::AdmissionClosed,
            io_kind: io::ErrorKind::ConnectionAborted,
            source: None,
        }
    }

    pub fn from_io(kind: FailureKind, error: io::Error) -> Self {
        if let Some(existing) = connect_error(&error) {
            return Self {
                kind: existing.kind,
                io_kind: error.kind(),
                source: existing.source.clone(),
            };
        }
        let io_kind = match kind {
            FailureKind::Unreachable if error.kind() != io::ErrorKind::Other => error.kind(),
            _ => kind.default_io_kind(),
        };
        Self {
            kind,
            io_kind,
            source: Some(Arc::new(error)),
        }
    }

    pub fn into_io_error(self) -> io::Error {
        record_failure_metric(self.kind);
        self.into_carrier_io_error()
    }

    pub(super) fn into_carrier_io_error(self) -> io::Error {
        io::Error::new(
            self.io_kind,
            ConnectError {
                kind: self.kind,
                standby_attempted: false,
                primary_failure: None,
                standby_failure: None,
                source: self.source,
            },
        )
    }
}

pub(super) fn dual_failure_error(
    primary_failure: SharedDialError,
    standby_failure: SharedDialError,
    final_is_standby: bool,
) -> io::Error {
    let chosen = if final_is_standby {
        &standby_failure
    } else {
        &primary_failure
    };
    let kind = if primary_failure.kind == FailureKind::Timeout
        || standby_failure.kind == FailureKind::Timeout
    {
        // When the shared deadline ends a dual-ingress attempt after an earlier
        // unreachable candidate, Timeout describes why acquisition stopped; if the
        // final candidate failed immediately with Unreachable, keep Unreachable.
        if chosen.kind == FailureKind::Timeout {
            FailureKind::Timeout
        } else {
            chosen.kind
        }
    } else {
        chosen.kind
    };
    let io_kind = if kind == FailureKind::Timeout {
        io::ErrorKind::TimedOut
    } else {
        chosen.io_kind
    };
    record_failure_metric(kind);
    io::Error::new(
        io_kind,
        ConnectError {
            kind,
            standby_attempted: true,
            primary_failure: Some(primary_failure.kind),
            standby_failure: Some(standby_failure.kind),
            source: chosen.source.clone().or(primary_failure.source),
        },
    )
}

fn is_crypto_error(code: quinn::TransportErrorCode) -> bool {
    (0x100..0x200).contains(&u64::from(code))
}

pub(super) fn classify_connect_error(error: quinn::ConnectError) -> SharedDialError {
    match error {
        quinn::ConnectError::EndpointStopping | quinn::ConnectError::CidsExhausted => {
            SharedDialError::from_io(FailureKind::Unreachable, io::Error::other(error))
        }
        quinn::ConnectError::InvalidServerName(_) => SharedDialError::from_io(
            FailureKind::Tls,
            io::Error::new(io::ErrorKind::InvalidInput, error),
        ),
        quinn::ConnectError::InvalidRemoteAddress(_)
        | quinn::ConnectError::NoDefaultClientConfig
        | quinn::ConnectError::UnsupportedVersion => SharedDialError::from_io(
            FailureKind::InvalidConfig,
            io::Error::new(io::ErrorKind::InvalidInput, error),
        ),
    }
}

pub(super) fn classify_connection_error(
    error: quinn::ConnectionError,
    during_auth: bool,
) -> SharedDialError {
    match error {
        quinn::ConnectionError::VersionMismatch => SharedDialError::from_io(
            FailureKind::InvalidConfig,
            io::Error::new(io::ErrorKind::InvalidData, error),
        ),
        quinn::ConnectionError::TransportError(ref transport)
            if is_crypto_error(transport.code) =>
        {
            SharedDialError::from_io(
                FailureKind::Tls,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        }
        quinn::ConnectionError::ConnectionClosed(ref close)
            if is_crypto_error(close.error_code) =>
        {
            SharedDialError::from_io(
                FailureKind::Tls,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        }
        quinn::ConnectionError::ApplicationClosed(ref close)
            if during_auth && close.error_code == super::AUTH_FAILED =>
        {
            SharedDialError::authentication_failed()
        }
        quinn::ConnectionError::TimedOut => SharedDialError::timeout(),
        quinn::ConnectionError::Reset => SharedDialError::from_io(
            FailureKind::Unreachable,
            io::Error::new(io::ErrorKind::ConnectionReset, error),
        ),
        quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::CidsExhausted => {
            SharedDialError::from_io(FailureKind::Unreachable, io::Error::from(error))
        }
    }
}

/// Process-wide, lock-free counters for QUIC ingress selection and recovery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectorStats {
    pub primary_dials: u64,
    pub standby_dials: u64,
    pub acquisitions_succeeded: u64,
    pub timeout_failures: u64,
    pub unreachable_failures: u64,
    pub tls_failures: u64,
    pub auth_failures: u64,
    pub admission_failures: u64,
    pub config_failures: u64,
    pub standby_promotions: u64,
    pub primary_failbacks: u64,
}

struct AtomicStats {
    primary_dials: AtomicU64,
    standby_dials: AtomicU64,
    acquisitions_succeeded: AtomicU64,
    timeout_failures: AtomicU64,
    unreachable_failures: AtomicU64,
    tls_failures: AtomicU64,
    auth_failures: AtomicU64,
    admission_failures: AtomicU64,
    config_failures: AtomicU64,
    standby_promotions: AtomicU64,
    primary_failbacks: AtomicU64,
}

static STATS: AtomicStats = AtomicStats {
    primary_dials: AtomicU64::new(0),
    standby_dials: AtomicU64::new(0),
    acquisitions_succeeded: AtomicU64::new(0),
    timeout_failures: AtomicU64::new(0),
    unreachable_failures: AtomicU64::new(0),
    tls_failures: AtomicU64::new(0),
    auth_failures: AtomicU64::new(0),
    admission_failures: AtomicU64::new(0),
    config_failures: AtomicU64::new(0),
    standby_promotions: AtomicU64::new(0),
    primary_failbacks: AtomicU64::new(0),
};

pub fn selector_stats() -> SelectorStats {
    SelectorStats {
        primary_dials: STATS.primary_dials.load(Ordering::Relaxed),
        standby_dials: STATS.standby_dials.load(Ordering::Relaxed),
        acquisitions_succeeded: STATS.acquisitions_succeeded.load(Ordering::Relaxed),
        timeout_failures: STATS.timeout_failures.load(Ordering::Relaxed),
        unreachable_failures: STATS.unreachable_failures.load(Ordering::Relaxed),
        tls_failures: STATS.tls_failures.load(Ordering::Relaxed),
        auth_failures: STATS.auth_failures.load(Ordering::Relaxed),
        admission_failures: STATS.admission_failures.load(Ordering::Relaxed),
        config_failures: STATS.config_failures.load(Ordering::Relaxed),
        standby_promotions: STATS.standby_promotions.load(Ordering::Relaxed),
        primary_failbacks: STATS.primary_failbacks.load(Ordering::Relaxed),
    }
}

pub(super) fn record_dial(ingress: Ingress) {
    match ingress {
        Ingress::Primary => STATS.primary_dials.fetch_add(1, Ordering::Relaxed),
        Ingress::Standby => STATS.standby_dials.fetch_add(1, Ordering::Relaxed),
    };
}

pub(super) fn record_success() {
    STATS.acquisitions_succeeded.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_failure_metric(kind: FailureKind) {
    let counter = match kind {
        FailureKind::Timeout => &STATS.timeout_failures,
        FailureKind::Unreachable => &STATS.unreachable_failures,
        FailureKind::Tls => &STATS.tls_failures,
        FailureKind::Authentication => &STATS.auth_failures,
        FailureKind::AdmissionClosed => &STATS.admission_failures,
        FailureKind::InvalidConfig => &STATS.config_failures,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ingress {
    Primary,
    Standby,
}

impl Ingress {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Standby => "standby",
        }
    }

    pub const fn alternate(self) -> Self {
        match self {
            Self::Primary => Self::Standby,
            Self::Standby => Self::Primary,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PoolStatus {
    Healthy,
    Faulted(usize),
    Empty,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct SelectorKey {
    pub runtime: tokio::runtime::Id,
    pub host: Box<str>,
    pub primary_port: u16,
    pub standby_port: u16,
    pub standby_generation: u64,
    pub credential: [u8; 32],
    pub trust_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preference {
    Primary,
    PrimaryFaulted { id: usize },
    Standby { id: usize, sticky_until: Instant },
    StandbyFaulted { id: usize },
}

struct SelectorInner {
    preference: Preference,
    consecutive_all_failed: u32,
    next_dial_after: Option<Instant>,
}

pub(super) struct SelectorState {
    inner: Mutex<SelectorInner>,
}

impl Default for SelectorState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SelectorInner {
                preference: Preference::Primary,
                consecutive_all_failed: 0,
                next_dial_after: None,
            }),
        }
    }
}

impl SelectorState {
    /// Choose the two-candidate order `[first, second]` for this acquisition.
    ///
    /// Also returns an optional `Ingress` whose faulted pooled connection was
    /// observed here and must be retired from its physical pool slot.
    pub fn plan(
        &self,
        now: Instant,
        primary_status: PoolStatus,
        standby_status: PoolStatus,
    ) -> ([Ingress; 2], Option<(Ingress, usize)>) {
        let mut inner = self.inner.lock();
        match inner.preference {
            Preference::Primary => match primary_status {
                PoolStatus::Healthy | PoolStatus::Empty => {
                    ([Ingress::Primary, Ingress::Standby], None)
                }
                PoolStatus::Faulted(id) => {
                    inner.preference = Preference::PrimaryFaulted { id };
                    (
                        [Ingress::Standby, Ingress::Primary],
                        Some((Ingress::Primary, id)),
                    )
                }
            },
            Preference::PrimaryFaulted { id } => {
                let retire = match primary_status {
                    PoolStatus::Faulted(current) if current == id => Some((Ingress::Primary, id)),
                    PoolStatus::Healthy | PoolStatus::Faulted(_) | PoolStatus::Empty => None,
                };
                ([Ingress::Standby, Ingress::Primary], retire)
            }
            Preference::Standby {
                id: _,
                sticky_until,
            } => match standby_status {
                PoolStatus::Healthy => ([Ingress::Standby, Ingress::Primary], None),
                PoolStatus::Faulted(fault_id) => {
                    inner.preference = Preference::StandbyFaulted { id: fault_id };
                    (
                        [Ingress::Primary, Ingress::Standby],
                        Some((Ingress::Standby, fault_id)),
                    )
                }
                PoolStatus::Empty => {
                    if now < sticky_until {
                        ([Ingress::Standby, Ingress::Primary], None)
                    } else {
                        // Standby's pooled connection was idle-evicted after its sticky
                        // window: probe primary on the next session without background timers.
                        inner.preference = Preference::Primary;
                        STATS.primary_failbacks.fetch_add(1, Ordering::Relaxed);
                        ([Ingress::Primary, Ingress::Standby], None)
                    }
                }
            },
            Preference::StandbyFaulted { id } => {
                let retire = match standby_status {
                    PoolStatus::Faulted(current) if current == id => Some((Ingress::Standby, id)),
                    PoolStatus::Healthy | PoolStatus::Faulted(_) | PoolStatus::Empty => None,
                };
                ([Ingress::Primary, Ingress::Standby], retire)
            }
        }
    }

    pub fn backoff_until(&self, now: Instant) -> Option<Instant> {
        let inner = self.inner.lock();
        inner.next_dial_after.filter(|&until| until > now)
    }

    /// Record that an already-pooled connection faulted while waiting on `open_bi`.
    pub fn note_mid_admission_fault(&self, ingress: Ingress, conn_id: usize) {
        let mut inner = self.inner.lock();
        match (ingress, inner.preference) {
            (Ingress::Primary, Preference::Primary) => {
                inner.preference = Preference::PrimaryFaulted { id: conn_id };
            }
            (Ingress::Standby, Preference::Standby { .. }) => {
                inner.preference = Preference::StandbyFaulted { id: conn_id };
            }
            _ => {}
        }
    }

    /// Publish an authenticated ingress result. Called only after TLS and
    /// exporter-bound application authentication have both succeeded.
    pub fn note_success(
        &self,
        ingress: Ingress,
        port: u16,
        conn_id: usize,
        fresh_dial: bool,
        now: Instant,
    ) {
        let (promoted_standby, failed_back_primary) = {
            let mut inner = self.inner.lock();
            inner.consecutive_all_failed = 0;
            inner.next_dial_after = None;
            match ingress {
                Ingress::Primary => {
                    let from_standby = matches!(
                        inner.preference,
                        Preference::Standby { .. } | Preference::StandbyFaulted { .. }
                    );
                    inner.preference = Preference::Primary;
                    (false, from_standby)
                }
                Ingress::Standby => {
                    let (was_standby, sticky_until) = match inner.preference {
                        Preference::Standby { sticky_until, .. } if !fresh_dial => {
                            (true, sticky_until)
                        }
                        Preference::Standby { .. } => (true, now + STANDBY_STICKY),
                        Preference::Primary
                        | Preference::PrimaryFaulted { .. }
                        | Preference::StandbyFaulted { .. } => (false, now + STANDBY_STICKY),
                    };
                    inner.preference = Preference::Standby {
                        id: conn_id,
                        sticky_until,
                    };
                    (!was_standby, false)
                }
            }
        };
        if promoted_standby {
            STATS.standby_promotions.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                carrier = "quic",
                preferred_ingress = "standby",
                port,
                connection_id = conn_id,
                "promoted standby QUIC ingress for new sessions"
            );
        } else if failed_back_primary {
            STATS.primary_failbacks.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                carrier = "quic",
                preferred_ingress = "primary",
                port,
                connection_id = conn_id,
                "restored primary QUIC ingress for new sessions"
            );
        }
    }

    /// Record that every candidate ingress for this node failed with retryable
    /// network/timeout errors, pacing subsequent rounds for this node only.
    pub fn note_all_failed(&self, now: Instant) {
        let mut inner = self.inner.lock();
        if matches!(
            inner.preference,
            Preference::PrimaryFaulted { .. } | Preference::StandbyFaulted { .. }
        ) {
            inner.preference = Preference::Primary;
        }
        if inner.next_dial_after.is_some_and(|until| until > now) {
            return;
        }
        inner.consecutive_all_failed = inner.consecutive_all_failed.saturating_add(1);
        let shift = inner.consecutive_all_failed.saturating_sub(1).min(2);
        let base_ms = (BACKOFF_INITIAL.as_millis() as u64).saturating_mul(1u64 << shift);
        let jitter_ms = rand::rng().random_range(0..=125u64);
        let delay = Duration::from_millis(base_ms.saturating_add(jitter_ms)).min(BACKOFF_CAP);
        inner.next_dial_after = Some(now + delay);
    }
}

static SELECTORS: LazyLock<Cache<SelectorKey, Arc<SelectorState>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(256)
        .time_to_idle(Duration::from_secs(300))
        .build()
});

pub(super) fn selector(key: SelectorKey) -> Arc<SelectorState> {
    SELECTORS.get_with(key, || Arc::new(SelectorState::default()))
}

pub(super) fn invalidate_runtime(runtime: tokio::runtime::Id) {
    for (key, _) in SELECTORS.iter() {
        if key.runtime == runtime {
            SELECTORS.invalidate(key.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standby_rules_validate_ports_schemes_uniqueness_and_canonical_hosts() {
        let domain = StandbyRule::parse("Proxy.Example.:10811=10812").unwrap();
        assert_eq!(domain.host(), "proxy.example");
        assert_eq!(domain.primary_port().get(), 10811);
        assert_eq!(domain.standby_port().get(), 10812);

        let scheme = StandbyRule::parse("quic://[2001:0db8::1]:10811=20811").unwrap();
        assert_eq!(scheme.host(), "2001:db8::1");
        assert_eq!(scheme.standby_port().get(), 20811);

        let idn = StandbyRule::parse("B\u{fc}cher.Example:10811=10812").unwrap();
        assert_eq!(idn.host(), "xn--bcher-kva.example");

        assert!(StandbyRule::parse("").is_err());
        assert!(StandbyRule::parse("proxy.example=10812").is_err());
        assert!(StandbyRule::parse("proxy.example:0=10812").is_err());
        assert!(StandbyRule::parse("proxy.example:10811=0").is_err());
        assert!(StandbyRule::parse("proxy.example:10811=10811").is_err());
        assert!(StandbyRule::parse("tcp://proxy.example:10811=10812").is_err());
        assert!(StandbyRule::parse("quic://user:pass@proxy.example:10811=10812").is_err());
        assert!(StandbyRule::parse("proxy.example:10811=10812=10813").is_err());

        assert!(StandbyRule::parse_list("   ").unwrap().is_empty());
        assert_eq!(
            StandbyRule::parse_list("a.example:10811=10812, b.example:10811=10813")
                .unwrap()
                .len(),
            2
        );
        assert!(
            StandbyRule::parse_list("a.example:10811=10812, A.EXAMPLE.:10811=10813").is_err(),
            "duplicate logical node entries must be rejected"
        );
        assert!(StandbyRule::parse_list("a.example:10811=10812,").is_err());
    }

    #[test]
    fn tls_alpn_and_authentication_errors_are_non_retryable_and_preserve_sources() {
        let local_tls = classify_connection_error(
            quinn::ConnectionError::TransportError(quinn::TransportErrorCode::crypto(0x30).into()),
            false,
        );
        assert_eq!(local_tls.kind, FailureKind::Tls);
        assert!(!local_tls.kind.is_retryable());

        let peer_alpn = classify_connection_error(
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::crypto(0x78),
                frame_type: None,
                reason: Default::default(),
            }),
            false,
        );
        assert_eq!(peer_alpn.kind, FailureKind::Tls);
        assert!(!peer_alpn.kind.is_retryable());

        let peer_auth = classify_connection_error(
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: super::super::AUTH_FAILED,
                reason: Default::default(),
            }),
            true,
        );
        assert_eq!(peer_auth.kind, FailureKind::Authentication);
        assert!(!peer_auth.kind.is_retryable());
        assert_eq!(
            peer_auth.clone().into_carrier_io_error().kind(),
            io::ErrorKind::PermissionDenied
        );

        let reset = classify_connection_error(quinn::ConnectionError::Reset, false);
        assert_eq!(reset.kind, FailureKind::Unreachable);
        assert!(reset.kind.is_retryable());

        let os_err =
            SharedDialError::from_io(FailureKind::Unreachable, io::Error::from_raw_os_error(111))
                .into_carrier_io_error();
        assert_eq!(classify_error(&os_err), FailureKind::Unreachable);
        let cause = StdError::source(&os_err)
            .and_then(|err| err.downcast_ref::<io::Error>())
            .unwrap();
        assert_eq!(cause.raw_os_error(), Some(111));
    }

    #[tokio::test(start_paused = true)]
    async fn selector_prefers_standby_while_healthy_and_probes_primary_after_idle_eviction() {
        let state = SelectorState::default();
        let t0 = Instant::now();

        assert_eq!(
            state.plan(t0, PoolStatus::Empty, PoolStatus::Empty),
            ([Ingress::Primary, Ingress::Standby], None)
        );

        // Primary connection faults -> all concurrent callers try standby first, with primary
        // rescue.
        assert_eq!(
            state.plan(t0, PoolStatus::Faulted(7), PoolStatus::Empty),
            (
                [Ingress::Standby, Ingress::Primary],
                Some((Ingress::Primary, 7))
            )
        );
        assert_eq!(
            state.plan(t0, PoolStatus::Empty, PoolStatus::Empty),
            ([Ingress::Standby, Ingress::Primary], None)
        );

        // Standby authenticates -> sticky while active or within sticky window.
        state.note_success(Ingress::Standby, 10812, 8, true, t0);
        assert_eq!(
            state.plan(
                t0 + Duration::from_secs(5),
                PoolStatus::Empty,
                PoolStatus::Empty
            ),
            ([Ingress::Standby, Ingress::Primary], None),
            "within sticky window standby remains preferred even without a cached slot"
        );
        assert_eq!(
            state.plan(
                t0 + Duration::from_secs(120),
                PoolStatus::Empty,
                PoolStatus::Healthy,
            ),
            ([Ingress::Standby, Ingress::Primary], None),
            "while standby connection stays healthy in the pool, do not probe primary"
        );

        // Once close_when_idle evicts the idle standby connection, the next dial probes primary.
        assert_eq!(
            state.plan(
                t0 + super::super::POOL_LINGER + Duration::from_secs(1),
                PoolStatus::Empty,
                PoolStatus::Empty,
            ),
            ([Ingress::Primary, Ingress::Standby], None)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn standby_fault_reverses_immediately_and_backoff_stays_node_scoped() {
        let node_a = SelectorState::default();
        let node_b = SelectorState::default();
        let t0 = Instant::now();

        node_a.note_success(Ingress::Standby, 10812, 11, true, t0);
        assert_eq!(
            node_a.plan(
                t0 + Duration::from_secs(1),
                PoolStatus::Empty,
                PoolStatus::Faulted(11)
            ),
            (
                [Ingress::Primary, Ingress::Standby],
                Some((Ingress::Standby, 11))
            )
        );

        node_a.note_all_failed(t0 + Duration::from_secs(2));
        let until = node_a.backoff_until(t0 + Duration::from_secs(2)).unwrap();
        assert!(until > t0 + Duration::from_secs(2));
        assert!(until <= t0 + Duration::from_secs(2) + BACKOFF_CAP);
        assert!(
            node_b.backoff_until(t0 + Duration::from_secs(2)).is_none(),
            "failure pacing must never leak across nodes"
        );

        node_a.note_success(Ingress::Primary, 10811, 12, true, until);
        assert!(node_a.backoff_until(until).is_none());
    }
}
