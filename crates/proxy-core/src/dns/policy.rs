//! Endpoint resolver configuration and its text form.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::{fmt, io};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use url::Url;

const DNS_PORT: u16 = 53;
const DEFAULT_DOH_PATH: &str = "/dns-query";
/// Resolvers are raced two at a time, so a longer list only adds waiting.
const MAX_RESOLVERS: usize = 8;

/// RFC 8484 servers behind the `encrypted` preset. Providers alternate so one
/// blocked operator does not occupy both concurrent attempts, and the URLs are
/// IP literals, so reaching them needs no bootstrap lookup. Both operators
/// publish certificates for these addresses.
pub(crate) const ENCRYPTED_PRESET: [&str; 4] = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://[2606:4700:4700::1111]/dns-query",
    "https://[2001:4860:4860::8888]/dns-query",
];

/// How the client resolves the remote proxy endpoints it dials before any
/// tunnel exists: native nodes, relay targets and external upstream proxies.
///
/// The text form is `auto`, or a comma-separated list. `auto` asks built-in
/// DNS-over-HTTPS servers and falls back to the platform resolver, whose
/// answer it refuses while forged ones are visible on the path; see
/// `docs/endpoint-dns.md`. In a list, `https://` entries are DNS-over-HTTPS
/// servers, `udp://` entries plaintext servers given by IP address,
/// `encrypted` expands to a built-in DoH list, and `system` is the platform
/// resolver. Listed network entries are raced; a trailing `system` is
/// consulted only after all of them fail, and without it a failure is
/// returned instead of a plaintext answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointDnsPolicy(Strategy);

/// What an [`EndpointDnsPolicy`] asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Strategy {
    Automatic,
    System,
    Listed {
        /// Never empty.
        resolvers: Vec<Resolver>,
        system_fallback: bool,
    },
}

/// One network resolver of an [`EndpointDnsPolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolver {
    Https(Url),
    Udp {
        server: SocketAddr,
        shape: QueryShape,
    },
}

/// Question layout of a plaintext query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryShape {
    /// One question and an EDNS(0) record, as RFC 1035 and RFC 6891 specify.
    Standard,
    /// A second question that is a compression pointer to the first.
    ///
    /// CircumVolve (CCS 2026) observed the GFW injectors exempting this shape,
    /// which RFC 9619 forbids, and only some public resolvers answering it.
    DualQuestion,
}

/// Why an endpoint DNS policy was rejected.
#[derive(Debug, Snafu, Clone, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum ParsePolicyError {
    #[snafu(display("the endpoint DNS policy lists no resolver"))]
    Empty,
    #[snafu(display(
        "unknown endpoint DNS entry `{entry}`; expected auto, system, encrypted, https://… or \
         udp://…"
    ))]
    UnknownEntry { entry: String },
    #[snafu(display(
        "`auto` is a complete endpoint DNS policy and cannot be combined with other entries"
    ))]
    AutoNotAlone,
    #[snafu(display("invalid DNS-over-HTTPS URL: {reason}"))]
    InvalidHttps { reason: String },
    #[snafu(display("invalid UDP resolver `{entry}`: {reason}"))]
    InvalidUdp { entry: String, reason: &'static str },
    #[snafu(display(
        "`system` must be the last endpoint DNS entry; it is only consulted after the others fail"
    ))]
    SystemNotLast,
    #[snafu(display(
        "the endpoint DNS policy lists {count} resolvers; at most {MAX_RESOLVERS} are allowed"
    ))]
    TooMany { count: usize },
}

impl ParsePolicyError {
    /// An `io::Error` whose message is `what` and whose `source` is this parse
    /// failure, so callers can branch on the kind without flattening the cause.
    pub fn into_io(self, kind: io::ErrorKind, what: &'static str) -> io::Error {
        io::Error::new(kind, PolicyIoError { what, source: self })
    }
}

/// Carries a [`ParsePolicyError`] across an `io::Result` boundary.
#[derive(Debug)]
struct PolicyIoError {
    what: &'static str,
    source: ParsePolicyError,
}

impl fmt::Display for PolicyIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)
    }
}

impl std::error::Error for PolicyIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl EndpointDnsPolicy {
    /// Built-in DNS-over-HTTPS servers, then the platform resolver, whose
    /// answer is refused while forged ones are visible on the path.
    pub fn auto() -> Self {
        Self(Strategy::Automatic)
    }

    /// The platform resolver alone; the behaviour before endpoint policies.
    pub fn system() -> Self {
        Self(Strategy::System)
    }

    /// The built-in DNS-over-HTTPS list without a plaintext fallback.
    pub fn encrypted() -> Self {
        Self::from_entries(["encrypted"]).expect("the built-in preset is valid")
    }

    /// Parses policy entries, such as the items of a comma-separated list.
    /// Empty entries are skipped and duplicates are kept once.
    pub fn from_entries<I>(entries: I) -> Result<Self, ParsePolicyError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut resolvers = Vec::new();
        let mut system = false;
        let mut automatic = false;
        for entry in entries {
            let entry = entry.as_ref().trim();
            if entry.is_empty() {
                continue;
            }
            let parsed = match entry.to_ascii_lowercase().as_str() {
                "auto" => {
                    automatic = true;
                    continue;
                }
                "system" => {
                    system = true;
                    continue;
                }
                "encrypted" => ENCRYPTED_PRESET
                    .iter()
                    .map(|url| parse_https(url))
                    .collect::<Result<Vec<_>, _>>()?,
                _ if has_scheme(entry, "https") => vec![parse_https(entry)?],
                _ if has_scheme(entry, "udp") => vec![parse_udp(entry)?],
                _ => {
                    let entry = entry.split_once("://").map_or(entry, |(scheme, _)| scheme);
                    return UnknownEntrySnafu { entry }.fail();
                }
            };
            if system {
                return SystemNotLastSnafu.fail();
            }
            for resolver in parsed {
                if !resolvers.contains(&resolver) {
                    resolvers.push(resolver);
                }
            }
        }
        if automatic {
            return if system || !resolvers.is_empty() {
                AutoNotAloneSnafu.fail()
            } else {
                Ok(Self::auto())
            };
        }
        if resolvers.is_empty() {
            return if system {
                Ok(Self::system())
            } else {
                EmptySnafu.fail()
            };
        }
        if resolvers.len() > MAX_RESOLVERS {
            return TooManySnafu {
                count: resolvers.len(),
            }
            .fail();
        }
        Ok(Self(Strategy::Listed {
            resolvers,
            system_fallback: system,
        }))
    }

    /// Whether the policy is `auto`.
    pub fn is_automatic(&self) -> bool {
        matches!(self.0, Strategy::Automatic)
    }

    /// Whether every lookup goes to the platform resolver.
    pub fn is_system_only(&self) -> bool {
        matches!(self.0, Strategy::System)
    }

    /// Whether the platform resolver answers after the network resolvers fail.
    pub fn has_system_fallback(&self) -> bool {
        match &self.0 {
            Strategy::Automatic => true,
            Strategy::System => false,
            Strategy::Listed {
                system_fallback, ..
            } => *system_fallback,
        }
    }

    /// Whether any listed resolver is reached over plaintext UDP or TCP.
    pub fn has_plaintext_resolvers(&self) -> bool {
        self.listed()
            .iter()
            .any(|resolver| matches!(resolver, Resolver::Udp { .. }))
    }

    /// Whether any listed resolver uses a non-standard query layout.
    pub fn has_experimental_queries(&self) -> bool {
        self.listed().iter().any(|resolver| {
            matches!(
                resolver,
                Resolver::Udp {
                    shape: QueryShape::DualQuestion,
                    ..
                }
            )
        })
    }

    /// The policy in a form [`EndpointDnsSpec::parse`] reads back exactly,
    /// including the URL paths and query strings [`fmt::Display`] hides. It
    /// is for handing the policy to another process.
    pub fn to_spec(&self) -> EndpointDnsSpec {
        // Entries, because a URL may contain the comma that separates them
        // in the text form.
        EndpointDnsSpec::Entries(self.entries(|resolver| match resolver {
            Resolver::Https(url) => url.to_string(),
            Resolver::Udp { .. } => resolver.to_string(),
        }))
    }

    /// The resolvers a list names; none for `auto` and `system`.
    pub(crate) fn listed(&self) -> &[Resolver] {
        match &self.0 {
            Strategy::Automatic | Strategy::System => &[],
            Strategy::Listed { resolvers, .. } => resolvers,
        }
    }

    fn entries(&self, entry: impl Fn(&Resolver) -> String) -> Vec<String> {
        match &self.0 {
            Strategy::Automatic => vec!["auto".to_owned()],
            Strategy::System => vec!["system".to_owned()],
            Strategy::Listed {
                resolvers,
                system_fallback,
            } => resolvers
                .iter()
                .map(entry)
                .chain(system_fallback.then(|| "system".to_owned()))
                .collect(),
        }
    }
}

/// `auto`, except in builds that promise to contact only the resolver the
/// network configures (`no-external-geo`, the Mac App Store edition), where
/// it is `system`.
impl Default for EndpointDnsPolicy {
    fn default() -> Self {
        if cfg!(feature = "no-external-geo") {
            Self::system()
        } else {
            Self::auto()
        }
    }
}

impl FromStr for EndpointDnsPolicy {
    type Err = ParsePolicyError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        Self::from_entries(spec.split(','))
    }
}

/// An endpoint DNS policy as a configuration or another process carries it,
/// not yet checked: the comma-separated text form, or its entries as a list.
///
/// Decoding never fails on the policy itself, so the holder can report what
/// is wrong with it instead of rejecting the whole message. An entry can
/// carry a resolver account token, which is why `Debug` shows none of them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EndpointDnsSpec {
    Text(String),
    Entries(Vec<String>),
}

impl EndpointDnsSpec {
    pub fn parse(&self) -> Result<EndpointDnsPolicy, ParsePolicyError> {
        match self {
            Self::Text(text) => text.parse(),
            Self::Entries(entries) => EndpointDnsPolicy::from_entries(entries),
        }
    }
}

impl fmt::Debug for EndpointDnsSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointDnsSpec(..)")
    }
}

/// Lists resolvers without URL paths or query strings, which can carry
/// account tokens, so the output is safe for logs and banners.
impl fmt::Display for EndpointDnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.entries(Resolver::to_string).join(","))
    }
}

impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Https(url) => {
                write!(f, "https://{}", url.host_str().unwrap_or_default())?;
                match url.port() {
                    Some(port) => write!(f, ":{port}"),
                    None => Ok(()),
                }
            }
            Self::Udp { server, shape } => {
                write!(f, "udp://{server}")?;
                match shape {
                    QueryShape::Standard => Ok(()),
                    QueryShape::DualQuestion => f.write_str("?shape=dual-question"),
                }
            }
        }
    }
}

fn has_scheme(entry: &str, scheme: &str) -> bool {
    entry
        .split_once("://")
        .is_some_and(|(prefix, _)| prefix.eq_ignore_ascii_case(scheme))
}

pub(crate) fn parse_https(entry: &str) -> Result<Resolver, ParsePolicyError> {
    let invalid = |reason: &str| InvalidHttpsSnafu { reason }.build();
    // The parser's message may quote the input, which can hold a token.
    let mut url = Url::parse(entry).map_err(|_| invalid("not an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(invalid("only https:// is accepted"));
    }
    if url.host().is_none() {
        return Err(invalid("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("credentials in the URL are not supported"));
    }
    if url.fragment().is_some() {
        return Err(invalid("the URL has a fragment"));
    }
    if url.path() == "/" {
        url.set_path(DEFAULT_DOH_PATH);
    }
    Ok(Resolver::Https(url))
}

fn parse_udp(entry: &str) -> Result<Resolver, ParsePolicyError> {
    let invalid = |reason| {
        InvalidUdpSnafu {
            entry: entry.to_owned(),
            reason,
        }
        .build()
    };
    let rest = entry.split_once("://").map_or(entry, |(_, rest)| rest);
    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    let server = match authority.parse::<SocketAddr>() {
        Ok(server) => server,
        Err(_) => authority
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, DNS_PORT))
            .map_err(|_| invalid("expected an IP address with an optional port"))?,
    };
    if server.port() == 0 {
        return Err(invalid("port 0 is not a DNS server"));
    }
    if server.ip().is_unspecified() || server.ip().is_multicast() {
        return Err(invalid("the address cannot be a unicast DNS server"));
    }
    let shape = match query {
        "" => QueryShape::Standard,
        "shape=standard" => QueryShape::Standard,
        "shape=dual-question" => QueryShape::DualQuestion,
        _ => return Err(invalid("the only option is shape=standard|dual-question")),
    };
    Ok(Resolver::Udp { server, shape })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn policy(spec: &str) -> EndpointDnsPolicy {
        spec.parse().unwrap()
    }

    #[test]
    fn default_policy_is_automatic_except_in_builds_that_promise_the_network_resolver() {
        let default = EndpointDnsPolicy::default();
        if cfg!(feature = "no-external-geo") {
            assert_eq!(default, EndpointDnsPolicy::system());
        } else {
            assert_eq!(default, EndpointDnsPolicy::auto());
        }
    }

    #[test]
    fn auto_stands_alone_and_may_use_the_system_resolver() {
        let auto = policy(" AUTO ");
        assert_eq!(auto, EndpointDnsPolicy::auto());
        assert!(auto.is_automatic());
        assert!(!auto.is_system_only());
        assert!(auto.has_system_fallback());
        assert!(!auto.has_plaintext_resolvers());
        assert!(!auto.has_experimental_queries());
        assert_eq!(auto.to_string(), "auto");
        assert_eq!(policy("auto,auto"), auto);
        for spec in [
            "auto,system",
            "system,auto",
            "auto,encrypted",
            "https://1.1.1.1,auto",
        ] {
            assert_eq!(
                spec.parse::<EndpointDnsPolicy>(),
                Err(ParsePolicyError::AutoNotAlone),
                "{spec}"
            );
        }
    }

    #[test]
    fn system_alone_is_the_platform_resolver() {
        let system = policy("system");
        assert_eq!(system, EndpointDnsPolicy::system());
        assert!(system.is_system_only());
        assert!(!system.is_automatic());
        assert!(!system.has_system_fallback());
        assert_eq!(system.to_string(), "system");
    }

    #[test]
    fn a_spec_round_trips_what_display_redacts() {
        for entries in [
            vec!["auto"],
            vec!["system"],
            vec![
                "https://dns.example:8443/secret-token?id=1",
                "udp://8.8.8.8:53?shape=dual-question",
                "system",
            ],
            // A comma inside a URL is why the exact form is a list.
            vec!["https://dns.example/dns-query?token=a,b"],
        ] {
            let parsed = EndpointDnsPolicy::from_entries(&entries).unwrap();
            let spec = parsed.to_spec();
            assert_eq!(serde_json::to_value(&spec).unwrap(), json!(entries));
            assert_eq!(spec.parse(), Ok(parsed));
        }
        let encrypted = EndpointDnsPolicy::encrypted();
        assert_eq!(encrypted.to_spec().parse(), Ok(encrypted));
        assert!(
            !policy("https://dns.example/secret-token")
                .to_string()
                .contains("secret")
        );
    }

    #[test]
    fn a_spec_is_text_or_entries_and_is_checked_only_when_parsed() {
        let decode = |value| serde_json::from_value::<EndpointDnsSpec>(value).unwrap();
        assert_eq!(
            decode(json!("encrypted, system")).parse(),
            Ok(policy("encrypted,system"))
        );
        assert_eq!(
            decode(json!(["encrypted", "system"])).parse(),
            Ok(policy("encrypted,system"))
        );
        assert_eq!(
            decode(json!(["auto"])).parse(),
            Ok(EndpointDnsPolicy::auto())
        );
        assert_eq!(
            decode(json!("system,encrypted")).parse(),
            Err(ParsePolicyError::SystemNotLast)
        );
        assert_eq!(decode(json!([])).parse(), Err(ParsePolicyError::Empty));
        assert!(serde_json::from_value::<EndpointDnsSpec>(json!(53)).is_err());

        let secret = decode(json!(["https://dns.example/secret-token"]));
        assert!(!format!("{secret:?}").contains("secret"));
    }

    #[test]
    fn encrypted_preset_alternates_providers_without_plaintext() {
        let encrypted = policy("encrypted");
        assert_eq!(encrypted, EndpointDnsPolicy::encrypted());
        assert_eq!(
            encrypted.to_string(),
            "https://1.1.1.1,https://8.8.8.8,https://[2606:4700:4700::1111],https://[2001:4860:4860::8888]"
        );
        assert!(!encrypted.has_system_fallback());
        assert!(!encrypted.has_plaintext_resolvers());
        assert!(!encrypted.has_experimental_queries());
    }

    #[test]
    fn trailing_system_is_an_explicit_fallback() {
        let fallback = policy(" encrypted , system ");
        assert!(fallback.has_system_fallback());
        assert_eq!(fallback.listed().len(), ENCRYPTED_PRESET.len());
        assert!(fallback.to_string().ends_with(",system"));
    }

    #[test]
    fn system_before_a_network_resolver_is_rejected() {
        assert_eq!(
            "system,encrypted".parse::<EndpointDnsPolicy>(),
            Err(ParsePolicyError::SystemNotLast)
        );
    }

    #[test]
    fn https_entries_keep_their_path_and_hide_it_when_displayed() {
        let custom = policy("HTTPS://dns.example:8443/secret-token?id=1,https://1.1.1.1");
        let Resolver::Https(url) = &custom.listed()[0] else {
            panic!("expected DoH");
        };
        assert_eq!(url.as_str(), "https://dns.example:8443/secret-token?id=1");
        assert_eq!(
            &custom.listed()[1],
            &parse_https("https://1.1.1.1/dns-query").unwrap()
        );
        let shown = custom.to_string();
        assert_eq!(shown, "https://dns.example:8443,https://1.1.1.1");
        assert!(!shown.contains("secret"));
    }

    #[test]
    fn https_entries_reject_plaintext_and_credentials() {
        for (spec, expected) in [
            (
                "http://1.1.1.1/dns-query",
                "unknown endpoint DNS entry `http`",
            ),
            ("https://user:pw@dns.example/dns-query", "credentials"),
            ("https://dns.example/dns-query#frag", "fragment"),
            ("https://", "absolute URL"),
        ] {
            let error = spec.parse::<EndpointDnsPolicy>().unwrap_err().to_string();
            assert!(error.contains(expected), "{spec}: {error}");
            assert!(!error.contains("pw@"), "{spec}: {error}");
        }
    }

    #[test]
    fn udp_entries_need_ip_addresses() {
        let plain = policy("udp://8.8.8.8,udp://[2001:4860:4860::8888]:5353/,udp://9.9.9.9:53");
        assert_eq!(
            plain.listed(),
            [
                Resolver::Udp {
                    server: "8.8.8.8:53".parse().unwrap(),
                    shape: QueryShape::Standard
                },
                Resolver::Udp {
                    server: "[2001:4860:4860::8888]:5353".parse().unwrap(),
                    shape: QueryShape::Standard
                },
                Resolver::Udp {
                    server: "9.9.9.9:53".parse().unwrap(),
                    shape: QueryShape::Standard
                },
            ]
        );
        assert!(plain.has_plaintext_resolvers());
        assert!(!plain.has_experimental_queries());
        for spec in [
            "udp://dns.google",
            "udp://8.8.8.8:0",
            "udp://0.0.0.0",
            "udp://224.0.0.251",
            "udp://8.8.8.8?shape=bogus",
        ] {
            assert!(
                matches!(
                    spec.parse::<EndpointDnsPolicy>(),
                    Err(ParsePolicyError::InvalidUdp { .. })
                ),
                "{spec}"
            );
        }
    }

    #[test]
    fn dual_question_shape_is_opt_in_per_resolver() {
        let experimental = policy("udp://8.8.8.8?shape=dual-question,udp://1.1.1.1");
        assert!(experimental.has_experimental_queries());
        assert_eq!(
            experimental.to_string(),
            "udp://8.8.8.8:53?shape=dual-question,udp://1.1.1.1:53"
        );
        assert_eq!(
            experimental.to_string().parse::<EndpointDnsPolicy>(),
            Ok(experimental)
        );
    }

    #[test]
    fn duplicates_collapse_and_limits_apply() {
        assert_eq!(
            policy("encrypted,https://1.1.1.1/dns-query"),
            policy("encrypted")
        );
        assert_eq!(
            "".parse::<EndpointDnsPolicy>(),
            Err(ParsePolicyError::Empty)
        );
        assert_eq!(
            " , ".parse::<EndpointDnsPolicy>(),
            Err(ParsePolicyError::Empty)
        );
        let many = (1..=9)
            .map(|n| format!("udp://10.0.0.{n}"))
            .collect::<Vec<_>>();
        assert_eq!(
            EndpointDnsPolicy::from_entries(&many),
            Err(ParsePolicyError::TooMany { count: 9 })
        );
        assert!(matches!(
            "dns.google".parse::<EndpointDnsPolicy>(),
            Err(ParsePolicyError::UnknownEntry { .. })
        ));
    }
}
