//! Endpoint resolver configuration and its text form.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

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
const ENCRYPTED_PRESET: [&str; 4] = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://[2606:4700:4700::1111]/dns-query",
    "https://[2001:4860:4860::8888]/dns-query",
];

/// How the client resolves the remote proxy endpoints it dials before any
/// tunnel exists: native nodes, relay targets and external upstream proxies.
///
/// The text form is a comma-separated list. `https://` entries are
/// DNS-over-HTTPS servers, `udp://` entries plaintext servers given by IP
/// address, `encrypted` expands to a built-in DoH list, and `system` is the
/// platform resolver. Network entries are raced; a trailing `system` is
/// consulted only after all of them fail, and without it a failure is
/// returned instead of a plaintext answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointDnsPolicy {
    resolvers: Vec<Resolver>,
    system_fallback: bool,
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
        "unknown endpoint DNS entry `{entry}`; expected system, encrypted, https://… or udp://…"
    ))]
    UnknownEntry { entry: String },
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

impl EndpointDnsPolicy {
    /// The platform resolver alone; the behaviour before endpoint policies.
    pub fn system() -> Self {
        Self::default()
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
        let mut any = false;
        for entry in entries {
            let entry = entry.as_ref().trim();
            if entry.is_empty() {
                continue;
            }
            any = true;
            let parsed = match entry.to_ascii_lowercase().as_str() {
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
        if !any {
            return EmptySnafu.fail();
        }
        if resolvers.len() > MAX_RESOLVERS {
            return TooManySnafu {
                count: resolvers.len(),
            }
            .fail();
        }
        Ok(Self {
            system_fallback: system && !resolvers.is_empty(),
            resolvers,
        })
    }

    /// Whether every lookup goes to the platform resolver.
    pub fn is_system_only(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Whether the platform resolver answers after the network resolvers fail.
    pub fn has_system_fallback(&self) -> bool {
        self.system_fallback
    }

    /// Whether any network resolver is reached over plaintext UDP or TCP.
    pub fn has_plaintext_resolvers(&self) -> bool {
        self.resolvers
            .iter()
            .any(|resolver| matches!(resolver, Resolver::Udp { .. }))
    }

    /// Whether any resolver uses a non-standard query layout.
    pub fn has_experimental_queries(&self) -> bool {
        self.resolvers.iter().any(|resolver| {
            matches!(
                resolver,
                Resolver::Udp {
                    shape: QueryShape::DualQuestion,
                    ..
                }
            )
        })
    }

    pub(crate) fn resolvers(&self) -> &[Resolver] {
        &self.resolvers
    }
}

impl FromStr for EndpointDnsPolicy {
    type Err = ParsePolicyError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        Self::from_entries(spec.split(','))
    }
}

/// Lists resolvers without URL paths or query strings, which can carry
/// account tokens, so the output is safe for logs and banners.
impl fmt::Display for EndpointDnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, resolver) in self.resolvers.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{resolver}")?;
        }
        if self.resolvers.is_empty() {
            f.write_str("system")
        } else if self.system_fallback {
            f.write_str(",system")
        } else {
            Ok(())
        }
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

fn parse_https(entry: &str) -> Result<Resolver, ParsePolicyError> {
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
    use super::*;

    fn policy(spec: &str) -> EndpointDnsPolicy {
        spec.parse().unwrap()
    }

    #[test]
    fn default_policy_is_the_system_resolver() {
        let default = EndpointDnsPolicy::default();
        assert!(default.is_system_only());
        assert!(!default.has_system_fallback());
        assert_eq!(default, policy("system"));
        assert_eq!(default.to_string(), "system");
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
        assert_eq!(fallback.resolvers().len(), ENCRYPTED_PRESET.len());
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
        let Resolver::Https(url) = &custom.resolvers()[0] else {
            panic!("expected DoH");
        };
        assert_eq!(url.as_str(), "https://dns.example:8443/secret-token?id=1");
        assert_eq!(
            &custom.resolvers()[1],
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
            plain.resolvers(),
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
