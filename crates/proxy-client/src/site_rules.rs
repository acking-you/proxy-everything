//! Per-website routes the user chose, independent of the default upstream.
//!
//! Each new TCP stream matches one immutable snapshot before it opens its
//! outbound connection, so an edit affects later connections only.
use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{fmt, fs};

use arc_swap::ArcSwap;
use proxy_core::upstream::UpstreamAddress;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

/// Most rules one profile holds.
pub const MAX_RULES: usize = 256;
/// Longest node ID a rule can name.
const MAX_NODE_ID_BYTES: usize = 256;
/// A rules file is refused before decoding when it is larger than this.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

const _: () = assert!(
    MAX_FILE_BYTES as usize >= MAX_RULES * 1024,
    "a full rule set, at under 1 KiB per rule, must fit in the file limit",
);

#[derive(Debug, Snafu)]
#[snafu(display(
    "Use a domain, *.domain, IP address or HTTP(S) URL, with an optional nonzero port"
))]
pub struct InvalidSite;

/// Where a rule applies: one host, or every subdomain of one, optionally on a
/// single port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Site {
    /// Lowercase ASCII domain or canonical IP address, without brackets.
    host: String,
    /// `*.host`: children at any depth, not the host itself.
    subdomains: bool,
    port: Option<NonZeroU16>,
}

impl FromStr for Site {
    type Err = InvalidSite;

    /// Accepts `example.com`, `*.example.com`, either with `:port`, an IP
    /// address, or an HTTP(S) URL whose host and effective port are kept.
    fn from_str(input: &str) -> Result<Self, InvalidSite> {
        let input = input.trim();
        let (is_url, authority) = match input.split_once("://") {
            Some((_, rest)) => (true, rest),
            None => (false, input),
        };
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        // Credentials and raw percent-escapes never belong in a rule, and a
        // backslash is a path separator to some parsers but not to others.
        if authority.is_empty()
            || authority.contains(['@', '%'])
            || input.contains('\\')
            || input.contains(char::is_whitespace)
        {
            return Err(InvalidSite);
        }
        // A scheme that is not special leaves the host opaque, so `*.` survives
        // parsing and a bare host gets no default port; non-ASCII labels are
        // percent-encoded there and decoded back before IDNA mapping below.
        let parsed = url::Url::parse(&if is_url {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(format!("site://{input}"))
        })
        .map_err(|_| InvalidSite)?;
        let shape_ok = if is_url {
            matches!(parsed.scheme(), "http" | "https")
        } else {
            parsed.path().is_empty() && parsed.query().is_none() && parsed.fragment().is_none()
        };
        if !shape_ok {
            return Err(InvalidSite);
        }
        let raw = parsed.host_str().ok_or(InvalidSite)?.trim_end_matches('.');
        let decoded = percent_encoding::percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| InvalidSite)?;
        let (subdomains, raw) = match decoded.strip_prefix("*.") {
            Some(suffix) => (true, suffix),
            None => (false, decoded.as_ref()),
        };
        let host = match url::Host::parse(raw).map_err(|_| InvalidSite)? {
            url::Host::Domain(domain) if is_dns_name(&domain) => domain,
            url::Host::Ipv4(ip) if !subdomains => ip.to_string(),
            url::Host::Ipv6(ip) if !subdomains => ip.to_string(),
            _ => return Err(InvalidSite),
        };
        let port = parsed
            .port_or_known_default()
            .map(|port| NonZeroU16::new(port).ok_or(InvalidSite))
            .transpose()?;
        Ok(Self {
            host,
            subdomains,
            port,
        })
    }
}

fn is_dns_name(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl TryFrom<String> for Site {
    type Error = InvalidSite;

    fn try_from(input: String) -> Result<Self, InvalidSite> {
        input.parse()
    }
}

impl From<Site> for String {
    fn from(site: Site) -> Self {
        site.to_string()
    }
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.subdomains {
            f.write_str("*.")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

impl Site {
    /// `host` must already be normalized as [`normalize_host`] does.
    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p.get() != port) {
            return false;
        }
        if !self.subdomains {
            return self.host.eq_ignore_ascii_case(host);
        }
        host.len()
            .checked_sub(self.host.len())
            .and_then(|start| host.split_at_checked(start))
            .is_some_and(|(prefix, suffix)| {
                prefix.ends_with('.') && suffix.eq_ignore_ascii_case(&self.host)
            })
    }

    /// Larger is more specific: an exact host beats a suffix, a longer suffix
    /// beats a shorter one, and a port-qualified rule beats one without.
    fn specificity(&self) -> (bool, usize, bool) {
        (!self.subdomains, self.host.len(), self.port.is_some())
    }
}

/// The host as a client supplied it, in the form rules store.
fn normalize_host(host: &str) -> Option<Cow<'_, str>> {
    let host = host.trim_end_matches('.');
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::Ipv6Addr>() {
        return Some(Cow::Owned(ip.to_string()));
    }
    if host.is_ascii() {
        return Some(Cow::Borrowed(host));
    }
    url::Host::parse(host)
        .ok()
        .map(|host| Cow::Owned(host.to_string()))
}

#[derive(Debug, Snafu)]
#[snafu(display("A node ID is 1 to {MAX_NODE_ID_BYTES} bytes with a visible character"))]
pub struct InvalidNodeId;

/// A catalogue node's identity, as its server reports it or a CLI profile
/// declares it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId(String);

impl TryFrom<String> for NodeId {
    type Error = InvalidNodeId;

    fn try_from(id: String) -> Result<Self, InvalidNodeId> {
        if id.trim().is_empty() || id.len() > MAX_NODE_ID_BYTES {
            return Err(InvalidNodeId);
        }
        Ok(Self(id))
    }
}

impl From<NodeId> for String {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl NodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a matching connection does instead of following the default route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Target {
    Direct,
    /// The endpoint is pinned when the rule is saved, so a later catalogue
    /// change does not silently move the website to another address.
    Node {
        node_id: NodeId,
        #[serde(flatten)]
        endpoint: UpstreamAddress,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub site: Site,
    pub target: Target,
}

/// The rules of one profile, sorted by site with no site twice. The file and
/// the controller API share this shape: `{"rules": [{"site", "target"}]}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRuleSet")]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct RawRuleSet {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Snafu)]
pub enum InvalidRuleSet {
    #[snafu(display("A profile holds at most {MAX_RULES} website rules"))]
    TooMany,
    #[snafu(display("{site} has more than one rule"))]
    Duplicate { site: Site },
}

impl TryFrom<RawRuleSet> for RuleSet {
    type Error = InvalidRuleSet;

    fn try_from(RawRuleSet { mut rules }: RawRuleSet) -> Result<Self, InvalidRuleSet> {
        if rules.len() > MAX_RULES {
            return TooManySnafu.fail();
        }
        rules.sort_by(|a, b| a.site.cmp(&b.site));
        if let Some(pair) = rules.windows(2).find(|pair| pair[0].site == pair[1].site) {
            return DuplicateSnafu {
                site: pair[0].site.clone(),
            }
            .fail();
        }
        Ok(Self { rules })
    }
}

impl RuleSet {
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The most specific rule for a destination, if any.
    pub fn resolve(&self, host: &str, port: u16) -> Option<&Target> {
        if self.rules.is_empty() {
            return None;
        }
        let host = normalize_host(host)?;
        self.rules
            .iter()
            .filter(|rule| rule.site.matches(&host, port))
            .max_by_key(|rule| rule.site.specificity())
            .map(|rule| &rule.target)
    }

    fn set(&mut self, rule: Rule) -> Result<(), InvalidRuleSet> {
        match self.rules.binary_search_by(|r| r.site.cmp(&rule.site)) {
            Ok(index) => self.rules[index] = rule,
            Err(_) if self.rules.len() >= MAX_RULES => return TooManySnafu.fail(),
            Err(index) => self.rules.insert(index, rule),
        }
        Ok(())
    }

    fn remove(&mut self, site: &Site) {
        self.rules.retain(|rule| rule.site != *site);
    }
}

#[derive(Debug, Snafu)]
pub enum RulesError {
    #[snafu(display("Could not read website rules from {}", path.display()))]
    Read { path: PathBuf, source: io::Error },
    #[snafu(display("{} exceeds the website rules size limit", path.display()))]
    TooLarge { path: PathBuf },
    #[snafu(display("Website rules in {} are malformed", path.display()))]
    Decode {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[snafu(display("Could not save website rules to {}", path.display()))]
    Write { path: PathBuf, source: io::Error },
    #[snafu(transparent)]
    Invalid { source: InvalidRuleSet },
}

/// A profile's rules file and the snapshot that new connections match.
///
/// This process owns the file while the store is open: edits start from the
/// published snapshot and replace the file atomically before publishing.
#[derive(Debug)]
pub struct SiteRules {
    path: PathBuf,
    current: ArcSwap<RuleSet>,
    /// Serializes edits so each one starts from the previous result.
    edits: Mutex<()>,
}

impl SiteRules {
    /// Load the rules at `path`; a missing file is an empty rule set.
    pub fn open(path: PathBuf) -> Result<Self, RulesError> {
        let rules = read(&path)?;
        Ok(Self {
            path,
            current: ArcSwap::from_pointee(rules),
            edits: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> Arc<RuleSet> {
        self.current.load_full()
    }

    pub fn resolve(&self, host: &str, port: u16) -> Option<Target> {
        self.current.load().resolve(host, port).cloned()
    }

    /// Add or replace the rule for its site. Blocks on file I/O.
    pub fn set(&self, rule: Rule) -> Result<Arc<RuleSet>, RulesError> {
        self.replace(None, rule)
    }

    /// Replace `previous` (when different from `rule.site`) and save `rule` in
    /// one atomic update. Blocks on file I/O.
    pub fn replace(&self, previous: Option<&Site>, rule: Rule) -> Result<Arc<RuleSet>, RulesError> {
        self.edit(|rules| {
            if let Some(previous) = previous
                && previous != &rule.site
            {
                rules.remove(previous);
            }
            rules.set(rule)
        })
    }

    /// Remove the rule for `site`, if there is one. Blocks on file I/O.
    pub fn remove(&self, site: &Site) -> Result<Arc<RuleSet>, RulesError> {
        self.edit(|rules| {
            rules.remove(site);
            Ok(())
        })
    }

    fn edit(
        &self,
        change: impl FnOnce(&mut RuleSet) -> Result<(), InvalidRuleSet>,
    ) -> Result<Arc<RuleSet>, RulesError> {
        let _edit = self.edits.lock().unwrap_or_else(|p| p.into_inner());
        let mut rules = RuleSet::clone(&self.current.load());
        change(&mut rules)?;
        write(&self.path, &rules)?;
        let rules = Arc::new(rules);
        self.current.store(rules.clone());
        Ok(rules)
    }
}

fn read(path: &Path) -> Result<RuleSet, RulesError> {
    let file = match fs::File::open(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(RuleSet::default()),
        opened => opened.context(ReadSnafu { path })?,
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context(ReadSnafu { path })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return TooLargeSnafu { path }.fail();
    }
    serde_json::from_slice(&bytes).context(DecodeSnafu { path })
}

fn write(path: &Path, rules: &RuleSet) -> Result<(), RulesError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(directory).context(WriteSnafu { path })?;
    let mut file = tempfile::NamedTempFile::new_in(directory).context(WriteSnafu { path })?;
    serde_json::to_writer_pretty(&mut file, rules)
        .map_err(io::Error::from)
        .context(WriteSnafu { path })?;
    file.write_all(b"\n").context(WriteSnafu { path })?;
    file.as_file().sync_all().context(WriteSnafu { path })?;
    file.persist(path)
        .map_err(|error| error.error)
        .context(WriteSnafu { path })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use proxy_core::upstream::Carrier;

    use super::*;

    fn site(input: &str) -> Site {
        input.parse().unwrap()
    }

    fn node(id: &str, address: &str) -> Target {
        Target::Node {
            node_id: id.to_owned().try_into().unwrap(),
            endpoint: UpstreamAddress::parse(address).unwrap(),
        }
    }

    #[test]
    fn sites_normalize_urls_wildcards_and_ports() {
        assert_eq!(site(" *.Example.COM. ").to_string(), "*.example.com");
        assert_eq!(
            site("https://API.example.com/@docs?q=private").to_string(),
            "api.example.com:443"
        );
        assert_eq!(site("[2001:DB8::1]:8443").to_string(), "[2001:db8::1]:8443");
        assert_eq!(
            site("B\u{fc}cher.Example").to_string(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            site("*.B\u{fc}cher.Example:8443").to_string(),
            "*.xn--bcher-kva.example:8443"
        );
        for invalid in [
            "",
            "ftp://example.com",
            "example.com/path",
            "user@example.com",
            "bad%20host.example.com",
            "example%2ecom",
            "https://example%20bad.com/",
            "*.10.0.0.1",
            "example.com:0",
            "-bad-.example.com",
        ] {
            assert!(invalid.parse::<Site>().is_err(), "{invalid} parsed");
        }
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let mut rules = RuleSet::default();
        rules
            .set(Rule {
                site: site("*.example.com"),
                target: Target::Direct,
            })
            .unwrap();
        rules
            .set(Rule {
                site: site("*.api.example.com"),
                target: node("west", "tcp://west.example:1081"),
            })
            .unwrap();
        rules
            .set(Rule {
                site: site("v1.api.example.com:443"),
                target: node("east", "quic://east.example:10811"),
            })
            .unwrap();
        let resolve = |host, port| match rules.resolve(host, port) {
            Some(Target::Node { node_id, .. }) => Some(node_id.as_str()),
            Some(Target::Direct) => Some("direct"),
            None => None,
        };
        assert_eq!(resolve("V1.Api.Example.com.", 443), Some("east"));
        assert_eq!(resolve("v1.api.example.com", 80), Some("west"));
        assert_eq!(resolve("cdn.example.com", 80), Some("direct"));
        assert_eq!(resolve("example.com", 443), None);
        assert_eq!(resolve("notexample.com", 443), None);
    }

    #[test]
    fn edits_replace_the_file_and_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile").join("rules.json");
        let store = SiteRules::open(path.clone()).unwrap();
        store
            .set(Rule {
                site: site("https://api.example.com/private?token=secret"),
                target: node("west", "quic://west.example:10811"),
            })
            .unwrap();
        store
            .set(Rule {
                site: site("*.example.com"),
                target: Target::Direct,
            })
            .unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("secret"));

        let reopened = SiteRules::open(path.clone()).unwrap();
        assert_eq!(reopened.snapshot(), store.snapshot());
        assert!(matches!(
            reopened.resolve("api.example.com", 443),
            Some(Target::Node { endpoint, .. }) if endpoint.carrier == Carrier::Quic && endpoint.port == 10811
        ));

        store.remove(&site("api.example.com:443")).unwrap();
        assert_eq!(store.resolve("api.example.com", 443), Some(Target::Direct));
        assert_eq!(SiteRules::open(path).unwrap().snapshot().rules().len(), 1);
    }

    #[test]
    fn replacing_a_rule_renames_its_site_atomically_at_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rules.json");
        let store = SiteRules::open(path).unwrap();
        for index in 0..MAX_RULES {
            store
                .set(Rule {
                    site: site(&format!("host-{index}.example.com")),
                    target: Target::Direct,
                })
                .unwrap();
        }
        assert!(matches!(
            store.set(Rule {
                site: site("overflow.example.com"),
                target: Target::Direct,
            }),
            Err(RulesError::Invalid {
                source: InvalidRuleSet::TooMany
            })
        ));
        let previous = site("host-0.example.com");
        store
            .replace(
                Some(&previous),
                Rule {
                    site: site("*.host-0.example.com"),
                    target: Target::Direct,
                },
            )
            .unwrap();
        assert_eq!(store.snapshot().rules().len(), MAX_RULES);
        assert!(store.resolve("host-0.example.com", 443).is_none());
        assert_eq!(
            store.resolve("sub.host-0.example.com", 443),
            Some(Target::Direct)
        );
    }

    #[test]
    fn a_failed_save_keeps_the_published_rules() {
        let directory = tempfile::tempdir().unwrap();
        // A directory where the file belongs makes the final rename fail.
        let path = directory.path().join("rules.json");
        let store = SiteRules::open(path.clone()).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("occupied"), b"").unwrap();
        assert!(matches!(
            store.set(Rule {
                site: site("example.com"),
                target: Target::Direct,
            }),
            Err(RulesError::Write { .. })
        ));
        assert!(store.snapshot().rules().is_empty());
        assert!(store.resolve("example.com", 80).is_none());
    }

    #[test]
    fn malformed_or_duplicate_files_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rules.json");
        fs::write(&path, "{").unwrap();
        assert!(matches!(
            SiteRules::open(path.clone()),
            Err(RulesError::Decode { .. })
        ));
        let rule = r#"{"site":"example.com","target":{"action":"direct"}}"#;
        fs::write(&path, format!(r#"{{"rules":[{rule},{rule}]}}"#)).unwrap();
        assert!(matches!(
            SiteRules::open(path),
            Err(RulesError::Decode { .. })
        ));
    }
}
