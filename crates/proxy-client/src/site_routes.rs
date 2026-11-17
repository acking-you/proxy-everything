//! Website policies are independent of the default upstream. Each new TCP
//! flow matches one immutable snapshot before opening its outbound stream.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::{fmt, fs};

use arc_swap::ArcSwap;
use proxy_core::upstream::{Carrier, UpstreamAddress};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snafu::{ResultExt, Snafu};

use crate::controller::NodeId;

const MAX_RULES: usize = 256;
const MAX_FILE: u64 = 1024 * 1024;

#[derive(Debug, Snafu)]
#[snafu(display(
    "Use a website domain, *.domain, IP address or HTTP(S) URL with an optional nonzero port"
))]
pub struct InvalidSite;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Site {
    host: String,
    subdomains: bool,
    port: Option<NonZeroU16>,
}

impl TryFrom<String> for Site {
    type Error = InvalidSite;

    fn try_from(input: String) -> Result<Self, InvalidSite> {
        let input = input.trim();
        let authority = input
            .split_once("://")
            .map_or(input, |(_, rest)| rest)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.is_empty()
            || authority.contains('@')
            || input.contains('\\')
            || input.chars().any(char::is_whitespace)
        {
            return Err(InvalidSite);
        }
        let is_url = input.contains("://");
        let parsed = if is_url {
            url::Url::parse(input)
        } else {
            url::Url::parse(&format!("site://{input}"))
        }
        .map_err(|_| InvalidSite)?;
        if (is_url && !matches!(parsed.scheme(), "http" | "https"))
            || (!is_url
                && (!parsed.path().is_empty()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()))
        {
            return Err(InvalidSite);
        }
        let raw = parsed.host_str().ok_or(InvalidSite)?.trim_end_matches('.');
        let subdomains = raw.starts_with("*.");
        let raw = raw.strip_prefix("*.").unwrap_or(raw);
        let host = match url::Host::parse(raw).map_err(|_| InvalidSite)? {
            url::Host::Domain(domain)
                if domain.len() <= 253
                    && domain.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }) =>
            {
                domain
            }
            url::Host::Ipv4(ip) if !subdomains => ip.to_string(),
            url::Host::Ipv6(ip) if !subdomains => ip.to_string(),
            _ => return Err(InvalidSite),
        };
        let port = parsed
            .port_or_known_default()
            .map(|p| NonZeroU16::new(p).ok_or(InvalidSite))
            .transpose()?;
        Ok(Self {
            host,
            subdomains,
            port,
        })
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

impl From<Site> for String {
    fn from(site: Site) -> Self {
        site.to_string()
    }
}

impl Site {
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Target {
    Direct,
    Node {
        node_id: NodeId,
        #[serde(with = "address")]
        endpoint: UpstreamAddress,
    },
}

mod address {
    use super::*;
    pub fn serialize<S: serde::Serializer>(a: &UpstreamAddress, s: S) -> Result<S::Ok, S::Error> {
        let scheme = match a.carrier {
            Carrier::Tcp => "tcp",
            Carrier::Quic => "quic",
        };
        let host = if a.host.contains(':') {
            format!("[{}]", a.host)
        } else {
            a.host.clone()
        };
        s.serialize_str(&format!("{scheme}://{host}:{}", a.port))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<UpstreamAddress, D::Error> {
        UpstreamAddress::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Snafu)]
pub enum StoreError {
    #[snafu(display("Could not access website rules in {}", path.display()))]
    File { path: PathBuf, source: io::Error },
    #[snafu(display("Could not decode website rules in {}", path.display()))]
    Decode {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[snafu(display("Could not encode website rules"))]
    Encode { source: serde_json::Error },
    #[snafu(display("Website rule limit exceeded"))]
    Limit,
    #[snafu(display("Website rules are being updated by another process"))]
    Busy,
}

type Rules = BTreeMap<Site, Target>;

pub struct Store {
    path: PathBuf,
    rules: ArcSwap<Rules>,
    mutation: Mutex<()>,
}

impl Store {
    pub fn open(path: PathBuf) -> Result<Self, StoreError> {
        let rules = Self::read(&path)?;
        Ok(Self {
            path,
            rules: ArcSwap::from_pointee(rules),
            mutation: Mutex::new(()),
        })
    }

    fn read(path: &Path) -> Result<Rules, StoreError> {
        let file = match fs::File::open(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Rules::new()),
            open => open.context(FileSnafu { path })?,
        };
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .context(FileSnafu { path })?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(StoreError::Limit);
        }
        let rules: Rules = serde_json::from_slice(&bytes).context(DecodeSnafu { path })?;
        if rules.len() > MAX_RULES {
            return Err(StoreError::Limit);
        }
        Ok(rules)
    }

    pub fn resolve(&self, host: &str, port: u16) -> Option<Target> {
        let rules = self.rules.load();
        if rules.is_empty() {
            return None;
        }
        let host = host.trim_end_matches('.');
        let canonical;
        let host = if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            canonical = ip.to_string();
            &canonical
        } else if !host.is_ascii() {
            canonical = url::Host::parse(host).ok()?.to_string();
            &canonical
        } else {
            host
        };
        rules
            .iter()
            .filter(|(s, _)| s.matches(host, port))
            .max_by_key(|(s, _)| (!s.subdomains, s.host.len(), s.port.is_some()))
            .map(|(_, target)| target.clone())
    }

    pub fn view(&self) -> Value {
        let rules = self.rules.load();
        let rows: Vec<_> = rules
            .iter()
            .map(|(site, target)| {
                let target = match target {
                    Target::Direct => json!({"action":"direct"}),
                    Target::Node { node_id, endpoint } => json!({"action":"node","node_id":node_id,
                    "host":endpoint.host, "port":endpoint.port, "transport":endpoint.carrier}),
                };
                json!({"site":site, "target":target})
            })
            .collect();
        json!({"rules":rows})
    }

    /// Call on a blocking worker. Read under the file lock so independent
    /// processes sharing a profile cannot overwrite one another's edits.
    pub fn update(&self, site: Site, target: Option<Target>) -> Result<Value, StoreError> {
        let _guard = self.mutation.lock().unwrap_or_else(|p| p.into_inner());
        let path = self.path.as_path();
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(dir).context(FileSnafu { path: dir })?;
        let lock_path = path.with_added_extension("lock");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .context(FileSnafu { path: &lock_path })?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(StoreError::Busy),
            Err(fs::TryLockError::Error(source)) => {
                return Err(StoreError::File {
                    path: lock_path,
                    source,
                });
            }
        }
        let result = self.update_locked(site, target, dir);
        // A concurrently spawned child can briefly inherit the open description
        // on Unix. Release the advisory lock before closing our descriptor.
        if let Err(error) = lock.unlock() {
            tracing::warn!(?error, "could not explicitly unlock the website rules file");
        }
        result
    }

    fn update_locked(
        &self,
        site: Site,
        target: Option<Target>,
        dir: &Path,
    ) -> Result<Value, StoreError> {
        let path = self.path.as_path();
        let mut rules = Self::read(path)?;
        if let Some(target) = target {
            rules.insert(site, target);
        } else {
            rules.remove(&site);
        }
        if rules.len() > MAX_RULES {
            return Err(StoreError::Limit);
        }
        let bytes = serde_json::to_vec_pretty(&rules).context(EncodeSnafu)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(StoreError::Limit);
        }
        let mut tmp = tempfile::NamedTempFile::new_in(dir).context(FileSnafu { path: dir })?;
        tmp.write_all(&bytes).context(FileSnafu { path })?;
        tmp.as_file().sync_all().context(FileSnafu { path })?;
        tmp.persist(path)
            .map_err(|err| err.error)
            .context(FileSnafu { path })?;
        self.rules.store(rules.into());
        Ok(self.view())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_port_beats_subdomain_and_edits_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let store = Store::open(path.clone()).unwrap();
        let wildcard = Site::try_from("*.Example.com".to_owned()).unwrap();
        store
            .update(wildcard.clone(), Some(Target::Direct))
            .unwrap();
        let site = Site::try_from("https://API.example.com/@docs?q=private".to_owned()).unwrap();
        let endpoint = UpstreamAddress::parse("quic://node.example:10811").unwrap();
        let target = Target::Node {
            node_id: "west".to_owned().try_into().unwrap(),
            endpoint,
        };
        store.update(site.clone(), Some(target)).unwrap();
        let reopened = Store::open(path.clone()).unwrap();
        assert!(
            matches!(reopened.resolve("Api.Example.com.", 443), Some(Target::Node { endpoint, .. }) if endpoint.carrier == Carrier::Quic)
        );
        assert!(matches!(
            reopened.resolve("api.example.com", 80),
            Some(Target::Direct)
        ));
        assert!(reopened.resolve("example.com", 443).is_none());
        assert!(reopened.resolve("notexample.com", 80).is_none());
        assert!(!fs::read_to_string(&path).unwrap().contains("private"));
        store.update(site, None).unwrap();
        assert!(matches!(
            store.resolve("api.example.com", 443),
            Some(Target::Direct)
        ));
        fs::write(&path, "{").unwrap();
        assert!(store.update(wildcard, None).is_err());
        assert!(matches!(
            store.resolve("api.example.com", 443),
            Some(Target::Direct)
        ));
    }
}
