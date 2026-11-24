//! Names the machine answers for itself: hosts-file pins and local names.
//!
//! Neither is a question for a public resolver. A hosts entry is the user's
//! own answer, and the oldest defence against a polluted one. A name that
//! exists only on the local network would be disclosed to a public resolver
//! for nothing, so the platform resolver keeps those.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::wire::is_routable_endpoint;

/// Hosts files that block advertising run to megabytes, with the entries
/// people write by hand at the top. Reading stops here.
const HOSTS_SCAN_LIMIT: u64 = 8 * 1024 * 1024;

/// Top-level labels that never resolve in the public DNS: special-use names
/// (RFC 6761, 6762, 7686, 9476), `internal`, which ICANN reserved for private
/// use, `home` and `corp`, which it will not delegate, and the common
/// private-network conventions.
const LOCAL_SUFFIXES: [&str; 14] = [
    "alt",
    "corp",
    "example",
    "home",
    "internal",
    "intranet",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "private",
    "test",
];

/// Whether only the local network can resolve `name`: a single label, which
/// the platform completes with its search domains or finds by a local
/// protocol, or a name under a suffix that never exists publicly. `name` is
/// lowercase without the root label.
pub(crate) fn is_local_name(name: &str) -> bool {
    let Some((_, last)) = name.rsplit_once('.') else {
        return true;
    };
    LOCAL_SUFFIXES.contains(&last) || name.ends_with(".home.arpa")
}

/// Where this platform keeps its hosts file.
pub(crate) fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32\\drivers\\etc\\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// The addresses the hosts file at `path` pins for `name`, in file order.
/// `name` is lowercase without the root label. `None` when the file has no
/// usable entry or cannot be read.
pub(crate) async fn hosts_addresses(path: &Path, name: &str) -> Option<Vec<IpAddr>> {
    let (path, name) = (path.to_owned(), name.to_owned());
    // Bounded by HOSTS_SCAN_LIMIT, so it needs no cancellation.
    tokio::task::spawn_blocking(move || scan(File::open(path).ok()?, &name))
        .await
        .ok()
        .flatten()
}

fn scan(hosts: impl Read, name: &str) -> Option<Vec<IpAddr>> {
    let mut lines = BufReader::new(hosts.take(HOSTS_SCAN_LIMIT));
    let mut addresses = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        match lines.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        // Hosts files are ASCII in practice; a line that is not text cannot
        // name this host.
        let Ok(text) = std::str::from_utf8(&line) else {
            continue;
        };
        let entry = text.split('#').next().unwrap_or_default();
        let mut fields = entry.split_ascii_whitespace();
        let Some(address) = fields.next() else {
            continue;
        };
        if !fields.any(|alias| alias.trim_end_matches('.').eq_ignore_ascii_case(name)) {
            continue;
        }
        // An IPv6 zone names a local interface; such an address is link-local
        // and no remote endpoint.
        let Ok(address) = address.parse::<IpAddr>() else {
            continue;
        };
        if is_routable_endpoint(address) && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    (!addresses.is_empty()).then_some(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(addresses: &[&str]) -> Option<Vec<IpAddr>> {
        Some(addresses.iter().map(|ip| ip.parse().unwrap()).collect())
    }

    #[test]
    fn single_labels_and_private_suffixes_are_local() {
        for name in [
            "nas",
            "localhost",
            "printer.local",
            "node.lan",
            "relay.corp",
            "proxy.internal",
            "gw.home.arpa",
            "node.endpoint-dns.test",
            "proxy.example",
        ] {
            assert!(is_local_name(name), "{name}");
        }
    }

    #[test]
    fn public_names_are_not_local_even_when_they_mention_a_private_suffix() {
        for name in [
            "node.example.com",
            "local.example.org",
            "test.dev",
            "home.arpa.example.net",
            "xn--fiqs8s.cn",
        ] {
            assert!(!is_local_name(name), "{name}");
        }
    }

    #[test]
    fn pins_are_read_in_file_order_for_every_alias() {
        let hosts: &[u8] = b"# static table\n\
            127.0.0.1 localhost\n\
            203.0.113.7\tNode.Example.COM node # primary\n\
            2001:db8::7 node.example.com.\n\
            203.0.113.7 node.example.com\n\
            198.51.100.9 other.example.com\n";
        assert_eq!(
            scan(hosts, "node.example.com"),
            ips(&["203.0.113.7", "2001:db8::7"])
        );
        assert_eq!(scan(hosts, "node"), ips(&["203.0.113.7"]));
        assert_eq!(scan(hosts, "localhost"), ips(&["127.0.0.1"]));
        assert_eq!(scan(hosts, "example.com"), None);
        assert_eq!(scan(hosts, "primary"), None);
    }

    #[test]
    fn blocking_entries_and_garbage_are_not_pins() {
        let hosts: &[u8] = b"0.0.0.0 ads.example.com\n\
            :: ads.example.com\n\
            fe80::1%eth0 ads.example.com\n\
            not-an-address ads.example.com\n\
            \xff\xfe ads.example.com\n\
            \n\
            ads.example.com\n";
        assert_eq!(scan(hosts, "ads.example.com"), None);
    }

    #[test]
    fn a_last_line_without_a_newline_still_counts() {
        assert_eq!(
            scan(&b"203.0.113.7 node.example.com"[..], "node.example.com"),
            ips(&["203.0.113.7"])
        );
    }

    #[tokio::test]
    async fn a_missing_file_pins_nothing() {
        let absent = std::env::temp_dir().join("proxy-everything-no-such-hosts-file");
        assert_eq!(hosts_addresses(&absent, "node.example.com").await, None);
    }

    #[test]
    fn scanning_stops_at_the_limit() {
        let mut hosts = vec![b'#'; HOSTS_SCAN_LIMIT as usize];
        hosts.extend_from_slice(b"\n203.0.113.7 node.example.com\n");
        assert_eq!(scan(hosts.as_slice(), "node.example.com"), None);
        let pin = b"203.0.113.7 node.example.com\n";
        hosts.splice(..pin.len(), pin.iter().copied());
        assert_eq!(
            scan(hosts.as_slice(), "node.example.com"),
            ips(&["203.0.113.7"])
        );
    }
}
