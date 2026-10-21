//! Host rules shared by the router, launchers and validation. A rule is a
//! host, an IP literal, a `.domain` suffix or a `*` glob; never a URL, port or
//! anything a shell or Chromium could read as an option.

pub const DEFAULT_RULES: [&str; 3] = ["*oa*", ".oa.com", ".woa.com"];
const MAX_RULES: usize = 200;

pub fn valid_rule(rule: &str) -> bool {
    !rule.is_empty()
        && rule.len() <= 253
        && rule
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"*._-[]:".contains(&b))
        && rule != "."
        && !rule.contains("..")
        && (!rule.contains(':') || rule == "::1" || rule == "[::1]")
}

pub fn valid_rules(rules: &[String]) -> bool {
    rules.len() <= MAX_RULES && rules.iter().all(|rule| valid_rule(rule))
}

/// Trimmed, lower-cased and de-duplicated, keeping the user's order.
pub fn normalize(rules: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    rules
        .iter()
        .map(|rule| rule.trim().to_ascii_lowercase())
        .filter(|rule| !rule.is_empty() && seen.insert(rule.clone()))
        .collect()
}

pub fn valid_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.chars().count() <= 80
        && !name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
}

/// Whether a request to `host` skips the upstream proxy. Loopback always does.
pub fn bypasses(rules: &[String], host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }
    rules.iter().any(|rule| {
        if rule == "[::1]" {
            host == "::1"
        } else if let Some(domain) = rule.strip_prefix('.') {
            host == domain || host.ends_with(rule.as_str())
        } else {
            glob(rule.as_bytes(), host.as_bytes())
        }
    })
}

/// `*`-only globbing without backtracking blow-up on many stars.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if let Some(position) = star {
            p = position + 1;
            retry += 1;
            t = retry;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

/// Chromium's `--proxy-bypass-list`. A leading dot means the domain and its
/// subdomains here; Chromium would read it as subdomains only.
pub fn chromium_bypass_list(rules: &[String]) -> Vec<String> {
    let mut list = vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()];
    for rule in rules {
        if rule == "::1" {
            list.push("[::1]".into());
        } else if let Some(domain) = rule.strip_prefix('.') {
            list.push(domain.into());
            list.push(format!("*{rule}"));
        } else {
            list.push(rule.clone());
        }
    }
    list
}

/// Whether backend clients receive `rule` through `NO_PROXY`.
pub fn applies_to_environment(rule: &str) -> bool {
    !rule.contains('*') || rule == "*" || (rule.starts_with("*.") && !rule[1..].contains('*'))
}

/// `NO_PROXY` has no portable arbitrary glob, so `*oa*` is left out rather
/// than passed on with a meaning clients would each read differently.
pub fn environment_bypass_list(rules: &[String]) -> Vec<String> {
    let mut list = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for rule in rules.iter().filter(|rule| applies_to_environment(rule)) {
        list.push(match rule.as_str() {
            "[::1]" => "::1".into(),
            "*" => "*".into(),
            _ => rule.strip_prefix('*').unwrap_or(rule).into(),
        });
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn rules_reject_urls_and_option_injection_and_keep_wildcard_intent() {
        assert_eq!(
            normalize(&rules(&[" *OA* ", ".woa.com", "*oa*", ""])),
            ["*oa*", ".woa.com"]
        );
        assert!(valid_rules(&rules(&[
            "*oa*", ".woa.com", "10.0.0.1", "[::1]"
        ])));
        for invalid in [
            "https://oa.com/path",
            "oa.com;--proxy-server=evil",
            "$(touch /tmp/unwanted)",
            "host:8080",
            "a..b",
            ".",
        ] {
            assert!(!valid_rule(invalid), "{invalid}");
        }
        assert!(!valid_name("../escape"));
        assert!(valid_name("Codex 代理启动器"));
    }

    #[test]
    fn matching_and_launcher_lists_follow_each_consumer() {
        let defaults = rules(&DEFAULT_RULES);
        assert!(bypasses(&defaults, "Portal.OA.Example"));
        assert!(bypasses(&defaults, "oa.com"));
        assert!(bypasses(&defaults, "x.woa.com."));
        assert!(bypasses(&[], "[::1]"));
        assert!(!bypasses(&defaults, "EXAMPLE.COM"));
        assert!(bypasses(&rules(&["*"]), "any.invalid"));
        assert!(bypasses(&rules(&["a*b*c*d*e*f"]), "aXbXcXdXeXf"));
        assert!(!bypasses(&rules(&["a*b*c*d*e*f"]), &"ab".repeat(200)));
        assert_eq!(
            chromium_bypass_list(&defaults).join(";"),
            "localhost;127.0.0.1;[::1];*oa*;oa.com;*.oa.com;woa.com;*.woa.com"
        );
        assert_eq!(
            environment_bypass_list(&rules(&["*oa*", ".oa.com", "*.corp.example", "[::1]"]))
                .join(","),
            "localhost,127.0.0.1,::1,.oa.com,.corp.example,::1"
        );
    }
}
