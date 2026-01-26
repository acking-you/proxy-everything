//! Address discovery helpers for server startup.

use std::net::{IpAddr, UdpSocket};

use proxy_core::config::{CONTROL_SESSION_KEY, DEFAULT_KEY};

pub(super) fn control_session_key_fallback() -> (Option<String>, bool) {
    if let Some(key) = (*CONTROL_SESSION_KEY).clone() {
        return (Some(key), false);
    }
    if let Ok(key) = std::env::var("SECRET_KEY") {
        return (Some(key), false);
    }
    let default_key = String::from_utf8_lossy(&DEFAULT_KEY.0).to_string();
    (Some(default_key), true)
}

pub(super) fn auto_advertise_addr(host: &str, port: u16) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    if host == "0.0.0.0" || host == "::" || host == "[::]" {
        return None;
    }
    if host == "localhost" {
        return Some(format_ip_addr(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }
    let ip = host.parse::<IpAddr>().ok()?;
    if ip.is_unspecified() {
        return None;
    }
    Some(format_ip_addr(ip, port))
}

pub(super) fn format_ip_addr(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(_) => format!("{}:{}", ip, port),
        IpAddr::V6(_) => format!("[{}]:{}", ip, port),
    }
}

pub(super) fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // This does not send packets, but lets the OS pick an outbound interface.
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip();
    if ip.is_unspecified() { None } else { Some(ip) }
}

/// Detect public IP by querying external services.
pub(super) fn detect_public_ip() -> Option<IpAddr> {
    const SERVICES: &[&str] = &[
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    let agent = ureq::Agent::new_with_defaults();
    for url in SERVICES {
        if let Ok(body) = agent
            .get(*url)
            .call()
            .and_then(|mut r| r.body_mut().read_to_string())
            && let Ok(ip) = body.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}

pub(super) fn parse_addr_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}
