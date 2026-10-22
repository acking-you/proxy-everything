//! Session-owned routing for kernel-exempt Network Extension sockets.
//!
//! Fake DNS retains hostnames for the proxy. Classification resolves through
//! authenticated DoH outside the tunnel, and direct connections use exactly the
//! classified IPs (never the system resolver or a fake address).
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use moka::sync::Cache;
use serde::Deserialize;
use tokio::sync::{Mutex, Semaphore};

#[derive(Clone, Debug)]
pub enum PacketRoute {
    Proxy,
    Direct(Arc<[IpAddr]>),
}

#[derive(Clone, Debug)]
struct CachedRoute {
    addresses: Arc<[IpAddr]>,
    expires: Instant,
}

#[derive(Debug)]
pub struct PacketRouter {
    reverse: bool,
    client: reqwest::Client,
    cache: Cache<String, CachedRoute>,
    locks: Cache<String, Arc<Mutex<()>>>,
    slots: Semaphore,
    direct_tcp: AtomicU64,
    proxy_tcp: AtomicU64,
    dns_failures: AtomicU64,
    direct_udp: AtomicU64,
    proxy_udp: AtomicU64,
    rejected_udp: AtomicU64,
}

impl PacketRouter {
    pub fn new(reverse: bool) -> std::io::Result<Self> {
        let client = proxy_core::util::http_client_builder()
            .no_proxy()
            // Bootstrap must not go through NE's virtual DNS or recurse.
            .resolve_to_addrs(
                "dns.alidns.com",
                &[
                    "223.5.5.5:443".parse().unwrap(),
                    "223.6.6.6:443".parse().unwrap(),
                ],
            )
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(2)
            .build()
            .map_err(std::io::Error::other)?;
        Ok(Self {
            reverse,
            client,
            cache: Cache::builder()
                .max_capacity(1024)
                .time_to_live(Duration::from_secs(300))
                .build(),
            locks: Cache::builder().max_capacity(1024).build(),
            slots: Semaphore::new(8),
            direct_tcp: AtomicU64::new(0),
            proxy_tcp: AtomicU64::new(0),
            dns_failures: AtomicU64::new(0),
            direct_udp: AtomicU64::new(0),
            proxy_udp: AtomicU64::new(0),
            rejected_udp: AtomicU64::new(0),
        })
    }

    pub async fn route(&self, host: &str) -> PacketRoute {
        let route = if let Ok(ip) = host.parse::<IpAddr>() {
            classify(&[ip], self.reverse)
        } else {
            classify(&self.resolve_addresses(host).await, self.reverse)
        };
        let counter = match &route {
            PacketRoute::Direct(_) => &self.direct_tcp,
            PacketRoute::Proxy => &self.proxy_tcp,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            host,
            direct = matches!(route, PacketRoute::Direct(_)),
            "packet route selected"
        );
        route
    }

    async fn resolve_addresses(&self, host: &str) -> Arc<[IpAddr]> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let lookup = async {
            let lock = self
                .locks
                .get_with(host.clone(), || Arc::new(Mutex::new(())));
            let _guard = lock.lock().await;
            if let Some(cached) = self.cache.get(&host)
                && cached.expires > Instant::now()
            {
                return Ok(cached.addresses);
            }
            let _slot = self.slots.acquire().await.map_err(std::io::Error::other)?;
            let (v4, v6) = tokio::join!(self.query(&host, 1), self.query(&host, 28));
            let mut addresses = Vec::new();
            let mut ttl = 300;
            // A single available family is sufficient. A failed family never
            // introduces a new address into a direct decision.
            for answer in [v4, v6].into_iter().flatten() {
                ttl = ttl.min(answer.1);
                addresses.extend(answer.0);
            }
            if addresses.is_empty() {
                return Err(std::io::Error::other("DoH returned no usable address"));
            }
            let addresses: Arc<[IpAddr]> = addresses.into();
            self.cache.insert(
                host.clone(),
                CachedRoute {
                    addresses: addresses.clone(),
                    expires: Instant::now() + Duration::from_secs(u64::from(ttl)),
                },
            );
            Ok(addresses)
        };
        match tokio::time::timeout(Duration::from_secs(4), lookup).await {
            Ok(Ok(addresses)) => addresses,
            result => {
                self.dns_failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(host, ?result, "route lookup unavailable");
                // Short negative caching bounds retries while offline; never
                // persist a failure or let it select direct egress.
                self.cache.insert(
                    host,
                    CachedRoute {
                        addresses: Arc::from([]),
                        expires: Instant::now() + Duration::from_secs(5),
                    },
                );
                Arc::from([])
            }
        }
    }

    async fn query(&self, host: &str, kind: u16) -> std::io::Result<(Vec<IpAddr>, u32)> {
        let mut response = self
            .client
            .get({
                let mut url = reqwest::Url::parse("https://dns.alidns.com/resolve").unwrap();
                url.query_pairs_mut()
                    .append_pair("name", host)
                    .append_pair("type", &kind.to_string());
                url
            })
            .send()
            .await
            .map_err(std::io::Error::other)?
            .error_for_status()
            .map_err(std::io::Error::other)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(std::io::Error::other)? {
            if bytes.len() + chunk.len() > 64 * 1024 {
                return Err(std::io::Error::other("DNS response exceeded size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let answer: DnsAnswer = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        answer.addresses(host, kind)
    }

    pub fn counters(&self) -> serde_json::Value {
        serde_json::json!({
            "directTcp": self.direct_tcp.load(Ordering::Relaxed),
            "proxyTcp": self.proxy_tcp.load(Ordering::Relaxed),
            "dnsFailures": self.dns_failures.load(Ordering::Relaxed),
            "directUdp": self.direct_udp.load(Ordering::Relaxed),
            "proxyUdp": self.proxy_udp.load(Ordering::Relaxed),
            "rejectedUdp": self.rejected_udp.load(Ordering::Relaxed),
        })
    }
}

impl tun2proxy::UdpRouter for PacketRouter {
    fn route<'a>(
        &'a self,
        destination: std::net::SocketAddr,
        domain: Option<&'a str>,
        proxy_enabled: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = tun2proxy::UdpRoute> + Send + 'a>> {
        Box::pin(async move {
            // UDP uses a fixed mainland/local rule, independent of TCP Auto or
            // reverse mode. Cache resolved addresses, not a TCP route decision.
            let addresses = match domain {
                Some(domain) => self.resolve_addresses(domain).await,
                None => Arc::from([destination.ip()]),
            };
            let decision = match classify(&addresses, false) {
                PacketRoute::Direct(addresses) => {
                    let ip = addresses
                        .iter()
                        .find(|ip| ip.is_ipv4() == destination.is_ipv4())
                        .unwrap_or(&addresses[0]);
                    self.direct_udp.fetch_add(1, Ordering::Relaxed);
                    tun2proxy::UdpRoute::Direct(std::net::SocketAddr::new(*ip, destination.port()))
                }
                PacketRoute::Proxy if proxy_enabled => {
                    self.proxy_udp.fetch_add(1, Ordering::Relaxed);
                    tun2proxy::UdpRoute::Proxy
                }
                PacketRoute::Proxy => {
                    self.rejected_udp.fetch_add(1, Ordering::Relaxed);
                    tun2proxy::UdpRoute::Reject
                }
            };
            tracing::debug!(%destination, ?domain, ?decision, "UDP destination policy");
            decision
        })
    }
}

fn is_virtual(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip.octets()[0] == 198 && (18..20).contains(&ip.octets()[1]),
        IpAddr::V6(ip) => ip.segments()[0] == 0xfc00,
    }
}

fn classify(addresses: &[IpAddr], reverse: bool) -> PacketRoute {
    let direct: Vec<_> = addresses
        .iter()
        .map(IpAddr::to_canonical)
        .filter(|ip| {
            !is_virtual(*ip)
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
        })
        .filter(|ip| {
            proxy_core::geo::is_local_network_host(&ip.to_string())
                || (proxy_core::geo::is_china_ip(*ip) != reverse)
        })
        .collect();
    if direct.is_empty() {
        PacketRoute::Proxy
    } else {
        PacketRoute::Direct(direct.into())
    }
}

#[derive(Deserialize)]
struct DnsAnswer {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Question")]
    question: DnsQuestion,
    #[serde(rename = "Answer", default)]
    answers: Vec<DnsRecord>,
}
#[derive(Deserialize)]
struct DnsQuestion {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
}
#[derive(Deserialize)]
struct DnsRecord {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
impl DnsAnswer {
    fn addresses(&self, host: &str, kind: u16) -> std::io::Result<(Vec<IpAddr>, u32)> {
        if self.status != 0 || self.question.kind != kind || !same_name(&self.question.name, host) {
            return Err(std::io::Error::other(
                "DNS response does not match successful query",
            ));
        }
        let mut name = host;
        let mut ttl = 300;
        for _ in 0..8 {
            let records: Vec<_> = self
                .answers
                .iter()
                .filter(|r| same_name(&r.name, name))
                .collect();
            let ips: Vec<_> = records
                .iter()
                .filter(|r| r.kind == kind)
                .filter_map(|r| r.data.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv4() == (kind == 1))
                .collect();
            for record in &records {
                ttl = ttl.min(record.ttl);
            }
            if !ips.is_empty() {
                return Ok((ips, ttl));
            }
            match records.iter().find(|r| r.kind == 5) {
                Some(record) if !same_name(name, &record.data) => name = &record.data,
                _ => return Ok((vec![], ttl)),
            }
        }
        Err(std::io::Error::other("DNS CNAME chain exceeded limit"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_classified_addresses_can_be_direct_and_unknown_never_leaks() {
        let addresses: Vec<IpAddr> = [
            "223.5.5.5",
            "1.1.1.1",
            "2400:3200::1",
            "2606:4700:4700::1111",
        ]
        .map(|s| s.parse().unwrap())
        .to_vec();
        let PacketRoute::Direct(cn) = classify(&addresses, false) else {
            panic!("CN must be direct")
        };
        assert_eq!(&*cn, &[addresses[0], addresses[2]]);
        let PacketRoute::Direct(other) = classify(&addresses, true) else {
            panic!("reverse must be direct")
        };
        assert_eq!(&*other, &[addresses[1], addresses[3]]);
        assert!(matches!(classify(&[], false), PacketRoute::Proxy));
        for reverse in [false, true] {
            assert!(matches!(
                classify(&["198.18.0.1".parse().unwrap()], reverse),
                PacketRoute::Proxy
            ));
            assert!(matches!(
                classify(&["127.0.0.1".parse().unwrap()], reverse),
                PacketRoute::Direct(_)
            ));
        }
    }

    #[test]
    fn doh_requires_matching_question_and_follows_only_the_answer_chain() {
        let mut answer: DnsAnswer = serde_json::from_value(serde_json::json!({
            "Status": 0, "Question": {"name": "www.example.cn.", "type": 1},
            "Answer": [
                {"name": "www.example.cn.", "type": 5, "TTL": 15, "data": "cdn.example.cn."},
                {"name": "cdn.example.cn.", "type": 1, "TTL": 90, "data": "223.5.5.5"},
                {"name": "unrelated.example.", "type": 1, "TTL": 90, "data": "127.0.0.1"}
            ]
        }))
        .unwrap();
        let (ips, ttl) = answer.addresses("WWW.EXAMPLE.CN", 1).unwrap();
        assert_eq!(ips, vec!["223.5.5.5".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 15);
        assert!(answer.addresses("other.example.cn", 1).is_err());
        assert!(answer.addresses("www.example.cn", 28).is_err());
        answer.status = 3;
        assert!(answer.addresses("www.example.cn", 1).is_err());
    }

    #[tokio::test]
    async fn tcp_uses_cached_session_policy() {
        let router = PacketRouter::new(false).unwrap();
        router.cache.insert(
            "cached.example".into(),
            CachedRoute {
                addresses: Arc::from(["223.5.5.5".parse().unwrap()]),
                expires: Instant::now() + Duration::from_secs(10),
            },
        );
        assert!(matches!(
            router.route("CACHED.EXAMPLE.").await,
            PacketRoute::Direct(_)
        ));
        assert!(matches!(
            router.route("cached.example").await,
            PacketRoute::Direct(_)
        ));
        assert!(matches!(router.route("8.8.8.8").await, PacketRoute::Proxy));
        assert_eq!(router.counters()["directTcp"], 2);
        assert_eq!(router.counters()["proxyTcp"], 1);
        assert_eq!(router.counters()["dnsFailures"], 0);
    }

    #[tokio::test]
    async fn udp_country_policy_ignores_tcp_reverse_and_requires_opt_in_for_foreign() {
        use tun2proxy::{UdpRoute, UdpRouter};
        let router = PacketRouter::new(true).unwrap();
        router.cache.insert(
            "cached.example".into(),
            CachedRoute {
                addresses: Arc::from(["223.5.5.5".parse().unwrap(), "1.1.1.1".parse().unwrap()]),
                expires: Instant::now() + Duration::from_secs(10),
            },
        );
        for enabled in [false, true] {
            let route = UdpRouter::route(
                &router,
                "198.18.0.1:443".parse().unwrap(),
                Some("cached.example"),
                enabled,
            )
            .await;
            assert!(
                matches!(route, UdpRoute::Direct(dst) if dst == "223.5.5.5:443".parse().unwrap())
            );
            let route = UdpRouter::route(
                &router,
                "2400:3200::1"
                    .parse::<IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, 443))
                    .unwrap(),
                None,
                enabled,
            )
            .await;
            assert!(matches!(route, UdpRoute::Direct(_)));
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            let dst = std::net::SocketAddr::new(ip.parse().unwrap(), 443);
            assert!(matches!(
                UdpRouter::route(&router, dst, None, false).await,
                UdpRoute::Reject
            ));
            assert!(matches!(
                UdpRouter::route(&router, dst, None, true).await,
                UdpRoute::Proxy
            ));
        }
        for ip in ["0.0.0.0", "::", "198.18.0.1"] {
            let dst = std::net::SocketAddr::new(ip.parse().unwrap(), 443);
            assert!(matches!(
                UdpRouter::route(&router, dst, None, false).await,
                UdpRoute::Reject
            ));
        }
        let PacketRoute::Direct(tcp) = router.route("cached.example").await else {
            panic!("reverse TCP route")
        };
        assert_eq!(&*tcp, &["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(router.counters()["dnsFailures"], 0);
    }

    #[tokio::test]
    #[ignore = "manual acceptance against public DoH and the bundled country ranges"]
    async fn public_china_and_foreign_names_follow_ip_policy() {
        let router = PacketRouter::new(false).unwrap();
        for host in [
            "www.baidu.com",
            "www.qq.com",
            "www.bilibili.com",
            "www.jd.com",
        ] {
            let started = Instant::now();
            let route = router.route(host).await;
            eprintln!("{host} {:?} {route:?}", started.elapsed());
            assert!(matches!(route, PacketRoute::Direct(_)), "{host}");
        }
        for host in [
            "www.google.com",
            "www.youtube.com",
            "api.ipify.org",
            "www.wikipedia.org",
        ] {
            let started = Instant::now();
            let route = router.route(host).await;
            eprintln!("{host} {:?} {route:?}", started.elapsed());
            assert!(matches!(route, PacketRoute::Proxy), "{host}");
        }
        assert_eq!(router.counters()["dnsFailures"], 0);
    }
}
