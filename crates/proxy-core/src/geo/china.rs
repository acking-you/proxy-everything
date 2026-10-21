//! Bundled CN routing ranges, independent of online GeoIP quotas.
//!
//! Source revision, hashes and MIT license are in `data/china-ip/`.
//! The generated tables contain sorted, disjoint inclusive intervals.
use std::net::IpAddr;

const V4: &[u8] = include_bytes!("../../data/china-ip/ipv4.bin");
const V6: &[u8] = include_bytes!("../../data/china-ip/ipv6.bin");

/// Whether a public address belongs to the bundled mainland China range set.
/// IPv4-mapped IPv6 addresses use the IPv4 policy.
pub fn is_china_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => contains(V4, &ip.octets()),
        IpAddr::V6(ip) => contains(V6, &ip.octets()),
    }
}

fn contains(data: &[u8], ip: &[u8]) -> bool {
    let width = ip.len();
    let stride = width * 2;
    let mut low = 0;
    let mut high = data.len() / stride;
    while low < high {
        let middle = low + (high - low) / 2;
        let record = &data[middle * stride..(middle + 1) * stride];
        if ip < &record[..width] {
            high = middle;
        } else if ip > &record[width..] {
            low = middle + 1;
        } else {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_ranges_are_sorted_disjoint_and_searchable() {
        for (table, width) in [(V4, 4), (V6, 16)] {
            assert_eq!(table.len() % (2 * width), 0);
            let mut previous_end: Option<&[u8]> = None;
            for record in table.chunks_exact(2 * width) {
                let (start, end) = record.split_at(width);
                assert!(start <= end);
                assert!(previous_end.is_none_or(|previous| previous < start));
                assert!(contains(table, start));
                assert!(contains(table, end));
                previous_end = Some(end);
            }
        }
        for ip in [
            "223.5.5.5",
            "119.29.29.29",
            "2400:3200::1",
            "::ffff:223.5.5.5",
        ] {
            assert!(is_china_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "13.228.117.199",
            "2606:4700:4700::1111",
            "127.0.0.1",
        ] {
            assert!(!is_china_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
