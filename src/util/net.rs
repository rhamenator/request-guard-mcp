use std::net::IpAddr;

/// Parse an IP string, returning None on failure.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// Treat IPv4-mapped IPv6 as the same address as its IPv4 form.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Check if an IP is a known private/loopback address.
pub fn is_private(ip: &IpAddr) -> bool {
    match canonical_ip(*ip) {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Truncate an IP for logging (last octet replaced with 0).
pub fn anonymize_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            // Truncate to /64
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::", s[0], s[1], s[2], s[3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_ip, is_private};
    use std::net::IpAddr;

    #[test]
    fn non_public_ipv6_and_mapped_ipv4_share_private_treatment() {
        for value in ["::1", "fc00::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(is_private(&value.parse::<IpAddr>().unwrap()), "{value}");
        }
        for value in ["2001:4860:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_private(&value.parse::<IpAddr>().unwrap()), "{value}");
        }
        assert_eq!(
            canonical_ip("::ffff:198.51.100.9".parse().unwrap()).to_string(),
            "198.51.100.9"
        );
    }
}
