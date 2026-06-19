use std::net::IpAddr;

/// Parse an IP string, returning None on failure.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// Check if an IP is a known private/loopback address.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback(),
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
