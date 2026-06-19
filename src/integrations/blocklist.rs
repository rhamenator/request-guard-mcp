use dashmap::DashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// In-memory blocklist for IPs, CIDRs, and user-agent patterns.
pub struct Blocklist {
    ips: Arc<DashSet<IpAddr>>,
    ua_patterns: Arc<Vec<regex::Regex>>,
}

impl Blocklist {
    pub fn new() -> Self {
        Blocklist {
            ips: Arc::new(DashSet::new()),
            ua_patterns: Arc::new(Vec::new()),
        }
    }

    pub fn add_ip(&self, ip: IpAddr) {
        self.ips.insert(ip);
        info!(ip = %ip, "IP added to blocklist");
    }

    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    pub fn is_ua_blocked(&self, ua: &str) -> bool {
        self.ua_patterns.iter().any(|r| r.is_match(ua))
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}
