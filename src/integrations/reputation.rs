/// Reputation data for an IP or ASN (stub - would connect to external APIs).
#[derive(Debug, Clone, Default)]
pub struct ReputationScore {
    pub score: f64,
    pub listed: bool,
    pub source: Option<String>,
    pub categories: Vec<String>,
}

#[derive(Default)]
pub struct ReputationClient {
    api_key: Option<String>,
}

impl ReputationClient {
    pub fn new(api_key: Option<String>) -> Self {
        ReputationClient { api_key }
    }

    pub fn is_configured(&self) -> bool {
        self.api_key.is_some()
    }

    /// Look up reputation for an IP. Returns default if not configured.
    pub async fn lookup_ip(&self, _ip: &str) -> ReputationScore {
        if !self.is_configured() {
            return ReputationScore::default();
        }
        // Real implementation would call an external API.
        ReputationScore::default()
    }
}
