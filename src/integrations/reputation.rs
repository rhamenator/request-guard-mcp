use crate::integrations::redis::RedisClient;
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct ReputationScore {
    pub score: f64,
    pub listed: bool,
    pub source: Option<String>,
    pub categories: Vec<String>,
}

pub struct ReputationClient {
    redis: Arc<RedisClient>,
}

impl ReputationClient {
    pub fn new(redis: Arc<RedisClient>) -> Self {
        Self { redis }
    }

    pub fn is_configured(&self) -> bool {
        self.redis.is_available()
    }

    pub async fn lookup_ip(&self, ip: &str) -> Result<ReputationScore> {
        self.lookup("ip", ip).await
    }

    pub async fn lookup_asn(&self, asn: u32) -> Result<ReputationScore> {
        self.lookup("asn", &asn.to_string()).await
    }

    async fn lookup(&self, indicator_type: &str, indicator: &str) -> Result<ReputationScore> {
        if !self.is_configured() {
            return Ok(ReputationScore::default());
        }
        let Some(record) = self.redis.threat_lookup(indicator_type, indicator).await? else {
            return Ok(ReputationScore::default());
        };
        let score = match record.severity.to_ascii_lowercase().as_str() {
            "critical" => 1.0,
            "high" => 0.9,
            "medium" => 0.6,
            "low" => 0.3,
            _ => 0.5,
        };
        Ok(ReputationScore {
            score,
            listed: true,
            source: Some(record.source),
            categories: vec![record.threat_type],
        })
    }
}
