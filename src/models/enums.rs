use serde::{Deserialize, Serialize};

/// Classification verdict for a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Block,
    Challenge,
    Flag,
    Unknown,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Verdict::Allow => "allow",
            Verdict::Block => "block",
            Verdict::Challenge => "challenge",
            Verdict::Flag => "flag",
            Verdict::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// Category of potential threat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    AiScraping,
    BotTraffic,
    Crawling,
    Scraping,
    DataExtraction,
    BruteForce,
    Spam,
    Unknown,
    None,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatCategory::AiScraping => "ai_scraping",
            ThreatCategory::BotTraffic => "bot_traffic",
            ThreatCategory::Crawling => "crawling",
            ThreatCategory::Scraping => "scraping",
            ThreatCategory::DataExtraction => "data_extraction",
            ThreatCategory::BruteForce => "brute_force",
            ThreatCategory::Spam => "spam",
            ThreatCategory::Unknown => "unknown",
            ThreatCategory::None => "none",
        };
        write!(f, "{s}")
    }
}

/// Confidence level for a classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
    VeryLow,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
            Confidence::VeryLow => "very_low",
        };
        write!(f, "{s}")
    }
}

/// Overall system health status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        };
        write!(f, "{s}")
    }
}
