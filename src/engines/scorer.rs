use crate::models::{
    enums::{Confidence, ThreatCategory, Verdict},
    signals::SignalSet,
};

pub const THRESHOLD_BLOCK: f64 = 0.75;
pub const THRESHOLD_FLAG: f64 = 0.55;
pub const THRESHOLD_CHALLENGE: f64 = 0.40;
pub const THRESHOLD_ALLOW: f64 = 0.0;

/// Compute a final verdict and threat category from a set of signals.
pub struct Scorer;

impl Scorer {
    pub fn new() -> Self {
        Scorer
    }

    pub fn score(&self, signals: &SignalSet) -> ScorerResult {
        let score = signals.aggregate_score();
        let verdict = self.verdict(score);
        let confidence = self.confidence(signals, score);
        let threat_category = self.threat_category(signals);
        ScorerResult {
            score,
            verdict,
            confidence,
            threat_category,
        }
    }

    fn verdict(&self, score: f64) -> Verdict {
        if score >= THRESHOLD_BLOCK {
            Verdict::Block
        } else if score >= THRESHOLD_FLAG {
            Verdict::Flag
        } else if score >= THRESHOLD_CHALLENGE {
            Verdict::Challenge
        } else {
            Verdict::Allow
        }
    }

    fn confidence(&self, signals: &SignalSet, _score: f64) -> Confidence {
        let count = signals.as_slice().len();
        let max_weight = signals
            .as_slice()
            .iter()
            .map(|s| s.weight)
            .fold(0.0f64, f64::max);

        if count >= 3 && max_weight >= 0.7 {
            Confidence::High
        } else if count >= 2 || max_weight >= 0.5 {
            Confidence::Medium
        } else if count >= 1 {
            Confidence::Low
        } else {
            Confidence::VeryLow
        }
    }

    fn threat_category(&self, signals: &SignalSet) -> ThreatCategory {
        let names: Vec<&str> = signals.as_slice().iter().map(|s| s.name.as_str()).collect();
        if names.contains(&"ua_ai_bot") {
            ThreatCategory::AiScraping
        } else if names.contains(&"ua_scraper") {
            ThreatCategory::Scraping
        } else if names.iter().any(|n| n.starts_with("ua_")) {
            ThreatCategory::BotTraffic
        } else if names.contains(&"path_sensitive") {
            ThreatCategory::DataExtraction
        } else if names.is_empty() {
            ThreatCategory::None
        } else {
            ThreatCategory::Unknown
        }
    }
}

impl Default for Scorer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScorerResult {
    pub score: f64,
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub threat_category: ThreatCategory,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::signals::{Signal, SignalSource};

    #[test]
    fn high_score_yields_block() {
        let mut signals = SignalSet::default();
        signals.push(Signal::new(
            "ua_ai_bot",
            1.0,
            0.8,
            SignalSource::RuleEngine,
            "test",
        ));
        signals.push(Signal::new(
            "ua_non_browser",
            0.7,
            0.3,
            SignalSource::RuleEngine,
            "test",
        ));
        let scorer = Scorer::new();
        let result = scorer.score(&signals);
        assert!(matches!(result.verdict, Verdict::Block | Verdict::Flag));
    }

    #[test]
    fn empty_signals_yields_allow() {
        let signals = SignalSet::default();
        let scorer = Scorer::new();
        let result = scorer.score(&signals);
        assert_eq!(result.verdict, Verdict::Allow);
        assert_eq!(result.score, 0.0);
    }
}
