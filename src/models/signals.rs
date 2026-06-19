use serde::{Deserialize, Serialize};

/// A computed signal value used during classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    pub value: f64,
    /// Normalized 0..1 weight for this signal in the final score.
    pub weight: f64,
    pub source: SignalSource,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    RuleEngine,
    Scorer,
    Heuristic,
    External,
    Cache,
}

impl Signal {
    pub fn new(
        name: &str,
        value: f64,
        weight: f64,
        source: SignalSource,
        description: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            value,
            weight,
            source,
            description: description.to_string(),
        }
    }

    /// Weighted contribution of this signal to the final score.
    pub fn contribution(&self) -> f64 {
        self.value * self.weight
    }
}

/// Aggregated signal set from all engines for one request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignalSet {
    pub signals: Vec<Signal>,
}

impl SignalSet {
    pub fn push(&mut self, signal: Signal) {
        self.signals.push(signal);
    }

    /// Compute aggregate score (weighted sum, clamped to [0, 1]).
    pub fn aggregate_score(&self) -> f64 {
        let sum: f64 = self.signals.iter().map(|s| s.contribution()).sum();
        let total_weight: f64 = self.signals.iter().map(|s| s.weight).sum();
        if total_weight == 0.0 {
            0.0
        } else {
            (sum / total_weight).clamp(0.0, 1.0)
        }
    }

    /// Return a mutable reference to all signals (for inspection).
    pub fn as_slice(&self) -> &[Signal] {
        &self.signals
    }
}
