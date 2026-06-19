use crate::models::signals::{Signal, SignalSet, SignalSource};
use std::collections::HashMap;

/// Simple statistical anomaly detection over recent request distributions.
pub struct AnomalyEngine {
    /// Running mean and variance per signal name.
    stats: HashMap<String, RunningStats>,
}

#[derive(Default)]
struct RunningStats {
    count: f64,
    mean: f64,
    m2: f64,
}

impl RunningStats {
    fn update(&mut self, value: f64) {
        self.count += 1.0;
        let delta = value - self.mean;
        self.mean += delta / self.count;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(&self) -> f64 {
        if self.count < 2.0 {
            0.0
        } else {
            self.m2 / (self.count - 1.0)
        }
    }

    fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    fn z_score(&self, value: f64) -> f64 {
        let sd = self.stddev();
        if sd == 0.0 {
            0.0
        } else {
            (value - self.mean).abs() / sd
        }
    }
}

impl AnomalyEngine {
    pub fn new() -> Self {
        AnomalyEngine {
            stats: HashMap::new(),
        }
    }

    /// Update internal statistics from a signal set.
    pub fn observe(&mut self, signals: &SignalSet) {
        for s in signals.as_slice() {
            self.stats
                .entry(s.name.clone())
                .or_default()
                .update(s.value);
        }
    }

    /// Return anomaly signals for values that deviate significantly from baseline.
    pub fn detect(&self, signals: &SignalSet) -> Vec<Signal> {
        const Z_THRESHOLD: f64 = 3.0;
        let mut anomalies = Vec::new();
        for s in signals.as_slice() {
            if let Some(stats) = self.stats.get(&s.name) {
                let z = stats.z_score(s.value);
                if z > Z_THRESHOLD {
                    anomalies.push(Signal::new(
                        &format!("anomaly_{}", s.name),
                        (z / 10.0).clamp(0.0, 1.0),
                        0.4,
                        SignalSource::Heuristic,
                        &format!("Anomalous value for signal '{}' (z={z:.2})", s.name),
                    ));
                }
            }
        }
        anomalies
    }
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new()
    }
}
