use crate::models::enums::Verdict;

/// Policy thresholds and decision-making.
pub struct Policy {
    pub block_threshold: f64,
    pub flag_threshold: f64,
    pub challenge_threshold: f64,
}

impl Policy {
    pub fn default_policy() -> Self {
        Self {
            block_threshold: 0.75,
            flag_threshold: 0.55,
            challenge_threshold: 0.40,
        }
    }

    pub fn apply(&self, score: f64) -> Verdict {
        if score >= self.block_threshold {
            Verdict::Block
        } else if score >= self.flag_threshold {
            Verdict::Flag
        } else if score >= self.challenge_threshold {
            Verdict::Challenge
        } else {
            Verdict::Allow
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::default_policy()
    }
}
