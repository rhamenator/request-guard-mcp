use crate::engines::{RuleEngine, Scorer};
use crate::models::{
    request::ScoreBreakdownRequest,
    response::{ScoreBreakdownResponse, ScoreComponent},
};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: ScoreBreakdownRequest) -> ScoreBreakdownResponse {
    let signals = if let Some(signals_val) = req.signals {
        // Try to deserialize as a ClassifyRequest to compute live
        if let Ok(cr) =
            serde_json::from_value::<crate::models::request::ClassifyRequest>(signals_val)
        {
            let engine = RuleEngine::new();
            engine.evaluate(&cr)
        } else {
            crate::models::signals::SignalSet::default()
        }
    } else {
        crate::models::signals::SignalSet::default()
    };

    let scorer = Scorer::new();
    let result = scorer.score(&signals);

    let breakdown = signals
        .as_slice()
        .iter()
        .map(|s| ScoreComponent {
            engine: "rule_engine".to_string(),
            score: s.value,
            weight: s.weight,
            weighted_score: s.value * s.weight,
            signals: vec![s.name.clone()],
        })
        .collect();

    ScoreBreakdownResponse {
        request_id: req.request_id,
        total_score: result.score,
        breakdown,
        threshold_allow: 0.0,
        threshold_block: 0.75,
    }
}
