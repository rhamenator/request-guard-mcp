use crate::engines::explain::explain_signals;
use crate::engines::{RuleEngine, Scorer};
use crate::models::{request::ExplainRequest, response::ExplainResponse};
use crate::state::AppState;
use uuid::Uuid;

pub async fn run(_state: &AppState, req: ExplainRequest) -> ExplainResponse {
    // Attempt to extract a classify request from the provided classification value
    let classify_req = serde_json::from_value::<crate::models::request::ClassifyRequest>(
        req.classification.clone(),
    );

    let request_id = classify_req
        .as_ref()
        .ok()
        .and_then(|r| r.request_id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(cr) = classify_req {
        let engine = RuleEngine::new();
        let scorer = Scorer::new();
        let signals = engine.evaluate(&cr);
        let result = scorer.score(&signals);
        explain_signals(
            &request_id,
            &signals,
            result.score,
            &result.verdict.to_string(),
        )
    } else {
        // Fallback: treat the JSON as a pre-computed result
        ExplainResponse {
            request_id,
            explanation: "Explanation generated from pre-computed classification result."
                .to_string(),
            factors: vec![],
            recommendations: vec![
                "Provide a full classify request for detailed explanation.".to_string()
            ],
        }
    }
}
