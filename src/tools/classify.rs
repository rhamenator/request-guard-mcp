use crate::engines::{RuleEngine, Scorer};
use crate::models::{
    request::ClassifyRequest,
    response::{ClassifyResponse, SignalHit},
    signals::SignalSet,
};
use crate::state::AppState;
use crate::util::{hashing::request_fingerprint, time::elapsed_ms};
use std::time::Instant;
use uuid::Uuid;

pub async fn run(state: &AppState, req: ClassifyRequest) -> ClassifyResponse {
    let start = Instant::now();
    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let rule_engine = RuleEngine::new();
    let scorer = Scorer::new();

    let signals: SignalSet = rule_engine.evaluate(&req);

    // Check cache for fingerprint
    let fingerprint = request_fingerprint(
        req.ip.as_deref(),
        req.user_agent.as_deref(),
        req.path.as_deref(),
    );
    if let Some(cached) = state.cache.get(&fingerprint).await {
        if let Ok(mut resp) = serde_json::from_value::<ClassifyResponse>(cached) {
            resp.request_id = request_id;
            resp.latency_ms = elapsed_ms(start);
            return resp;
        }
    }

    let result = scorer.score(&signals);

    let signal_hits: Vec<SignalHit> = signals
        .as_slice()
        .iter()
        .map(|s| SignalHit {
            name: s.name.clone(),
            value: s.value,
            weight: s.weight,
            description: s.description.clone(),
        })
        .collect();

    let resp = ClassifyResponse {
        request_id,
        verdict: result.verdict,
        score: result.score,
        confidence: result.confidence,
        threat_category: result.threat_category,
        signals: signal_hits,
        latency_ms: elapsed_ms(start),
        model_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Cache the result
    if let Ok(val) = serde_json::to_value(&resp) {
        state.cache.set(&fingerprint, val).await;
    }

    // Record metrics
    state
        .metrics
        .requests_total
        .with_label_values(&["classify", "ok"])
        .inc();

    resp
}
