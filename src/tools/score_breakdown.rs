use crate::engines::{RuleEngine, Scorer};
use crate::error::AppError;
use crate::models::{
    request::ScoreBreakdownRequest,
    response::{ScoreBreakdownResponse, ScoreComponent},
};
use crate::state::AppState;

pub async fn run(
    _state: &AppState,
    req: ScoreBreakdownRequest,
) -> Result<ScoreBreakdownResponse, AppError> {
    let signals = if let Some(signals_val) = req.signals {
        let cr = parse_signals(signals_val)?;
        let engine = RuleEngine::new();
        engine.evaluate(&cr)
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

    Ok(ScoreBreakdownResponse {
        request_id: req.request_id,
        total_score: result.score,
        breakdown,
        threshold_allow: crate::engines::scorer::THRESHOLD_CHALLENGE,
        threshold_block: crate::engines::scorer::THRESHOLD_BLOCK,
    })
}

pub(crate) fn parse_signals(
    signals_val: serde_json::Value,
) -> Result<crate::models::request::ClassifyRequest, AppError> {
    // Share the signal shape check with validate_payload so both reject
    // malformed supplied metadata.
    let valid_keys = [
        "ip",
        "user_agent",
        "path",
        "method",
        "headers",
        "body_snippet",
        "referer",
        "accept",
        "request_id",
        "timestamp",
        "tls_ja3",
        "tls_ja4",
        "tls_fingerprint_source",
        "tls_fingerprint_attestation",
        "extra",
    ];
    let fields = signals_val.as_object().ok_or_else(|| {
        AppError::InvalidRequest(
            "score_breakdown.signals must be a classification request object".into(),
        )
    })?;
    if fields.keys().any(|key| !valid_keys.contains(&key.as_str())) {
        return Err(AppError::InvalidRequest(
            "score_breakdown.signals contains an unsupported classification field".into(),
        ));
    }
    serde_json::from_value::<crate::models::request::ClassifyRequest>(signals_val).map_err(|_| {
        AppError::InvalidRequest(
            "score_breakdown.signals has an invalid classification field type".into(),
        )
    })
}
