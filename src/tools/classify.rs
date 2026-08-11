use crate::engines::{RuleEngine, Scorer};
use crate::error::AppError;
use crate::models::{
    request::ClassifyRequest,
    response::{ClassifyResponse, SignalHit},
    signals::SignalSet,
};
use crate::state::AppState;
use crate::util::{hashing::request_fingerprint, time::elapsed_ms};
use std::time::Instant;
use uuid::Uuid;

pub async fn run(state: &AppState, req: ClassifyRequest) -> Result<ClassifyResponse, AppError> {
    run_internal(state, req, true).await
}

pub(crate) async fn run_ephemeral(
    state: &AppState,
    req: ClassifyRequest,
) -> Result<ClassifyResponse, AppError> {
    run_internal(state, req, false).await
}

async fn run_internal(
    state: &AppState,
    req: ClassifyRequest,
    persist: bool,
) -> Result<ClassifyResponse, AppError> {
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
        req.method.as_deref(),
        req.headers.as_ref(),
    );
    let distributed_cached = if state.redis.is_available() {
        match state.redis.cache_get(&fingerprint).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "distributed cache read failed; using local cache");
                None
            }
        }
    } else {
        None
    };
    if let Some(cached) = distributed_cached.or(state.cache.get(&fingerprint).await) {
        if let Ok(mut resp) = serde_json::from_value::<ClassifyResponse>(cached) {
            resp.request_id = request_id;
            resp.latency_ms = elapsed_ms(start);
            if persist {
                persist_decision(state, &req, &resp).await?;
            }
            return Ok(resp);
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
        state.cache.set(&fingerprint, val.clone()).await;
        if state.redis.is_available() {
            if let Err(error) = state.redis.cache_set(&fingerprint, &val).await {
                tracing::warn!(%error, "distributed cache write failed; local cache remains active");
            }
        }
    }

    if persist {
        persist_decision(state, &req, &resp).await?;
    }
    Ok(resp)
}

async fn persist_decision(
    state: &AppState,
    request: &ClassifyRequest,
    response: &ClassifyResponse,
) -> Result<(), AppError> {
    if state.postgres.is_available() {
        state
            .postgres
            .record_decision(request, response)
            .await
            .map_err(|error| {
                AppError::Upstream(format!("PostgreSQL decision write failed: {error}"))
            })?;
    }
    Ok(())
}
