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
    run_internal(state, req, true, "internal").await
}

pub async fn run_scoped(
    state: &AppState,
    req: ClassifyRequest,
    caller_scope: &str,
) -> Result<ClassifyResponse, AppError> {
    run_internal(state, req, true, caller_scope).await
}

pub(crate) async fn run_ephemeral(
    state: &AppState,
    req: ClassifyRequest,
) -> Result<ClassifyResponse, AppError> {
    run_internal(state, req, false, "internal").await
}

async fn run_internal(
    state: &AppState,
    req: ClassifyRequest,
    persist: bool,
    caller_scope: &str,
) -> Result<ClassifyResponse, AppError> {
    let start = Instant::now();
    validate_tls_fingerprints(&req)?;
    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let rule_engine = RuleEngine::new();
    let scorer = Scorer::new();

    let signals: SignalSet = rule_engine.evaluate(&req);

    // Check cache for fingerprint
    let fingerprint = request_fingerprint(
        caller_scope,
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

fn validate_tls_fingerprints(request: &ClassifyRequest) -> Result<(), AppError> {
    if let Some(ja3) = request.tls_ja3.as_deref() {
        let candidate = ja3.trim();
        if candidate.len() != 32 || !candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::Validation(
                "tls_ja3 must be a 32-character hexadecimal JA3 digest".into(),
            ));
        }
    }
    if let Some(ja4) = request.tls_ja4.as_deref() {
        let candidate = ja4.trim().to_ascii_lowercase();
        let sections = candidate.split('_').collect::<Vec<_>>();
        let valid = sections.len() == 3
            && sections[0].len() == 10
            && sections[0]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && sections[1].len() == 12
            && sections[2].len() == 12
            && sections[1]
                .bytes()
                .chain(sections[2].bytes())
                .all(|byte| byte.is_ascii_hexdigit());
        if !valid {
            return Err(AppError::Validation(
                "tls_ja4 must use the canonical JA4 a_b_c format".into(),
            ));
        }
    }
    if let Some(source) = request.tls_fingerprint_source.as_deref() {
        if source.is_empty()
            || source.len() > 32
            || !source
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(AppError::Validation(
                "tls_fingerprint_source must be a short infrastructure identifier".into(),
            ));
        }
    }
    Ok(())
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
