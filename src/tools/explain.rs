use crate::engines::explain::explain_signals;
use crate::engines::Scorer;
use crate::error::AppError;
use crate::models::{
    request::{ClassifyRequest, ExplainRequest},
    response::{ClassifyResponse, ExplainResponse},
    signals::{Signal, SignalSet, SignalSource},
};
use crate::state::AppState;
use serde_json::Value;

const CLASSIFY_REQUEST_FIELDS: &[&str] = &[
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

fn explain_response(response: ClassifyResponse, supplied: bool) -> ExplainResponse {
    let mut signals = SignalSet::default();
    for hit in response.signals {
        let description = if supplied {
            format!("Unverified caller-supplied signal: {}", hit.description)
        } else {
            hit.description
        };
        signals.push(Signal::new(
            &hit.name,
            hit.value,
            hit.weight,
            SignalSource::External,
            &description,
        ));
    }
    let mut result = explain_signals(
        &response.request_id,
        &signals,
        response.score,
        &response.verdict.to_string(),
    );
    let provenance = if supplied {
        "Caller-supplied classification; not verified against a stored decision. "
    } else {
        "Recomputed from supplied request metadata; not a stored decision lookup. "
    };
    result.explanation.insert_str(0, provenance);
    result
}

pub(crate) enum ClassificationInput {
    Request(ClassifyRequest),
    Response(ClassifyResponse),
}

pub(crate) fn parse_classification(value: Value) -> Result<ClassificationInput, AppError> {
    let Value::Object(fields) = &value else {
        return Err(AppError::InvalidRequest(
            "classification must be a request or complete response object".to_string(),
        ));
    };
    let response_shape = [
        "verdict",
        "score",
        "signals",
        "confidence",
        "threat_category",
        "latency_ms",
        "model_version",
    ]
    .iter()
    .any(|field| fields.contains_key(*field));
    if response_shape {
        let response: ClassifyResponse = serde_json::from_value(value).map_err(|_| {
            AppError::InvalidRequest("classification must be a complete ClassifyResponse".into())
        })?;
        if response.request_id.is_empty()
            || response.request_id.len() > 256
            || response.request_id.chars().any(char::is_control)
            || response.signals.len() > 64
            || !response.score.is_finite()
            || !(0.0..=1.0).contains(&response.score)
            || response.signals.iter().any(|signal| {
                signal.name.is_empty()
                    || signal.name.len() > 64
                    || !signal
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    || signal.description.len() > 256
                    || signal.description.chars().any(char::is_control)
                    || !signal.value.is_finite()
                    || !signal.weight.is_finite()
                    || !(0.0..=1.0).contains(&signal.value)
                    || !(0.0..=1.0).contains(&signal.weight)
            })
        {
            return Err(AppError::InvalidRequest(
                "classification response has invalid score or signals".to_string(),
            ));
        }
        let mut signals = SignalSet::default();
        for hit in &response.signals {
            signals.push(Signal::new(
                &hit.name,
                hit.value,
                hit.weight,
                SignalSource::External,
                &hit.description,
            ));
        }
        let recomputed = Scorer::new().score(&signals);
        if (response.score - recomputed.score).abs() > 1e-9
            || response.verdict != recomputed.verdict
        {
            return Err(AppError::InvalidRequest(
                "classification response score or verdict disagrees with its signals".into(),
            ));
        }
        return Ok(ClassificationInput::Response(response));
    }

    if fields
        .keys()
        .any(|key| !CLASSIFY_REQUEST_FIELDS.contains(&key.as_str()))
    {
        return Err(AppError::InvalidRequest(
            "classification contains an unsupported request field".into(),
        ));
    }
    let request: ClassifyRequest = serde_json::from_value(value)
        .map_err(|_| AppError::InvalidRequest("classification must be a ClassifyRequest".into()))?;
    Ok(ClassificationInput::Request(request))
}

pub async fn run(state: &AppState, req: ExplainRequest) -> Result<ExplainResponse, AppError> {
    match parse_classification(req.classification)? {
        ClassificationInput::Response(response) => Ok(explain_response(response, true)),
        ClassificationInput::Request(request) => {
            // Use classify's TLS attestation, configured rules, scoring and
            // cache domain without writing a PostgreSQL decision.
            let response = crate::tools::classify::run_ephemeral(state, request).await?;
            Ok(explain_response(response, false))
        }
    }
}
