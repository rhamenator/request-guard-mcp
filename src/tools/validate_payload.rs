use crate::models::{
    request::{
        AbusePatternMatchRequest, BatchClassifyRequest, CalibrationReportRequest,
        CanaryEvalRequest, ClassifyRequest, ConfigSnapshotRequest, DriftReportRequest,
        EnrichAsnRequest, EnrichIpRequest, EnrichUaRequest, ExplainRequest, FeatureFlagsRequest,
        FeedbackRequest, QueueStatusRequest, RedactPreviewRequest, ReplayRequest,
        ScoreBreakdownRequest, SelfTestRequest, ThreatLookupRequest, ValidatePayloadRequest,
        WarmupRequest,
    },
    response::{ValidatePayloadResponse, ValidationError},
};
use crate::state::AppState;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub async fn run(state: &AppState, req: ValidatePayloadRequest) -> ValidatePayloadResponse {
    // Check the request structs used by the tool wrappers and supported names
    // for operational diagnostics. This is a structural check in other cases;
    // request shapes. This does not run a tool, check whether a feature is
    // enabled, test backend availability, or apply other business rules.
    let error = validate_for_tool(&req.tool, &req.payload)
        .and_then(|_| {
            if req.tool == "feature_flags" {
                if let Some(name) = req.payload.get("flag").and_then(Value::as_str) {
                    if !state.feature_flags.contains_key(name) {
                        return Err("unsupported feature flag".to_string());
                    }
                }
            }
            Ok(())
        })
        .err();
    ValidatePayloadResponse {
        valid: error.is_none(),
        errors: error
            .into_iter()
            .map(|message| ValidationError {
                path: "/".to_string(),
                message,
            })
            .collect(),
    }
}

fn decode<T: DeserializeOwned>(payload: &Value) -> Result<(), String> {
    serde_json::from_value::<T>(payload.clone())
        .map(|_| ())
        .map_err(|_| "payload does not match the tool's request shape".to_string())
}

fn validate_for_tool(tool: &str, payload: &Value) -> Result<(), String> {
    match tool {
        "health" | "model_info" => Ok(()), // These wrappers ignore arguments.
        "classify" => decode::<ClassifyRequest>(payload),
        "explain" => {
            let request: ExplainRequest = serde_json::from_value(payload.clone())
                .map_err(|_| "payload does not match the tool's request shape".to_string())?;
            crate::tools::explain::parse_classification(request.classification)
                .map(|_| ())
                .map_err(|_| "classification must be a complete request or response".to_string())
        }
        "batch_classify" => decode::<BatchClassifyRequest>(payload),
        "feedback" => decode::<FeedbackRequest>(payload),
        "feature_flags" => decode::<FeatureFlagsRequest>(payload),
        "warmup" => decode::<WarmupRequest>(payload),
        "replay_decision" => decode::<ReplayRequest>(payload),
        "redact_preview" => decode::<RedactPreviewRequest>(payload),
        "enrich_ip" => decode::<EnrichIpRequest>(payload),
        "enrich_asn" => decode::<EnrichAsnRequest>(payload),
        "enrich_ua" => decode::<EnrichUaRequest>(payload),
        "threat_lookup" => decode::<ThreatLookupRequest>(payload),
        "canary_eval" => decode::<CanaryEvalRequest>(payload),
        "abuse_pattern_match" => decode::<AbusePatternMatchRequest>(payload),
        "score_breakdown" => decode::<ScoreBreakdownRequest>(payload),
        "validate_payload" => decode::<ValidatePayloadRequest>(payload),
        "drift_report" => decode::<DriftReportRequest>(payload),
        "calibration_report" => decode::<CalibrationReportRequest>(payload),
        "queue_status" => decode::<QueueStatusRequest>(payload),
        "config_snapshot" => decode::<ConfigSnapshotRequest>(payload),
        "self_test" => decode::<SelfTestRequest>(payload),
        _ => Err("unknown tool".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_callable_request_shapes() {
        assert!(validate_for_tool("explain", &json!({"classification":{"path":"/admin"}})).is_ok());
        assert!(validate_for_tool(
            "explain",
            &json!({"classification":{"verdict":"block","score":0.9}})
        )
        .is_err());
        assert!(validate_for_tool("explain", &json!({"classification":{"pah":"/admin"}})).is_err());
        assert!(validate_for_tool("classify", &json!({})).is_ok());
        assert!(validate_for_tool("batch_classify", &json!({"items": []})).is_ok());
        assert!(validate_for_tool(
            "feedback",
            &json!({
                "request_id": "synthetic-id", "correct_verdict": "allow"
            })
        )
        .is_ok());
        assert!(validate_for_tool(
            "feedback",
            &json!({
                "request_id": 1, "correct_verdict": false
            })
        )
        .is_err());
        assert!(validate_for_tool("enrich_ip", &json!({"ip": 1})).is_err());
        assert!(
            validate_for_tool("threat_lookup", &json!({"indicator":"AS64500","typ":"asn"}))
                .is_err()
        );
        assert!(validate_for_tool("feature_flags", &json!({"flags": "enrichment"})).is_err());
        assert!(validate_for_tool("warmup", &json!({"targt": "cache"})).is_err());
        assert!(validate_for_tool("warmup", &json!({"target": "bogus"})).is_err());
        assert!(validate_for_tool("warmup", &json!({"target": null})).is_err());
        assert!(validate_for_tool("config_snapshot", &json!({"redact_secret": false})).is_err());
        assert!(validate_for_tool("config_snapshot", &json!({"redact_secrets": null})).is_err());
        assert!(validate_for_tool(
            "canary_eval",
            &json!({"token": "synthetic", "context": {"path": "/protected"}})
        )
        .is_ok());
        assert!(validate_for_tool(
            "canary_eval",
            &json!({"token": "synthetic", "contex": {"path": "/protected"}})
        )
        .is_err());
        assert!(validate_for_tool("not_a_tool", &json!({})).is_err());
    }

    #[test]
    fn recognizes_every_registered_tool() {
        let registry = crate::mcp::tool_registry::build_registry();
        for name in registry.list() {
            assert_ne!(
                validate_for_tool(name, &json!({})),
                Err("unknown tool".to_string()),
                "registered tool missing structural validator: {name}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_named_feature_is_invalid_without_running_tool() {
        let state = AppState::new(crate::config::Config::default());
        let known = run(
            &state,
            ValidatePayloadRequest {
                tool: "feature_flags".into(),
                payload: json!({"flag":"batch_classify"}),
            },
        )
        .await;
        assert!(known.valid);
        let unknown = run(
            &state,
            ValidatePayloadRequest {
                tool: "feature_flags".into(),
                payload: json!({"flag":"not_a_flag"}),
            },
        )
        .await;
        assert!(!unknown.valid);
        assert_eq!(unknown.errors[0].message, "unsupported feature flag");
    }
}
