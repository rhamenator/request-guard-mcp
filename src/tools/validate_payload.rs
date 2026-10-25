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

pub async fn run(_state: &AppState, req: ValidatePayloadRequest) -> ValidatePayloadResponse {
    // Check the same request structs used by the tool wrappers. This is a
    // structural check only: it does not run the tool or check feature flags,
    // backend availability, or tool-specific business rules.
    let error = validate_for_tool(&req.tool, &req.payload).err();
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
        "explain" => decode::<ExplainRequest>(payload),
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
}
