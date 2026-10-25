use serde::{de::Error, Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Primary classification request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyRequest {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub path: Option<String>,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body_snippet: Option<String>,
    pub referer: Option<String>,
    pub accept: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: Option<String>,
    /// TLS metadata is never trusted without a valid short-lived attestation.
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
    pub tls_fingerprint_source: Option<String>,
    #[serde(default, skip_serializing)]
    pub tls_fingerprint_attestation: Option<String>,
    /// Server-derived provenance. JSON callers cannot set this field.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub tls_fingerprint_verified: bool,
    pub extra: Option<serde_json::Value>,
}

/// Batch classification: list of classify requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassifyRequest {
    pub items: Vec<ClassifyRequest>,
    pub options: Option<BatchOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOptions {
    #[serde(default)]
    pub fail_fast: bool,
    // Preserve the historical detailed batch response when this option is omitted.
    #[serde(default = "default_batch_include_details")]
    pub include_details: bool,
}

fn default_batch_include_details() -> bool {
    true
}

/// Explain tool request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainRequest {
    pub classification: serde_json::Value,
    #[serde(default, deserialize_with = "deserialize_explain_format")]
    pub format: Option<String>,
}

fn deserialize_explain_format<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let format = String::deserialize(deserializer)?;
    if format == "json" {
        Ok(Some(format))
    } else {
        Err(D::Error::custom("unsupported explain format"))
    }
}

/// Feedback submission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackRequest {
    pub request_id: String,
    pub correct_verdict: String,
    pub notes: Option<String>,
    pub reporter: Option<String>,
}

/// Feature flags request – no body needed but keep struct for uniformity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlagsRequest {
    #[serde(default, deserialize_with = "deserialize_present_string")]
    pub flag: Option<String>,
}

/// Warmup request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmupRequest {
    #[serde(default, deserialize_with = "deserialize_warmup_target")]
    pub target: Option<String>,
}

fn deserialize_present_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn deserialize_warmup_target<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let target = String::deserialize(deserializer)?;
    if matches!(target.as_str(), "all" | "rule_engine" | "scorer" | "cache") {
        Ok(Some(target))
    } else {
        Err(D::Error::custom("unsupported warmup target"))
    }
}

/// Replay decision request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    pub request_id: String,
    pub deterministic: Option<bool>,
}

/// Redact preview request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactPreviewRequest {
    pub payload: serde_json::Value,
    pub fields: Option<Vec<String>>,
}

/// IP enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichIpRequest {
    pub ip: String,
}

/// ASN enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichAsnRequest {
    pub asn: u32,
}

/// User-agent enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichUaRequest {
    pub user_agent: String,
}

/// Threat lookup request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatLookupRequest {
    pub indicator: String,
    #[serde(rename = "type")]
    pub indicator_type: Option<String>,
}

/// Canary eval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryEvalRequest {
    pub token: String,
    pub context: Option<serde_json::Value>,
}

/// Abuse pattern match request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbusePatternMatchRequest {
    pub text: String,
    pub categories: Option<Vec<String>>,
}

/// Score breakdown request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreBreakdownRequest {
    pub request_id: Option<String>,
    #[serde(default, deserialize_with = "supplied_json_value")]
    pub signals: Option<serde_json::Value>,
}

// Keep an explicitly supplied JSON null distinct from an omitted optional
// field, so score_breakdown can reject it as malformed input.
fn supplied_json_value<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(serde_json::Value::deserialize(deserializer)?))
}

/// Validate payload request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatePayloadRequest {
    pub tool: String,
    pub payload: serde_json::Value,
}

/// Drift report request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftReportRequest {
    pub since: Option<String>,
    pub window_hours: Option<u32>,
}

/// Calibration report request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReportRequest {
    pub window_hours: Option<u32>,
}

/// Queue status request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueStatusRequest {
    pub queue: Option<String>,
}

/// Config snapshot request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSnapshotRequest {
    #[serde(default, deserialize_with = "deserialize_present_bool")]
    pub redact_secrets: Option<bool>,
}

fn deserialize_present_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    bool::deserialize(deserializer).map(Some)
}

/// Self-test request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfTestRequest {
    #[serde(default, deserialize_with = "deserialize_self_test_suite")]
    pub suite: Option<String>,
}

fn deserialize_self_test_suite<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let suite = String::deserialize(deserializer)?;
    if suite != "all" {
        return Err(D::Error::custom("unsupported self_test suite"));
    }
    Ok(Some(suite))
}

#[cfg(test)]
mod self_test_suite_tests {
    use super::{
        EnrichAsnRequest, EnrichIpRequest, EnrichUaRequest, ReplayRequest, SelfTestRequest,
        ValidatePayloadRequest,
    };
    use serde::de::DeserializeOwned;

    fn rejects_unknown<T: DeserializeOwned>(valid: &str, unknown: &str) {
        assert!(serde_json::from_str::<T>(valid).is_ok());
        assert!(serde_json::from_str::<T>(unknown).is_err());
    }

    #[test]
    fn remaining_tool_inputs_reject_unknown_fields() {
        rejects_unknown::<ReplayRequest>(
            r#"{"request_id":"id","deterministic":true}"#,
            r#"{"request_id":"id","determinitsic":true}"#,
        );
        rejects_unknown::<EnrichIpRequest>(
            r#"{"ip":"127.0.0.1"}"#,
            r#"{"ip":"127.0.0.1","ipp":"x"}"#,
        );
        rejects_unknown::<EnrichAsnRequest>(r#"{"asn":64512}"#, r#"{"asn":64512,"asnn":1}"#);
        rejects_unknown::<EnrichUaRequest>(
            r#"{"user_agent":"Mozilla/5.0"}"#,
            r#"{"user_agent":"Mozilla/5.0","user_agnet":"x"}"#,
        );
        rejects_unknown::<ValidatePayloadRequest>(
            r#"{"tool":"self_test","payload":{}}"#,
            r#"{"tool":"self_test","payload":{},"toool":"x"}"#,
        );
        rejects_unknown::<SelfTestRequest>(
            r#"{"suite":"all"}"#,
            r#"{"suite":"all","sutie":"all"}"#,
        );
    }

    #[test]
    fn only_all_or_omitted_suite_is_accepted() {
        for input in [r"{}", r#"{"suite":"all"}"#] {
            assert!(serde_json::from_str::<SelfTestRequest>(input).is_ok());
        }
        for input in [
            r#"{"suite":"unknown"}"#,
            r#"{"suite":""}"#,
            r#"{"suite":null}"#,
            r#"{"suite":1}"#,
        ] {
            assert!(serde_json::from_str::<SelfTestRequest>(input).is_err());
        }
    }
}
