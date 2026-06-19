use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Primary classification request.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub extra: Option<serde_json::Value>,
}

/// Batch classification: list of classify requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchClassifyRequest {
    pub items: Vec<ClassifyRequest>,
    pub options: Option<BatchOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOptions {
    #[serde(default)]
    pub fail_fast: bool,
    #[serde(default)]
    pub include_details: bool,
}

/// Explain tool request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainRequest {
    pub classification: serde_json::Value,
    pub format: Option<String>,
}

/// Feedback submission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRequest {
    pub request_id: String,
    pub correct_verdict: String,
    pub notes: Option<String>,
    pub reporter: Option<String>,
}

/// Feature flags request – no body needed but keep struct for uniformity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlagsRequest {
    pub flag: Option<String>,
}

/// Warmup request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupRequest {
    pub target: Option<String>,
}

/// Replay decision request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    pub request_id: String,
    pub deterministic: Option<bool>,
}

/// Redact preview request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactPreviewRequest {
    pub payload: serde_json::Value,
    pub fields: Option<Vec<String>>,
}

/// IP enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichIpRequest {
    pub ip: String,
}

/// ASN enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichAsnRequest {
    pub asn: u32,
}

/// User-agent enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichUaRequest {
    pub user_agent: String,
}

/// Threat lookup request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLookupRequest {
    pub indicator: String,
    #[serde(rename = "type")]
    pub indicator_type: Option<String>,
}

/// Canary eval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryEvalRequest {
    pub token: String,
    pub context: Option<serde_json::Value>,
}

/// Abuse pattern match request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbusePatternMatchRequest {
    pub text: String,
    pub categories: Option<Vec<String>>,
}

/// Score breakdown request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdownRequest {
    pub request_id: Option<String>,
    pub signals: Option<serde_json::Value>,
}

/// Validate payload request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatePayloadRequest {
    pub tool: String,
    pub payload: serde_json::Value,
}

/// Drift report request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReportRequest {
    pub since: Option<String>,
    pub window_hours: Option<u32>,
}

/// Calibration report request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReportRequest {
    pub window_hours: Option<u32>,
}

/// Queue status request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatusRequest {
    pub queue: Option<String>,
}

/// Config snapshot request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshotRequest {
    pub redact_secrets: Option<bool>,
}

/// Self-test request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestRequest {
    pub suite: Option<String>,
}
