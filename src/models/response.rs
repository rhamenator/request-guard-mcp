use crate::models::enums::{Confidence, ThreatCategory, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Primary classification response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResponse {
    pub request_id: String,
    pub verdict: Verdict,
    pub score: f64,
    pub confidence: Confidence,
    pub threat_category: ThreatCategory,
    pub signals: Vec<SignalHit>,
    pub latency_ms: u64,
    pub model_version: String,
}

/// A single signal that contributed to the classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalHit {
    pub name: String,
    pub value: f64,
    pub weight: f64,
    pub description: String,
}

/// Batch classification response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchClassifyResponse {
    pub results: Vec<BatchItemResult>,
    pub total: usize,
    pub processed: usize,
    pub errors: usize,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemResult {
    pub index: usize,
    pub result: Option<ClassifyResponse>,
    pub error: Option<String>,
}

/// Explain tool response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    pub request_id: String,
    pub explanation: String,
    pub factors: Vec<ExplanationFactor>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationFactor {
    pub name: String,
    pub contribution: f64,
    pub description: String,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: HashMap<String, ComponentHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Model info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfoResponse {
    pub model_version: String,
    pub tool_count: usize,
    pub tools: Vec<ToolInfo>,
    pub build_info: BuildInfoResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfoResponse {
    pub version: String,
    pub git_commit: String,
    pub build_date: String,
    pub rust_version: String,
}

/// Feedback response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackResponse {
    pub accepted: bool,
    pub feedback_id: String,
    pub message: String,
}

/// Feature flags response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlagsResponse {
    pub flags: HashMap<String, bool>,
}

/// Warmup response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupResponse {
    pub warmed: Vec<String>,
    pub skipped: Vec<String>,
    pub latency_ms: u64,
}

/// Replay response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    pub request_id: String,
    pub original: Option<serde_json::Value>,
    pub replayed: Option<ClassifyResponse>,
    pub matches_original: bool,
}

/// Redact preview response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactPreviewResponse {
    pub redacted: serde_json::Value,
    pub fields_redacted: Vec<String>,
}

/// IP enrichment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichIpResponse {
    pub ip: String,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub is_tor: bool,
    pub risk_score: f64,
}

/// ASN enrichment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichAsnResponse {
    pub asn: u32,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub risk_score: f64,
    pub is_hosting: bool,
}

/// User-agent enrichment response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichUaResponse {
    pub user_agent: String,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
    pub is_bot: bool,
    pub bot_name: Option<String>,
    pub risk_score: f64,
}

/// Threat lookup response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLookupResponse {
    pub indicator: String,
    pub found: bool,
    pub threat_type: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub last_seen: Option<String>,
}

/// Canary eval response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryEvalResponse {
    pub token: String,
    pub triggered: bool,
    pub canary_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Abuse pattern match response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbusePatternMatchResponse {
    pub matched: bool,
    pub patterns: Vec<PatternMatch>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern: String,
    pub category: String,
    pub confidence: f64,
    pub matched_text: Option<String>,
}

/// Score breakdown response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdownResponse {
    pub request_id: Option<String>,
    pub total_score: f64,
    pub breakdown: Vec<ScoreComponent>,
    pub threshold_allow: f64,
    pub threshold_block: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreComponent {
    pub engine: String,
    pub score: f64,
    pub weight: f64,
    pub weighted_score: f64,
    pub signals: Vec<String>,
}

/// Validate payload response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatePayloadResponse {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

/// Drift report response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReportResponse {
    pub window_hours: u32,
    pub drift_detected: bool,
    pub metrics: DriftMetrics,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftMetrics {
    pub score_mean: f64,
    pub score_stddev: f64,
    pub verdict_distribution: HashMap<String, u64>,
    pub signal_drift: HashMap<String, f64>,
}

/// Calibration report response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReportResponse {
    pub window_hours: u32,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub recommendations: Vec<String>,
    pub generated_at: String,
}

/// Queue status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatusResponse {
    pub queues: Vec<QueueInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueInfo {
    pub name: String,
    pub depth: u64,
    pub consumers: u32,
    pub rate_per_second: f64,
}

/// Config snapshot response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshotResponse {
    pub snapshot: serde_json::Value,
    pub generated_at: String,
}

/// Self-test response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResponse {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<SelfTestResult>,
    pub overall_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResult {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
    pub latency_ms: u64,
}

/// Generic error response returned to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}
