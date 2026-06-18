use crate::error::AppError;
use crate::mcp::protocol::McpRequest;
use crate::state::AppState;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Every registered tool implements this trait.
#[async_trait]
pub trait McpTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError>;
}

/// Central registry mapping tool names to implementations.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn McpTool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Arc<dyn McpTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn McpTool>> {
        self.tools.get(name)
    }

    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.tools.keys().map(String::as_str).collect();
        names.sort();
        names
    }

    pub async fn dispatch(
        &self,
        state: Arc<AppState>,
        req: &McpRequest,
    ) -> Result<Value, AppError> {
        // Strip the "tools/" prefix if present
        let tool_name = req.method.strip_prefix("tools/").unwrap_or(&req.method);

        let tool = self
            .tools
            .get(tool_name)
            .ok_or_else(|| AppError::ToolNotFound(tool_name.to_string()))?;

        tool.call(state, req.params.clone()).await
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Concrete tool wrappers ────────────────────────────────────────────────

// Health tool (no req body)
pub struct HealthTool;
#[async_trait]
impl McpTool for HealthTool {
    fn name(&self) -> &str {
        "health"
    }
    fn description(&self) -> &str {
        "Server health check"
    }
    async fn call(&self, state: Arc<AppState>, _params: Option<Value>) -> Result<Value, AppError> {
        let result = crate::tools::health::run(&state).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Model info tool
pub struct ModelInfoTool;
#[async_trait]
impl McpTool for ModelInfoTool {
    fn name(&self) -> &str {
        "model_info"
    }
    fn description(&self) -> &str {
        "Model and server metadata"
    }
    async fn call(&self, state: Arc<AppState>, _params: Option<Value>) -> Result<Value, AppError> {
        let result = crate::tools::model_info::run(&state).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Classify tool
pub struct ClassifyTool;
#[async_trait]
impl McpTool for ClassifyTool {
    fn name(&self) -> &str {
        "classify"
    }
    fn description(&self) -> &str {
        "Classify a request as bot/human"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ClassifyRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::ClassifyRequest {
                ip: None,
                user_agent: None,
                path: None,
                method: None,
                headers: None,
                body_snippet: None,
                referer: None,
                accept: None,
                request_id: None,
                timestamp: None,
                extra: None,
            });
        let result = crate::tools::classify::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Explain tool
pub struct ExplainTool;
#[async_trait]
impl McpTool for ExplainTool {
    fn name(&self) -> &str {
        "explain"
    }
    fn description(&self) -> &str {
        "Explain a classification decision"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ExplainRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::explain::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Batch classify
pub struct BatchClassifyTool;
#[async_trait]
impl McpTool for BatchClassifyTool {
    fn name(&self) -> &str {
        "batch_classify"
    }
    fn description(&self) -> &str {
        "Classify multiple requests"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::BatchClassifyRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::batch_classify::run(&state, req).await?;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Feedback tool
pub struct FeedbackTool;
#[async_trait]
impl McpTool for FeedbackTool {
    fn name(&self) -> &str {
        "feedback"
    }
    fn description(&self) -> &str {
        "Submit feedback on a classification"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::FeedbackRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::feedback::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Feature flags
pub struct FeatureFlagsTool;
#[async_trait]
impl McpTool for FeatureFlagsTool {
    fn name(&self) -> &str {
        "feature_flags"
    }
    fn description(&self) -> &str {
        "List or get feature flags"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::FeatureFlagsRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::FeatureFlagsRequest { flag: None });
        let result = crate::tools::feature_flags::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Warmup
pub struct WarmupTool;
#[async_trait]
impl McpTool for WarmupTool {
    fn name(&self) -> &str {
        "warmup"
    }
    fn description(&self) -> &str {
        "Warm up caches and engines"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::WarmupRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::WarmupRequest { target: None });
        let result = crate::tools::warmup::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Replay decision
pub struct ReplayDecisionTool;
#[async_trait]
impl McpTool for ReplayDecisionTool {
    fn name(&self) -> &str {
        "replay_decision"
    }
    fn description(&self) -> &str {
        "Replay a previous decision"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ReplayRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::replay_decision::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Redact preview
pub struct RedactPreviewTool;
#[async_trait]
impl McpTool for RedactPreviewTool {
    fn name(&self) -> &str {
        "redact_preview"
    }
    fn description(&self) -> &str {
        "Preview payload redaction"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::RedactPreviewRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::redact_preview::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Enrich IP
pub struct EnrichIpTool;
#[async_trait]
impl McpTool for EnrichIpTool {
    fn name(&self) -> &str {
        "enrich_ip"
    }
    fn description(&self) -> &str {
        "Enrich an IP address"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::EnrichIpRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::enrich_ip::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Enrich ASN
pub struct EnrichAsnTool;
#[async_trait]
impl McpTool for EnrichAsnTool {
    fn name(&self) -> &str {
        "enrich_asn"
    }
    fn description(&self) -> &str {
        "Enrich an ASN"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::EnrichAsnRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::enrich_asn::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Enrich UA
pub struct EnrichUaTool;
#[async_trait]
impl McpTool for EnrichUaTool {
    fn name(&self) -> &str {
        "enrich_ua"
    }
    fn description(&self) -> &str {
        "Enrich a user-agent"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::EnrichUaRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::enrich_ua::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Threat lookup
pub struct ThreatLookupTool;
#[async_trait]
impl McpTool for ThreatLookupTool {
    fn name(&self) -> &str {
        "threat_lookup"
    }
    fn description(&self) -> &str {
        "Look up a threat indicator"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ThreatLookupRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::threat_lookup::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Canary eval
pub struct CanaryEvalTool;
#[async_trait]
impl McpTool for CanaryEvalTool {
    fn name(&self) -> &str {
        "canary_eval"
    }
    fn description(&self) -> &str {
        "Evaluate a canary token"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::CanaryEvalRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::canary_eval::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Abuse pattern match
pub struct AbusePatternMatchTool;
#[async_trait]
impl McpTool for AbusePatternMatchTool {
    fn name(&self) -> &str {
        "abuse_pattern_match"
    }
    fn description(&self) -> &str {
        "Match abuse patterns in text"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::AbusePatternMatchRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::abuse_pattern_match::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Score breakdown
pub struct ScoreBreakdownTool;
#[async_trait]
impl McpTool for ScoreBreakdownTool {
    fn name(&self) -> &str {
        "score_breakdown"
    }
    fn description(&self) -> &str {
        "Break down a classification score"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ScoreBreakdownRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::ScoreBreakdownRequest {
                request_id: None,
                signals: None,
            });
        let result = crate::tools::score_breakdown::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Validate payload
pub struct ValidatePayloadTool;
#[async_trait]
impl McpTool for ValidatePayloadTool {
    fn name(&self) -> &str {
        "validate_payload"
    }
    fn description(&self) -> &str {
        "Validate a tool payload"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ValidatePayloadRequest = params
            .ok_or_else(|| AppError::InvalidRequest("params required".to_string()))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| AppError::InvalidRequest(e.to_string()))
            })?;
        let result = crate::tools::validate_payload::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Drift report
pub struct DriftReportTool;
#[async_trait]
impl McpTool for DriftReportTool {
    fn name(&self) -> &str {
        "drift_report"
    }
    fn description(&self) -> &str {
        "Report on score/signal drift"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::DriftReportRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::DriftReportRequest {
                since: None,
                window_hours: None,
            });
        let result = crate::tools::drift_report::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Calibration report
pub struct CalibrationReportTool;
#[async_trait]
impl McpTool for CalibrationReportTool {
    fn name(&self) -> &str {
        "calibration_report"
    }
    fn description(&self) -> &str {
        "Precision/recall calibration report"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::CalibrationReportRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::CalibrationReportRequest { window_hours: None });
        let result = crate::tools::calibration_report::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Queue status
pub struct QueueStatusTool;
#[async_trait]
impl McpTool for QueueStatusTool {
    fn name(&self) -> &str {
        "queue_status"
    }
    fn description(&self) -> &str {
        "Status of processing queues"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::QueueStatusRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::QueueStatusRequest { queue: None });
        let result = crate::tools::queue_status::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Config snapshot
pub struct ConfigSnapshotTool;
#[async_trait]
impl McpTool for ConfigSnapshotTool {
    fn name(&self) -> &str {
        "config_snapshot"
    }
    fn description(&self) -> &str {
        "Snapshot of current configuration"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::ConfigSnapshotRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::ConfigSnapshotRequest {
                redact_secrets: None,
            });
        let result = crate::tools::config_snapshot::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

// Self test
pub struct SelfTestTool;
#[async_trait]
impl McpTool for SelfTestTool {
    fn name(&self) -> &str {
        "self_test"
    }
    fn description(&self) -> &str {
        "Run internal self-test suite"
    }
    async fn call(&self, state: Arc<AppState>, params: Option<Value>) -> Result<Value, AppError> {
        let req: crate::models::request::SelfTestRequest = params
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e: serde_json::Error| AppError::InvalidRequest(e.to_string()))?
            .unwrap_or(crate::models::request::SelfTestRequest { suite: None });
        let result = crate::tools::self_test::run(&state, req).await;
        serde_json::to_value(result).map_err(AppError::from)
    }
}

/// Build and return a fully-populated tool registry.
pub fn build_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(ClassifyTool));
    registry.register(Arc::new(ExplainTool));
    registry.register(Arc::new(BatchClassifyTool));
    registry.register(Arc::new(HealthTool));
    registry.register(Arc::new(ModelInfoTool));
    registry.register(Arc::new(FeedbackTool));
    registry.register(Arc::new(FeatureFlagsTool));
    registry.register(Arc::new(WarmupTool));
    registry.register(Arc::new(ReplayDecisionTool));
    registry.register(Arc::new(RedactPreviewTool));
    registry.register(Arc::new(EnrichIpTool));
    registry.register(Arc::new(EnrichAsnTool));
    registry.register(Arc::new(EnrichUaTool));
    registry.register(Arc::new(ThreatLookupTool));
    registry.register(Arc::new(CanaryEvalTool));
    registry.register(Arc::new(AbusePatternMatchTool));
    registry.register(Arc::new(ScoreBreakdownTool));
    registry.register(Arc::new(ValidatePayloadTool));
    registry.register(Arc::new(DriftReportTool));
    registry.register(Arc::new(CalibrationReportTool));
    registry.register(Arc::new(QueueStatusTool));
    registry.register(Arc::new(ConfigSnapshotTool));
    registry.register(Arc::new(SelfTestTool));
    registry
}
