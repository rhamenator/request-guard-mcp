use crate::models::response::{BuildInfoResponse, ModelInfoResponse, ToolInfo};
use crate::state::AppState;

pub async fn run(state: &AppState) -> ModelInfoResponse {
    let bi = &state.build_info;
    let tools = vec![
        tool("classify", "Classify a request as bot/human", true),
        tool("explain", "Explain a classification decision", true),
        tool(
            "batch_classify",
            "Classify multiple requests at once",
            state.config.features.enable_batch,
        ),
        tool("health", "Server health check", true),
        tool("model_info", "Return model and server metadata", true),
        tool(
            "feedback",
            "Submit feedback on a classification",
            flag(state, "feedback"),
        ),
        tool("score_breakdown", "Break down a classification score", true),
        tool(
            "validate_payload",
            "Validate a tool payload against its schema",
            true,
        ),
        tool("feature_flags", "List or get feature flags", true),
        tool("warmup", "Warm up caches and engines", true),
        tool(
            "replay_decision",
            "Replay a previous decision",
            flag(state, "replay_decision"),
        ),
        tool("redact_preview", "Preview payload redaction", true),
        tool(
            "enrich_ip",
            "Enrich an IP address with geo/ASN data",
            state.config.features.enable_enrichment
                && (state.geoip.has_ip_database() || state.reputation.is_configured()),
        ),
        tool(
            "enrich_asn",
            "Enrich an ASN with org data",
            state.config.features.enable_enrichment
                && (state.geoip.has_asn_database() || state.reputation.is_configured()),
        ),
        tool(
            "enrich_ua",
            "Enrich a user-agent string",
            state.config.features.enable_enrichment,
        ),
        tool(
            "threat_lookup",
            "Look up a threat indicator",
            flag(state, "threat_lookup"),
        ),
        tool(
            "canary_eval",
            "Evaluate a canary token",
            flag(state, "canary_eval"),
        ),
        tool("abuse_pattern_match", "Match abuse patterns in text", true),
        tool(
            "drift_report",
            "Report on score/signal drift",
            flag(state, "drift_report"),
        ),
        tool(
            "calibration_report",
            "Precision/recall calibration report",
            flag(state, "calibration_report"),
        ),
        tool(
            "queue_status",
            "Status of processing queues",
            flag(state, "queue_status"),
        ),
        tool("config_snapshot", "Snapshot of current configuration", true),
        tool("self_test", "Run internal self-test suite", true),
    ];

    let tool_count = tools.len();
    ModelInfoResponse {
        model_version: env!("CARGO_PKG_VERSION").to_string(),
        tool_count,
        tools,
        build_info: BuildInfoResponse {
            version: bi.version.clone(),
            git_commit: bi.git_commit.clone(),
            build_date: bi.build_date.clone(),
            rust_version: bi.rust_version.clone(),
        },
    }
}

fn flag(state: &AppState, name: &str) -> bool {
    state.feature_flags.get(name).is_some_and(|value| *value)
}

fn tool(name: &str, desc: &str, enabled: bool) -> ToolInfo {
    ToolInfo {
        name: name.to_string(),
        description: desc.to_string(),
        enabled,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}
