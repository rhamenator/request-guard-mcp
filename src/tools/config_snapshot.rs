use crate::models::{request::ConfigSnapshotRequest, response::ConfigSnapshotResponse};
use crate::state::AppState;
use crate::util::time::now_rfc3339;

pub async fn run(state: &AppState, req: ConfigSnapshotRequest) -> ConfigSnapshotResponse {
    let redact = req.redact_secrets.unwrap_or(true);
    let cfg = &state.config;

    let mut snapshot = serde_json::json!({
        "host": cfg.host,
        "port": cfg.port,
        "log_level": cfg.log_level,
        "limits": {
            "max_request_bytes": cfg.limits.max_request_bytes,
            "max_batch_size": cfg.limits.max_batch_size,
            "global_concurrency": cfg.limits.global_concurrency,
            "per_tool_timeout_secs": cfg.limits.per_tool_timeout_secs,
            "classify_timeout_secs": cfg.limits.classify_timeout_secs,
        },
        "features": {
            "enable_batch": cfg.features.enable_batch,
            "enable_enrichment": cfg.features.enable_enrichment,
            "enable_feedback": cfg.features.enable_feedback,
        },
        "auth": {
            "enabled": cfg.auth.enabled,
            "token_count": cfg.auth.tokens.len(),
        },
        "telemetry": {
            "service_name": cfg.telemetry.service_name,
            "metrics_path": cfg.telemetry.metrics_path,
            "otlp_endpoint": if redact { serde_json::Value::String("[REDACTED]".to_string()) } else { serde_json::json!(cfg.telemetry.otlp_endpoint) },
        },
        "redis": {
            "configured": cfg.redis.url.is_some(),
            "pool_size": cfg.redis.pool_size,
            "key_prefix": cfg.redis.key_prefix,
            "cache_ttl_secs": cfg.redis.cache_ttl_secs,
        },
        "postgres": {
            "configured": cfg.postgres.url.is_some(),
            "max_connections": cfg.postgres.max_connections,
            "connect_timeout_secs": cfg.postgres.connect_timeout_secs,
        },
        "geoip": {
            "configured": cfg.geoip.mmdb_path.is_some() || cfg.geoip.city_mmdb_path.is_some() || cfg.geoip.asn_mmdb_path.is_some() || cfg.geoip.anonymous_ip_mmdb_path.is_some(),
            "city_configured": cfg.geoip.mmdb_path.is_some() || cfg.geoip.city_mmdb_path.is_some(),
            "asn_configured": cfg.geoip.asn_mmdb_path.is_some(),
            "anonymous_ip_configured": cfg.geoip.anonymous_ip_mmdb_path.is_some(),
        },
    });

    if redact {
        if let Some(obj) = snapshot.as_object_mut() {
            if let Some(auth) = obj.get_mut("auth").and_then(|v| v.as_object_mut()) {
                auth.remove("tokens");
            }
        }
    }

    ConfigSnapshotResponse {
        snapshot,
        generated_at: now_rfc3339(),
    }
}
