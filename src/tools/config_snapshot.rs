use crate::error::AppError;
use crate::models::{request::ConfigSnapshotRequest, response::ConfigSnapshotResponse};
use crate::state::AppState;
use crate::util::time::now_rfc3339;

pub async fn run(
    state: &AppState,
    req: ConfigSnapshotRequest,
) -> Result<ConfigSnapshotResponse, AppError> {
    if req.redact_secrets == Some(false) {
        return Err(AppError::InvalidRequest(
            "unredacted configuration snapshots are not available through MCP".to_string(),
        ));
    }
    let cfg = &state.config;

    let snapshot = serde_json::json!({
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
            "otlp_endpoint": if cfg.telemetry.otlp_endpoint.is_some() { serde_json::Value::String("[REDACTED]".to_string()) } else { serde_json::Value::Null },
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
        "tls_fingerprints": {
            "attestation_key_configured": cfg.tls_fingerprints.attestation_key.is_some(),
            "previous_attestation_key_configured": cfg.tls_fingerprints.previous_attestation_key.is_some(),
            "max_age_seconds": cfg.tls_fingerprints.max_age_seconds,
            "known_bad_ja3_count": cfg.tls_fingerprints.known_bad_ja3.len(),
            "known_bad_ja4_count": cfg.tls_fingerprints.known_bad_ja4.len(),
        },
    });

    Ok(ConfigSnapshotResponse {
        snapshot,
        generated_at: now_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn mcp_snapshot_never_exposes_otlp_credentials() {
        let mut config = Config::default();
        config.telemetry.otlp_endpoint = Some("http://user:secret@collector:4317".into());
        let state = AppState::new(config);
        let request = ConfigSnapshotRequest {
            redact_secrets: Some(true),
        };
        let response = run(&state, request).await.unwrap();
        let rendered = response.snapshot.to_string();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("collector"));
        assert_eq!(
            response.snapshot["telemetry"]["otlp_endpoint"],
            "[REDACTED]"
        );
        let unredacted = ConfigSnapshotRequest {
            redact_secrets: Some(false),
        };
        assert!(run(&state, unredacted).await.is_err());
    }
}
