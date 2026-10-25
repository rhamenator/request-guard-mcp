use crate::models::response::{ComponentHealth, HealthResponse};
use crate::state::AppState;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

const BACKEND_PING_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) async fn bounded_backend_ping(ping: impl Future<Output = bool>) -> bool {
    tokio::time::timeout(BACKEND_PING_TIMEOUT, ping)
        .await
        .unwrap_or(false)
}

pub async fn run(state: &AppState) -> HealthResponse {
    let uptime = state.started_at.elapsed().as_secs();
    let mut checks = HashMap::new();

    checks.insert(
        "server".to_string(),
        ComponentHealth {
            status: "healthy".to_string(),
            message: None,
            latency_ms: Some(0),
        },
    );

    checks.insert(
        "cache".to_string(),
        ComponentHealth {
            status: "healthy".to_string(),
            message: None,
            latency_ms: None,
        },
    );

    let redis_configured = state.config.redis.url.is_some();
    let postgres_configured = state.config.postgres.url.is_some();
    let redis_start = std::time::Instant::now();
    let postgres_start = std::time::Instant::now();
    let (redis_healthy, postgres_healthy) = tokio::join!(
        async { !redis_configured || bounded_backend_ping(state.redis.ping()).await },
        async { !postgres_configured || bounded_backend_ping(state.postgres.ping()).await },
    );
    checks.insert(
        "redis".to_string(),
        ComponentHealth {
            status: if !redis_configured {
                "disabled"
            } else if redis_healthy {
                "healthy"
            } else {
                "unhealthy"
            }
            .to_string(),
            message: (!redis_healthy)
                .then(|| "configured Redis did not respond to PING".to_string()),
            latency_ms: redis_configured
                .then(|| redis_start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
        },
    );

    checks.insert(
        "postgres".to_string(),
        ComponentHealth {
            status: if !postgres_configured {
                "disabled"
            } else if postgres_healthy {
                "healthy"
            } else {
                "unhealthy"
            }
            .to_string(),
            message: (!postgres_healthy)
                .then(|| "configured PostgreSQL did not respond to a health query".to_string()),
            latency_ms: postgres_configured.then(|| {
                postgres_start
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64
            }),
        },
    );

    let geoip_configured = state.config.geoip.mmdb_path.is_some()
        || state.config.geoip.city_mmdb_path.is_some()
        || state.config.geoip.asn_mmdb_path.is_some()
        || state.config.geoip.anonymous_ip_mmdb_path.is_some();
    let geoip_healthy = !geoip_configured || state.geoip.is_available();
    checks.insert(
        "geoip".to_string(),
        ComponentHealth {
            status: if !geoip_configured {
                "disabled"
            } else if geoip_healthy {
                "healthy"
            } else {
                "unhealthy"
            }
            .to_string(),
            message: (!geoip_healthy)
                .then(|| "configured MaxMind databases are unavailable".to_string()),
            latency_ms: None,
        },
    );

    HealthResponse {
        status: if redis_healthy && postgres_healthy && geoip_healthy {
            "healthy"
        } else {
            "unhealthy"
        }
        .to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_backend_ping_is_bounded() {
        assert!(bounded_backend_ping(async { true }).await);
        let start = std::time::Instant::now();
        assert!(!bounded_backend_ping(std::future::pending::<bool>()).await);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
