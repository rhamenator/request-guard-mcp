use crate::models::response::{ComponentHealth, HealthResponse};
use crate::state::AppState;
use crate::util::time::now_unix;
use std::collections::HashMap;

static START_TIME: once_cell::sync::Lazy<u64> = once_cell::sync::Lazy::new(now_unix);

pub async fn run(_state: &AppState) -> HealthResponse {
    // Trigger initialization of start time on first call.
    let _ = *START_TIME;

    let uptime = now_unix().saturating_sub(*START_TIME);
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

    HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        checks,
    }
}
