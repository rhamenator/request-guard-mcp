use crate::models::{request::WarmupRequest, response::WarmupResponse};
use crate::state::AppState;
use crate::util::time::elapsed_ms;
use std::time::Instant;

pub async fn run(state: &AppState, req: WarmupRequest) -> WarmupResponse {
    let start = Instant::now();
    let target = req.target.as_deref().unwrap_or("all");
    let mut warmed = Vec::new();
    let mut skipped = Vec::new();

    let targets = if target == "all" {
        vec!["rule_engine", "scorer", "cache"]
    } else {
        vec![target]
    };

    for t in targets {
        match t {
            "rule_engine" | "scorer" => {
                // Pre-run a dummy classify to JIT-compile regex patterns.
                let dummy = crate::models::request::ClassifyRequest {
                    ip: Some("127.0.0.1".to_string()),
                    user_agent: Some("warmup".to_string()),
                    path: Some("/warmup".to_string()),
                    method: Some("GET".to_string()),
                    headers: None,
                    body_snippet: None,
                    referer: None,
                    accept: None,
                    request_id: Some("warmup".to_string()),
                    timestamp: None,
                    extra: None,
                };
                crate::tools::classify::run(state, dummy).await;
                warmed.push(t.to_string());
            }
            "cache" => {
                state
                    .cache
                    .set("__warmup__", serde_json::json!({"ok": true}))
                    .await;
                warmed.push(t.to_string());
            }
            _ => {
                skipped.push(t.to_string());
            }
        }
    }

    WarmupResponse {
        warmed,
        skipped,
        latency_ms: elapsed_ms(start),
    }
}
