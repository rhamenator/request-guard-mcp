use crate::error::AppError;
use crate::models::{request::WarmupRequest, response::WarmupResponse};
use crate::state::AppState;
use crate::util::time::elapsed_ms;
use std::time::Instant;

pub async fn run(state: &AppState, req: WarmupRequest) -> Result<WarmupResponse, AppError> {
    let start = Instant::now();
    let target = req.target.as_deref().unwrap_or("all");
    if !matches!(target, "all" | "rule_engine" | "scorer" | "cache") {
        return Err(AppError::InvalidRequest(
            "unsupported warmup target".to_string(),
        ));
    }
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
                // Exercise the lazy rule regexes with a synthetic classify.
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
                    tls_ja3: None,
                    tls_ja4: None,
                    tls_fingerprint_source: None,
                    tls_fingerprint_attestation: None,
                    tls_fingerprint_verified: false,
                    extra: None,
                };
                if crate::tools::classify::run_ephemeral(state, dummy)
                    .await
                    .is_ok()
                {
                    warmed.push(t.to_string());
                } else {
                    skipped.push(t.to_string());
                }
            }
            "cache" => {
                state
                    .cache
                    .set("__warmup__", serde_json::json!({"ok": true}))
                    .await;
                warmed.push(t.to_string());
            }
            _ => unreachable!("warmup target was checked above"),
        }
    }

    Ok(WarmupResponse {
        warmed,
        skipped,
        latency_ms: elapsed_ms(start),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn unknown_target_is_an_error() {
        let state = AppState::new(Config::default());
        assert!(matches!(
            run(
                &state,
                WarmupRequest {
                    target: Some("not_a_target".into())
                }
            )
            .await,
            Err(AppError::InvalidRequest(_))
        ));
        assert!(run(
            &state,
            WarmupRequest {
                target: Some("cache".into())
            }
        )
        .await
        .is_ok());
    }
}
