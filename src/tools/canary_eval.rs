use crate::models::{request::CanaryEvalRequest, response::CanaryEvalResponse};
use crate::state::AppState;
use crate::util::hashing::sha256_hex;

pub async fn run(_state: &AppState, req: CanaryEvalRequest) -> CanaryEvalResponse {
    // A canary token is a traceable URL/value that should never be fetched by legitimate users.
    // Trigger if the token matches one of our registered canaries (stub: check hash prefix).
    let hash = sha256_hex(req.token.as_bytes());
    let triggered = hash.starts_with("00"); // Demo: 1-in-256 trigger rate

    CanaryEvalResponse {
        token: req.token,
        triggered,
        canary_id: if triggered {
            Some("canary-001".to_string())
        } else {
            None
        },
        metadata: None,
    }
}
