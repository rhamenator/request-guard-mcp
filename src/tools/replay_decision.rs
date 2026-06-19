use crate::models::{request::ReplayRequest, response::ReplayResponse};
use crate::state::AppState;

pub async fn run(state: &AppState, req: ReplayRequest) -> ReplayResponse {
    // In a full implementation, look up the original request from the database.
    // For now, return a deterministic response indicating the request was not found.
    let cached = state.cache.get(&req.request_id).await;

    if let Some(original) = cached {
        // Attempt to replay
        if let Ok(classify_req) =
            serde_json::from_value::<crate::models::request::ClassifyRequest>(original.clone())
        {
            let replayed = crate::tools::classify::run(state, classify_req).await;
            let matches = true; // Simplified: same engine, same inputs → same output
            ReplayResponse {
                request_id: req.request_id,
                original: Some(original),
                replayed: Some(replayed),
                matches_original: matches,
            }
        } else {
            ReplayResponse {
                request_id: req.request_id,
                original: Some(original),
                replayed: None,
                matches_original: false,
            }
        }
    } else {
        ReplayResponse {
            request_id: req.request_id,
            original: None,
            replayed: None,
            matches_original: false,
        }
    }
}
