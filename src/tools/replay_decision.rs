use crate::error::AppError;
use crate::models::{request::ReplayRequest, response::ReplayResponse};
use crate::state::AppState;
use uuid::Uuid;

pub async fn run(state: &AppState, req: ReplayRequest) -> Result<ReplayResponse, AppError> {
    if !state.postgres.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "decision replay requires PostgreSQL persistence".to_string(),
        ));
    }
    if req.deterministic == Some(false) {
        return Err(AppError::InvalidRequest(
            "only deterministic replay is supported".to_string(),
        ));
    }
    let original = state
        .postgres
        .get_decision(&req.request_id)
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?
        .ok_or_else(|| {
            AppError::InvalidRequest(format!(
                "classification request id '{}' was not found",
                req.request_id
            ))
        })?;
    let mut replay_request = original.request.clone();
    replay_request.request_id = Some(format!("replay-{}", Uuid::new_v4()));
    let replayed = crate::tools::classify::run_ephemeral(state, replay_request).await?;
    let matches_original = equivalent(&original.response, &replayed);
    Ok(ReplayResponse {
        request_id: req.request_id,
        original: Some(
            serde_json::to_value(&original.response)
                .map_err(|error| AppError::Serialization(error.to_string()))?,
        ),
        replayed: Some(replayed),
        matches_original,
    })
}

fn equivalent(
    original: &crate::models::response::ClassifyResponse,
    replayed: &crate::models::response::ClassifyResponse,
) -> bool {
    original.verdict == replayed.verdict
        && (original.score - replayed.score).abs() < f64::EPSILON
        && original.confidence == replayed.confidence
        && original.threat_category == replayed.threat_category
        && serde_json::to_value(&original.signals).ok()
            == serde_json::to_value(&replayed.signals).ok()
}
