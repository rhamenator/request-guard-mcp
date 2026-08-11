use crate::error::AppError;
use crate::models::{request::CanaryEvalRequest, response::CanaryEvalResponse};
use crate::state::AppState;

pub async fn run(state: &AppState, req: CanaryEvalRequest) -> Result<CanaryEvalResponse, AppError> {
    if !state.redis.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "canary evaluation requires Redis".to_string(),
        ));
    }
    if req.token.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "token cannot be empty".to_string(),
        ));
    }
    let record = state
        .redis
        .canary_lookup(&req.token, req.context.as_ref())
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    Ok(CanaryEvalResponse {
        token: req.token,
        triggered: record.is_some(),
        canary_id: record.as_ref().map(|value| value.canary_id.clone()),
        metadata: record.and_then(|value| value.metadata),
    })
}
