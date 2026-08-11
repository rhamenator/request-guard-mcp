use crate::error::AppError;
use crate::models::{request::FeedbackRequest, response::FeedbackResponse};
use crate::state::AppState;

pub async fn run(state: &AppState, req: FeedbackRequest) -> Result<FeedbackResponse, AppError> {
    if !state.postgres.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "feedback requires PostgreSQL persistence".to_string(),
        ));
    }
    let correct_verdict = req.correct_verdict.to_ascii_lowercase();
    if !matches!(
        correct_verdict.as_str(),
        "allow" | "block" | "flag" | "challenge"
    ) {
        return Err(AppError::InvalidRequest(
            "correct_verdict must be allow, block, flag, or challenge".to_string(),
        ));
    }
    let decision = state
        .postgres
        .get_decision(&req.request_id)
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    if decision.is_none() {
        return Err(AppError::InvalidRequest(format!(
            "classification request id '{}' was not found",
            req.request_id
        )));
    }
    let feedback_id = state
        .postgres
        .record_feedback(
            &req.request_id,
            &correct_verdict,
            req.notes.as_deref(),
            req.reporter.as_deref(),
        )
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    tracing::info!(
        request_id = %req.request_id,
        correct_verdict = %req.correct_verdict,
        feedback_id = %feedback_id,
        "feedback received"
    );
    Ok(FeedbackResponse {
        accepted: true,
        feedback_id,
        message: "Feedback accepted. Thank you.".to_string(),
    })
}
