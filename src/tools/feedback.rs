use crate::models::{request::FeedbackRequest, response::FeedbackResponse};
use crate::state::AppState;
use uuid::Uuid;

pub async fn run(_state: &AppState, req: FeedbackRequest) -> FeedbackResponse {
    // In a full implementation, this would persist the feedback to the database.
    let feedback_id = Uuid::new_v4().to_string();
    tracing::info!(
        request_id = %req.request_id,
        correct_verdict = %req.correct_verdict,
        feedback_id = %feedback_id,
        "feedback received"
    );
    FeedbackResponse {
        accepted: true,
        feedback_id,
        message: "Feedback accepted. Thank you.".to_string(),
    }
}
