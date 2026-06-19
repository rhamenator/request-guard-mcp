use crate::models::{request::CalibrationReportRequest, response::CalibrationReportResponse};
use crate::state::AppState;
use crate::util::time::now_rfc3339;

pub async fn run(_state: &AppState, req: CalibrationReportRequest) -> CalibrationReportResponse {
    let window_hours = req.window_hours.unwrap_or(24);

    // In production, compute these from labelled feedback data.
    let precision = 0.94;
    let recall = 0.87;
    let f1 = 2.0 * precision * recall / (precision + recall);

    CalibrationReportResponse {
        window_hours,
        precision,
        recall,
        f1,
        false_positive_rate: 0.03,
        false_negative_rate: 0.06,
        recommendations: vec![
            "Model performance is within acceptable bounds.".to_string(),
            "Consider increasing training data for edge cases.".to_string(),
        ],
        generated_at: now_rfc3339(),
    }
}
