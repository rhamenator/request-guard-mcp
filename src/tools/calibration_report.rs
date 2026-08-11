use crate::error::AppError;
use crate::models::{request::CalibrationReportRequest, response::CalibrationReportResponse};
use crate::state::AppState;
use crate::util::time::now_rfc3339;
use chrono::{Duration, Utc};

pub async fn run(
    state: &AppState,
    req: CalibrationReportRequest,
) -> Result<CalibrationReportResponse, AppError> {
    if !state.postgres.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "calibration reporting requires PostgreSQL persistence".to_string(),
        ));
    }
    let window_hours = req.window_hours.unwrap_or(24);
    if !(1..=8760).contains(&window_hours) {
        return Err(AppError::InvalidRequest(
            "window_hours must be between 1 and 8760".to_string(),
        ));
    }
    let summary = state
        .postgres
        .calibration_summary(Utc::now() - Duration::hours(i64::from(window_hours)))
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    let precision = ratio(
        summary.true_positives,
        summary.true_positives + summary.false_positives,
    );
    let recall = ratio(
        summary.true_positives,
        summary.true_positives + summary.false_negatives,
    );
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    let false_positive_rate = ratio(
        summary.false_positives,
        summary.false_positives + summary.true_negatives,
    );
    let false_negative_rate = ratio(
        summary.false_negatives,
        summary.false_negatives + summary.true_positives,
    );
    let recommendations = if summary.samples == 0 {
        vec!["No labelled feedback is available for this window.".to_string()]
    } else {
        let mut values = Vec::new();
        if false_positive_rate >= 0.10 {
            values.push("Review blocking thresholds to reduce false positives.".to_string());
        }
        if false_negative_rate >= 0.10 {
            values.push("Review allow thresholds to reduce false negatives.".to_string());
        }
        if values.is_empty() {
            values.push(
                "Observed labelled performance is within the configured reporting thresholds."
                    .to_string(),
            );
        }
        values
    };
    Ok(CalibrationReportResponse {
        window_hours,
        samples: summary.samples,
        precision,
        recall,
        f1,
        false_positive_rate,
        false_negative_rate,
        recommendations,
        generated_at: now_rfc3339(),
    })
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
