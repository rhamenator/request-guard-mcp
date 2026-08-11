use crate::error::AppError;
use crate::models::{
    request::DriftReportRequest,
    response::{DriftMetrics, DriftReportResponse},
};
use crate::state::AppState;
use crate::util::time::now_rfc3339;
use chrono::{DateTime, Duration, Utc};

pub async fn run(
    state: &AppState,
    req: DriftReportRequest,
) -> Result<DriftReportResponse, AppError> {
    if !state.postgres.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "drift reporting requires PostgreSQL persistence".to_string(),
        ));
    }
    if req.since.is_some() && req.window_hours.is_some() {
        return Err(AppError::InvalidRequest(
            "since and window_hours are mutually exclusive".to_string(),
        ));
    }
    let mut window_hours = req.window_hours.unwrap_or(24);
    if !(1..=8760).contains(&window_hours) {
        return Err(AppError::InvalidRequest(
            "window_hours must be between 1 and 8760".to_string(),
        ));
    }
    let now = Utc::now();
    let start = req
        .since
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|error| AppError::InvalidRequest(format!("invalid since timestamp: {error}")))?
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(|| now - Duration::hours(i64::from(window_hours)));
    if start > now {
        return Err(AppError::InvalidRequest(
            "since timestamp cannot be in the future".to_string(),
        ));
    }
    let elapsed_hours = now.signed_duration_since(start).num_seconds() as f64 / 3600.0;
    if req.since.is_some() {
        if elapsed_hours > 8760.0 {
            return Err(AppError::InvalidRequest(
                "since timestamp cannot be more than 8760 hours old".to_string(),
            ));
        }
        window_hours = elapsed_hours.ceil().max(1.0) as u32;
    }
    let midpoint = start + now.signed_duration_since(start) / 2;
    let summary = state
        .postgres
        .drift_summary(start, midpoint)
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    let score_shift = (summary.score_mean - summary.previous_score_mean).abs();
    let drift_detected = summary.previous_samples > 0
        && summary.current_samples > 0
        && (score_shift >= 0.10
            || summary
                .signal_drift
                .values()
                .any(|value| value.abs() >= 0.25));
    Ok(DriftReportResponse {
        window_hours,
        drift_detected,
        metrics: DriftMetrics {
            samples: summary.samples,
            score_mean: summary.score_mean,
            score_stddev: summary.score_stddev,
            verdict_distribution: summary.verdict_distribution,
            signal_drift: summary.signal_drift,
        },
        generated_at: now_rfc3339(),
    })
}
