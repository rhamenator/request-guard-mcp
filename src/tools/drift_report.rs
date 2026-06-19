use crate::models::{
    request::DriftReportRequest,
    response::{DriftMetrics, DriftReportResponse},
};
use crate::state::AppState;
use crate::util::time::now_rfc3339;
use std::collections::HashMap;

pub async fn run(_state: &AppState, req: DriftReportRequest) -> DriftReportResponse {
    let window_hours = req.window_hours.unwrap_or(24);

    // In production, compute these from stored metrics.
    let verdict_distribution: HashMap<String, u64> = [
        ("allow".to_string(), 8542),
        ("flag".to_string(), 312),
        ("block".to_string(), 146),
        ("challenge".to_string(), 87),
    ]
    .into_iter()
    .collect();

    DriftReportResponse {
        window_hours,
        drift_detected: false,
        metrics: DriftMetrics {
            score_mean: 0.12,
            score_stddev: 0.08,
            verdict_distribution,
            signal_drift: HashMap::new(),
        },
        generated_at: now_rfc3339(),
    }
}
