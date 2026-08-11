use crate::error::AppError;
use crate::models::{
    request::QueueStatusRequest,
    response::{QueueInfo, QueueStatusResponse},
};
use crate::state::AppState;

pub async fn run(
    state: &AppState,
    req: QueueStatusRequest,
) -> Result<QueueStatusResponse, AppError> {
    if !state.redis.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "queue status requires Redis".to_string(),
        ));
    }
    let queues = state
        .redis
        .queue_stats(req.queue.as_deref())
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?
        .into_iter()
        .map(|stats| QueueInfo {
            name: stats.name,
            depth: stats.active,
            consumers: state
                .config
                .limits
                .global_concurrency
                .min(u32::MAX as usize) as u32,
            rate_per_second: stats.completed_last_minute as f64 / 60.0,
        })
        .collect();
    Ok(QueueStatusResponse { queues })
}
