use crate::models::{
    request::QueueStatusRequest,
    response::{QueueInfo, QueueStatusResponse},
};
use crate::state::AppState;

pub async fn run(_state: &AppState, _req: QueueStatusRequest) -> QueueStatusResponse {
    // In production, query actual queue depths from Redis/RabbitMQ.
    QueueStatusResponse {
        queues: vec![QueueInfo {
            name: "classify".to_string(),
            depth: 0,
            consumers: 1,
            rate_per_second: 0.0,
        }],
    }
}
