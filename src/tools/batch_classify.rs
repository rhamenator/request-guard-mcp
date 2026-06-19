use crate::error::AppError;
use crate::models::{
    request::BatchClassifyRequest,
    response::{BatchClassifyResponse, BatchItemResult},
};
use crate::state::AppState;
use crate::util::time::elapsed_ms;
use std::time::Instant;

pub async fn run(
    state: &AppState,
    req: BatchClassifyRequest,
) -> Result<BatchClassifyResponse, AppError> {
    let start = Instant::now();
    let max = state.config.limits.max_batch_size;
    let got = req.items.len();

    if got > max {
        return Err(AppError::BatchTooLarge { max, got });
    }

    let mut results = Vec::with_capacity(got);
    let error_count = 0usize;

    for (i, item) in req.items.into_iter().enumerate() {
        let result = crate::tools::classify::run(state, item).await;
        results.push(BatchItemResult {
            index: i,
            result: Some(result),
            error: None,
        });
    }

    let processed = results.len() - error_count;

    Ok(BatchClassifyResponse {
        results,
        total: got,
        processed,
        errors: error_count,
        latency_ms: elapsed_ms(start),
    })
}
