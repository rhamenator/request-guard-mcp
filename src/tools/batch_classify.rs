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
    run_scoped(state, req, "internal").await
}

pub async fn run_scoped(
    state: &AppState,
    req: BatchClassifyRequest,
    caller_scope: &str,
) -> Result<BatchClassifyResponse, AppError> {
    let start = Instant::now();
    let max = state.config.limits.max_batch_size;
    let got = req.items.len();

    if got > max {
        return Err(AppError::BatchTooLarge { max, got });
    }

    let mut results = Vec::with_capacity(got);
    let mut error_count = 0usize;
    let fail_fast = req
        .options
        .as_ref()
        .is_some_and(|options| options.fail_fast);

    for (i, item) in req.items.into_iter().enumerate() {
        match crate::tools::classify::run_scoped(state, item, caller_scope).await {
            Ok(result) => results.push(BatchItemResult {
                index: i,
                result: Some(result),
                error: None,
            }),
            Err(error) => {
                error_count += 1;
                if fail_fast {
                    return Err(error);
                }
                results.push(BatchItemResult {
                    index: i,
                    result: None,
                    error: Some(error.code().to_string()),
                });
            }
        }
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
