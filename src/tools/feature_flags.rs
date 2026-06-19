use crate::models::{request::FeatureFlagsRequest, response::FeatureFlagsResponse};
use crate::state::AppState;
use std::collections::HashMap;

pub async fn run(state: &AppState, req: FeatureFlagsRequest) -> FeatureFlagsResponse {
    let flags: HashMap<String, bool> = if let Some(name) = &req.flag {
        let val = state.feature_flags.get(name).map(|v| *v).unwrap_or(false);
        [(name.clone(), val)].into_iter().collect()
    } else {
        state
            .feature_flags
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    };
    FeatureFlagsResponse { flags }
}
