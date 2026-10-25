use crate::error::AppError;
use crate::models::{request::FeatureFlagsRequest, response::FeatureFlagsResponse};
use crate::state::AppState;
use std::collections::HashMap;

pub async fn run(
    state: &AppState,
    req: FeatureFlagsRequest,
) -> Result<FeatureFlagsResponse, AppError> {
    let flags: HashMap<String, bool> = if let Some(name) = &req.flag {
        let val = state
            .feature_flags
            .get(name)
            .map(|v| *v)
            .ok_or_else(|| AppError::InvalidRequest("unsupported feature flag".to_string()))?;
        [(name.clone(), val)].into_iter().collect()
    } else {
        state
            .feature_flags
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    };
    Ok(FeatureFlagsResponse { flags })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn unknown_flag_is_an_error_not_a_disabled_flag() {
        let state = AppState::new(Config::default());
        assert!(run(&state, FeatureFlagsRequest { flag: None })
            .await
            .is_ok());
        assert!(run(
            &state,
            FeatureFlagsRequest {
                flag: Some("batch_classify".into())
            }
        )
        .await
        .is_ok());
        assert!(matches!(
            run(
                &state,
                FeatureFlagsRequest {
                    flag: Some("not_a_flag".into())
                }
            )
            .await,
            Err(AppError::InvalidRequest(_))
        ));
    }
}
