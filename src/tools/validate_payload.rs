use crate::models::{
    request::ValidatePayloadRequest,
    response::{ValidatePayloadResponse, ValidationError},
};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: ValidatePayloadRequest) -> ValidatePayloadResponse {
    // Basic structural validation based on tool name.
    let errors = validate_for_tool(&req.tool, &req.payload);
    ValidatePayloadResponse {
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_for_tool(tool: &str, payload: &serde_json::Value) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    match tool {
        "classify" => {
            // At least one of ip, user_agent, path must be present
            let has_ip = payload.get("ip").is_some();
            let has_ua = payload.get("user_agent").is_some();
            let has_path = payload.get("path").is_some();
            if !has_ip && !has_ua && !has_path {
                errors.push(ValidationError {
                    path: "/".to_string(),
                    message: "at least one of 'ip', 'user_agent', or 'path' is required"
                        .to_string(),
                });
            }
        }
        "batch_classify" => {
            if payload
                .get("items")
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(true)
            {
                errors.push(ValidationError {
                    path: "/items".to_string(),
                    message: "'items' must be a non-empty array".to_string(),
                });
            }
        }
        "feedback" => {
            for field in &["request_id", "correct_verdict"] {
                if payload.get(field).is_none() {
                    errors.push(ValidationError {
                        path: format!("/{field}"),
                        message: format!("'{field}' is required"),
                    });
                }
            }
        }
        "enrich_ip" if payload.get("ip").is_none() => {
            errors.push(ValidationError {
                path: "/ip".to_string(),
                message: "'ip' is required".to_string(),
            });
        }
        _ => {
            // Unknown tool - no specific validation
        }
    }

    errors
}
