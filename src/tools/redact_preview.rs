use crate::models::{request::RedactPreviewRequest, response::RedactPreviewResponse};
use crate::state::AppState;
use crate::util::json::redact_fields;

const DEFAULT_SENSITIVE_FIELDS: &[&str] = &[
    "authorization",
    "password",
    "token",
    "secret",
    "api_key",
    "cookie",
    "x-api-key",
    "x-auth-token",
];

pub async fn run(_state: &AppState, req: RedactPreviewRequest) -> RedactPreviewResponse {
    let mut payload = req.payload.clone();
    let fields: Vec<String> = req.fields.unwrap_or_else(|| {
        DEFAULT_SENSITIVE_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    let before_json = serde_json::to_string(&payload).unwrap_or_default();
    redact_fields(&mut payload, &fields);
    let after_json = serde_json::to_string(&payload).unwrap_or_default();

    // Determine which fields were actually redacted
    let fields_redacted: Vec<String> = fields
        .iter()
        .filter(|f| before_json.contains(f.as_str()) && after_json.contains("[REDACTED]"))
        .cloned()
        .collect();

    RedactPreviewResponse {
        redacted: payload,
        fields_redacted,
    }
}
