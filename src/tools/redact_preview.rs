use crate::models::{request::RedactPreviewRequest, response::RedactPreviewResponse};
use crate::state::AppState;
use crate::util::json::redact_fields;
use serde_json::Value;

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
    preview(req)
}

fn preview(req: RedactPreviewRequest) -> RedactPreviewResponse {
    let mut payload = req.payload;
    let fields: Vec<String> = req.fields.unwrap_or_else(|| {
        DEFAULT_SENSITIVE_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    let mut found = vec![false; fields.len()];
    find_redacted_keys(&payload, &fields, &mut found);
    redact_fields(&mut payload, &fields);
    let fields_redacted: Vec<String> = fields
        .iter()
        .zip(found)
        .filter(|(_, was_redacted)| *was_redacted)
        .map(|(field, _)| field)
        .cloned()
        .collect();

    RedactPreviewResponse {
        redacted: payload,
        fields_redacted,
    }
}

fn find_redacted_keys(value: &Value, fields: &[String], found: &mut [bool]) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let mut replaced = false;
                for (index, field) in fields.iter().enumerate() {
                    if field.eq_ignore_ascii_case(key) {
                        found[index] = true;
                        replaced = true;
                    }
                }
                // redact_fields replaces the whole value at a matching key,
                // so nested keys within it are not visited.
                if !replaced {
                    find_redacted_keys(child, fields, found);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                find_redacted_keys(item, fields, found);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::preview;
    use crate::models::request::RedactPreviewRequest;
    use serde_json::json;

    #[test]
    fn reports_only_keys_actually_replaced() {
        let result = preview(RedactPreviewRequest {
            payload: json!({
                "token": "synthetic",
                "note": "api_key is rotated",
                "already": "[REDACTED]",
                "nested": [{"PASSWORD": "synthetic"}]
            }),
            fields: Some(vec!["token".into(), "api_key".into(), "password".into()]),
        });
        assert_eq!(result.fields_redacted, vec!["token", "password"]);
        assert_eq!(result.redacted["token"], "[REDACTED]");
        assert_eq!(result.redacted["nested"][0]["PASSWORD"], "[REDACTED]");
        assert_eq!(result.redacted["note"], "api_key is rotated");
    }

    #[test]
    fn replaced_parent_does_not_claim_its_nested_key() {
        let result = preview(RedactPreviewRequest {
            payload: json!({"token": {"password": "synthetic"}}),
            fields: Some(vec!["token".into(), "password".into()]),
        });
        assert_eq!(result.fields_redacted, vec!["token"]);
        assert_eq!(result.redacted["token"], "[REDACTED]");
    }

    #[test]
    fn rejects_misspelled_custom_fields() {
        let request = serde_json::from_value::<RedactPreviewRequest>(json!({
            "payload": {"access_token": "synthetic"},
            "field": ["access_token"]
        }));
        assert!(request.is_err());
    }
}
