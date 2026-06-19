use serde_json::Value;

/// Redact a set of fields in a JSON value (in-place).
pub fn redact_fields(value: &mut Value, fields: &[String]) {
    match value {
        Value::Object(map) => {
            for key in map.keys().cloned().collect::<Vec<_>>() {
                if fields.iter().any(|f| f.eq_ignore_ascii_case(&key)) {
                    map.insert(key, Value::String("[REDACTED]".to_string()));
                } else if let Some(v) = map.get_mut(&key) {
                    redact_fields(v, fields);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_fields(item, fields);
            }
        }
        _ => {}
    }
}

/// Serialize a value to compact JSON, returning an error string on failure.
pub fn to_json_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Parse JSON from bytes, returning None on failure.
pub fn parse_json(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}
