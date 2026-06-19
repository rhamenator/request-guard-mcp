use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns the current Unix timestamp in milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns the elapsed milliseconds since a start `Instant`.
pub fn elapsed_ms(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Format a Unix timestamp as ISO-8601 UTC string.
pub fn format_utc(secs: u64) -> String {
    use chrono::{DateTime, TimeZone, Utc};
    let dt: DateTime<Utc> = Utc
        .timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    dt.to_rfc3339()
}

/// Return current UTC time as RFC3339.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
