use sha2::{Digest, Sha256};

/// Compute a SHA-256 hex digest of the input bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute a stable fingerprint from every field used by the rule engine.
pub fn request_fingerprint(
    ip: Option<&str>,
    ua: Option<&str>,
    path: Option<&str>,
    method: Option<&str>,
    headers: Option<&std::collections::HashMap<String, String>>,
    tls_ja3: Option<&str>,
    tls_ja4: Option<&str>,
) -> String {
    let mut canonical_headers = headers
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| format!("{}:{}", key.to_lowercase(), value.trim()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    canonical_headers.sort_unstable();
    let input = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        ip.unwrap_or(""),
        ua.unwrap_or(""),
        path.unwrap_or(""),
        method.unwrap_or("").to_uppercase(),
        canonical_headers.join(","),
        tls_ja3.unwrap_or("").to_ascii_lowercase(),
        tls_ja4.unwrap_or("").to_ascii_lowercase(),
    );
    sha256_hex(input.as_bytes())
}
