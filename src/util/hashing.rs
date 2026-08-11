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
) -> String {
    let mut header_names = headers
        .map(|values| {
            values
                .keys()
                .map(|key| key.to_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    header_names.sort_unstable();
    header_names.dedup();
    let input = format!(
        "{}|{}|{}|{}|{}",
        ip.unwrap_or(""),
        ua.unwrap_or(""),
        path.unwrap_or(""),
        method.unwrap_or("").to_uppercase(),
        header_names.join(",")
    );
    sha256_hex(input.as_bytes())
}
