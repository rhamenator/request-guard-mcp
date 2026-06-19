use sha2::{Digest, Sha256};

/// Compute a SHA-256 hex digest of the input bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute a fast fingerprint string from a classify request's key fields.
pub fn request_fingerprint(ip: Option<&str>, ua: Option<&str>, path: Option<&str>) -> String {
    let input = format!(
        "{}|{}|{}",
        ip.unwrap_or(""),
        ua.unwrap_or(""),
        path.unwrap_or("")
    );
    sha256_hex(input.as_bytes())
}
