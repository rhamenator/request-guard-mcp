use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Compute a SHA-256 hex digest of the input bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute an HMAC-SHA256 hex digest keyed with a server-side secret, for
/// identifiers derived from secrets (e.g. bearer tokens) that land in shared
/// storage such as Redis keys. Unlike a bare hash, the digest is useless for
/// offline dictionary attacks without the key.
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Compute a stable cache key from the authenticated caller scope and every
/// caller field used by the rule engine. Caller-asserted TLS fingerprints are
/// deliberately excluded because this server cannot verify the client TLS
/// handshake that produced them.
pub fn request_fingerprint(
    caller_scope: &str,
    ip: Option<&str>,
    ua: Option<&str>,
    path: Option<&str>,
    method: Option<&str>,
    headers: Option<&std::collections::HashMap<String, String>>,
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
        "{}|{}|{}|{}|{}|{}",
        caller_scope,
        ip.unwrap_or(""),
        ua.unwrap_or(""),
        path.unwrap_or(""),
        method.unwrap_or("").to_uppercase(),
        canonical_headers.join(","),
    );
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keys_are_scoped_to_server_authenticated_callers() {
        let first = request_fingerprint(
            "caller:first",
            Some("198.51.100.1"),
            Some("Mozilla/5.0"),
            Some("/"),
            Some("GET"),
            None,
        );
        let second = request_fingerprint(
            "caller:second",
            Some("198.51.100.1"),
            Some("Mozilla/5.0"),
            Some("/"),
            Some("GET"),
            None,
        );

        assert_ne!(first, second);
    }
}
