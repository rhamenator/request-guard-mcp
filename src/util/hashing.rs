use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::models::request::ClassifyRequest;

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
/// caller field used by the rule engine. TLS values participate only after the
/// server verifies a short-lived request binding.
pub fn request_fingerprint(caller_scope: &str, request: &ClassifyRequest) -> String {
    let mut canonical_headers = request
        .headers
        .as_ref()
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| format!("{}:{}", key.to_lowercase(), value.trim()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    canonical_headers.sort_unstable();
    let input = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        caller_scope,
        request.ip.as_deref().unwrap_or(""),
        request.user_agent.as_deref().unwrap_or(""),
        request.path.as_deref().unwrap_or(""),
        request.method.as_deref().unwrap_or("").to_uppercase(),
        canonical_headers.join(","),
        request.tls_fingerprint_verified,
        if request.tls_fingerprint_verified {
            request.tls_ja3.as_deref().unwrap_or("")
        } else {
            ""
        },
        if request.tls_fingerprint_verified {
            request.tls_ja4.as_deref().unwrap_or("")
        } else {
            ""
        },
        if request.tls_fingerprint_verified {
            request.tls_fingerprint_source.as_deref().unwrap_or("")
        } else {
            ""
        },
    );
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ClassifyRequest {
        ClassifyRequest {
            ip: Some("198.51.100.1".into()),
            user_agent: Some("Mozilla/5.0".into()),
            path: Some("/".into()),
            method: Some("GET".into()),
            headers: None,
            body_snippet: None,
            referer: None,
            accept: None,
            request_id: None,
            timestamp: None,
            tls_ja3: None,
            tls_ja4: None,
            tls_fingerprint_source: None,
            tls_fingerprint_attestation: None,
            tls_fingerprint_verified: false,
            extra: None,
        }
    }

    #[test]
    fn cache_keys_are_scoped_to_server_authenticated_callers() {
        let request = request();
        let first = request_fingerprint("caller:first", &request);
        let second = request_fingerprint("caller:second", &request);

        assert_ne!(first, second);
    }

    #[test]
    fn verified_tls_values_partition_cache_identity() {
        let mut request = request();
        request.tls_fingerprint_verified = true;
        request.tls_ja3 = Some("72a589da586844d7f0818ce684948eea".into());
        request.tls_fingerprint_source = Some("envoy".into());
        let first = request_fingerprint("caller", &request);
        request.tls_ja3 = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        let second = request_fingerprint("caller", &request);
        assert_ne!(first, second);
    }
}
