use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
    let canonical_headers = request.headers.as_ref().map(|values| {
        values
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim()))
            .collect::<BTreeMap<_, _>>()
    });
    let verified_tls = request.tls_fingerprint_verified.then(|| {
        serde_json::json!({
            "ja3": request.tls_ja3,
            "ja4": request.tls_ja4,
            "source": request.tls_fingerprint_source,
        })
    });
    let input = serde_json::json!({
        "caller_scope": caller_scope,
        "ip": request.ip,
        "user_agent": request.user_agent,
        "path": request.path,
        "method": request.method.as_deref().map(str::to_ascii_uppercase),
        "headers": canonical_headers,
        "body_snippet": request.body_snippet,
        "referer": request.referer,
        "accept": request.accept,
        "extra": request.extra,
        "verified_tls": verified_tls,
    });
    sha256_hex(input.to_string().as_bytes())
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

    #[test]
    fn all_decision_inputs_partition_cache_identity() {
        let base = request();
        let original = request_fingerprint("caller", &base);

        let mut changed = base.clone();
        changed.body_snippet = Some("payload".into());
        assert_ne!(original, request_fingerprint("caller", &changed));

        let mut changed = base.clone();
        changed.referer = Some("https://example.test".into());
        assert_ne!(original, request_fingerprint("caller", &changed));

        let mut changed = base;
        changed.extra = Some(serde_json::json!({"risk": "high"}));
        assert_ne!(original, request_fingerprint("caller", &changed));
    }
}
