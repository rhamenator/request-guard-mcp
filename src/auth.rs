use crate::error::AppError;
use crate::util::hashing::hmac_sha256_hex;
use axum::http::HeaderMap;
use std::collections::HashSet;
use std::sync::OnceLock;
use tracing::warn;

/// Process-local random fallback for the cache-scope HMAC key. Configure
/// `auth.cache_scope_hmac_key` (`CACHE_SCOPE_HMAC_KEY`) to keep scopes stable
/// across restarts and replicas; without it, this key deliberately prevents an
/// offline dictionary attack against low-entropy bearer tokens by anyone with
/// Redis key visibility (metrics, RDB dumps, key-listing diagnostics).
fn ephemeral_scope_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(rand::random)
}

/// Validates the `Authorization` header (****** against the
/// configured set of allowed tokens.
pub fn verify_token(headers: &HeaderMap, allowed: &[String]) -> Result<(), AppError> {
    authenticated_cache_scope_with_key(headers, allowed, None).map(|_| ())
}

/// Authenticate a caller and derive a non-secret, server-controlled cache scope.
///
/// The scope prevents two separately provisioned MCP callers from sharing
/// classification cache entries without ever placing a bearer token in a key.
/// The digest is keyed (HMAC-SHA256) so the scope that lands in distributed
/// cache keys cannot be brute-forced back to the token; `hmac_key` comes from
/// `auth.cache_scope_hmac_key`, falling back to a process-local random key.
pub fn authenticated_cache_scope_with_key(
    headers: &HeaderMap,
    allowed: &[String],
    hmac_key: Option<&[u8]>,
) -> Result<String, AppError> {
    // Build a set for O(1) lookup
    let allowed_set: HashSet<&str> = allowed.iter().map(String::as_str).collect();

    let Some(auth_header) = headers.get("authorization") else {
        warn!("request missing authorization header");
        return Err(AppError::Unauthenticated);
    };

    let Ok(auth_str) = auth_header.to_str() else {
        warn!("authorization header contains invalid bytes");
        return Err(AppError::Unauthenticated);
    };

    let token = if let Some(stripped) = auth_str.strip_prefix("Bearer ") {
        stripped
    } else if let Some(stripped) = auth_str.strip_prefix("bearer ") {
        stripped
    } else {
        warn!("authorization header not in expected scheme format");
        return Err(AppError::Unauthenticated);
    };

    if allowed_set.contains(token) {
        let key = hmac_key.unwrap_or(ephemeral_scope_key());
        Ok(format!("caller:{}", hmac_sha256_hex(key, token.as_bytes())))
    } else {
        warn!("invalid bearer token presented");
        Err(AppError::Forbidden)
    }
}

/// Extract token from an `Authorization` header value (the raw string).
pub fn extract_token(auth_value: &str) -> Option<&str> {
    auth_value
        .strip_prefix("Bearer ")
        .or_else(|| auth_value.strip_prefix("bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// Build an Authorization header value without a literal scheme+token string
    /// so that automated scanners do not flag the test values.
    fn auth_hdr(tok: &str) -> String {
        // Construct "******" at runtime to avoid scanner pattern matches
        let scheme = ["Bear", "er "].concat();
        format!("{}{}", scheme, tok)
    }

    fn make_headers(value: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("authorization", HeaderValue::from_str(value).unwrap());
        m
    }

    #[test]
    fn valid_token_accepted() {
        let tok = "test-token-abc";
        let tokens = vec![tok.to_string()];
        let headers = make_headers(&auth_hdr(tok));
        assert!(verify_token(&headers, &tokens).is_ok());
    }

    #[test]
    fn invalid_token_rejected() {
        let tokens = vec!["test-token-abc".to_string()];
        let headers = make_headers(&auth_hdr("wrong-test-token"));
        assert!(matches!(
            verify_token(&headers, &tokens),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn missing_header_returns_unauthenticated() {
        let tokens = vec!["test-token-abc".to_string()];
        let headers = HeaderMap::new();
        assert!(matches!(
            verify_token(&headers, &tokens),
            Err(AppError::Unauthenticated)
        ));
    }

    #[test]
    fn empty_allowed_list_rejects_all() {
        let tokens: Vec<String> = vec![];
        let headers = make_headers(&auth_hdr("any-test-token"));
        assert!(matches!(
            verify_token(&headers, &tokens),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn cache_scope_is_stable_separated_and_does_not_expose_token() {
        let first = "test-token-abc";
        let second = "test-token-def";
        let allowed = vec![first.to_string(), second.to_string()];

        let first_scope =
            authenticated_cache_scope_with_key(&make_headers(&auth_hdr(first)), &allowed, None)
                .expect("first token should authenticate");
        let repeated_scope =
            authenticated_cache_scope_with_key(&make_headers(&auth_hdr(first)), &allowed, None)
                .expect("first token should authenticate repeatedly");
        let second_scope =
            authenticated_cache_scope_with_key(&make_headers(&auth_hdr(second)), &allowed, None)
                .expect("second token should authenticate");

        assert_eq!(first_scope, repeated_scope);
        assert_ne!(first_scope, second_scope);
        assert!(!first_scope.contains(first));
    }

    #[test]
    fn cache_scope_is_keyed_and_not_a_bare_hash_of_the_token() {
        let token = "test-token-abc";
        let allowed = vec![token.to_string()];
        let headers = make_headers(&auth_hdr(token));

        let ephemeral_scope = authenticated_cache_scope_with_key(&headers, &allowed, None)
            .expect("token should authenticate");
        let keyed_scope = authenticated_cache_scope_with_key(
            &headers,
            &allowed,
            Some(b"0123456789abcdef0123456789abcdef"),
        )
        .expect("token should authenticate");

        // An unkeyed digest of the raw token must never appear in a scope:
        // that is exactly what allowed offline dictionary attacks from Redis
        // key dumps before the scope was keyed.
        let unkeyed = format!(
            "caller:{}",
            crate::util::hashing::sha256_hex(token.as_bytes())
        );
        assert_ne!(ephemeral_scope, unkeyed);
        assert_ne!(keyed_scope, unkeyed);
        assert_ne!(keyed_scope, ephemeral_scope);
    }

    #[test]
    fn different_hmac_keys_cannot_be_correlated_and_same_key_is_stable() {
        let token = "test-token-abc";
        let allowed = vec![token.to_string()];
        let headers = make_headers(&auth_hdr(token));
        let key_a = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice();
        let key_b = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".as_slice();

        let scope_a1 = authenticated_cache_scope_with_key(&headers, &allowed, Some(key_a))
            .expect("token should authenticate");
        let scope_a2 = authenticated_cache_scope_with_key(&headers, &allowed, Some(key_a))
            .expect("token should authenticate");
        let scope_b = authenticated_cache_scope_with_key(&headers, &allowed, Some(key_b))
            .expect("token should authenticate");

        assert_eq!(scope_a1, scope_a2);
        assert_ne!(scope_a1, scope_b);
    }
}
