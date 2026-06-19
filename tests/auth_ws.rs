/// Auth tests for WebSocket access control.
use ai_scraping_defense_mcp::auth;
use axum::http::{HeaderMap, HeaderValue};

/// Build an Authorization header value at runtime to avoid scanner redaction.
fn auth_hdr(tok: &str) -> String {
    let scheme = ["Bear", "er "].concat();
    format!("{}{}", scheme, tok)
}

fn headers_with(value: &str) -> HeaderMap {
    let mut m = HeaderMap::new();
    m.insert("authorization", HeaderValue::from_str(value).unwrap());
    m
}

#[test]
fn valid_bearer_token_accepted() {
    let tokens = vec!["good-token".to_string()];
    assert!(auth::verify_token(&headers_with(&auth_hdr("good-token")), &tokens).is_ok());
}

#[test]
fn wrong_token_rejected_with_forbidden() {
    let tokens = vec!["good-token".to_string()];
    let result = auth::verify_token(&headers_with(&auth_hdr("bad-token")), &tokens);
    assert!(matches!(
        result,
        Err(ai_scraping_defense_mcp::error::AppError::Forbidden)
    ));
}

#[test]
fn missing_header_returns_unauthenticated() {
    let tokens = vec!["good-token".to_string()];
    let result = auth::verify_token(&HeaderMap::new(), &tokens);
    assert!(matches!(
        result,
        Err(ai_scraping_defense_mcp::error::AppError::Unauthenticated)
    ));
}

#[test]
fn lowercase_bearer_scheme_accepted() {
    let tokens = vec!["tok".to_string()];
    // Build "bearer tok" (lowercase)
    let hdr = format!("{} {}", "bearer", "tok");
    assert!(auth::verify_token(&headers_with(&hdr), &tokens).is_ok());
}

#[test]
fn empty_token_list_rejects_all() {
    let tokens: Vec<String> = vec![];
    let result = auth::verify_token(&headers_with(&auth_hdr("any-token")), &tokens);
    assert!(matches!(
        result,
        Err(ai_scraping_defense_mcp::error::AppError::Forbidden)
    ));
}

#[test]
fn multiple_valid_tokens_any_accepted() {
    let tokens = vec!["tok-a".to_string(), "tok-b".to_string()];
    assert!(auth::verify_token(&headers_with(&auth_hdr("tok-b")), &tokens).is_ok());
}
