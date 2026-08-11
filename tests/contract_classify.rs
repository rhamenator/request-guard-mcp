/// Contract tests for the classify tool.
use request_guard_mcp::*;

fn make_state() -> state::AppState {
    state::AppState::new(config::Config::default())
}

fn bot_request() -> models::request::ClassifyRequest {
    models::request::ClassifyRequest {
        ip: Some("1.2.3.4".to_string()),
        user_agent: Some("GPTBot/1.0".to_string()),
        path: Some("/data/export".to_string()),
        method: Some("GET".to_string()),
        headers: None,
        body_snippet: None,
        referer: None,
        accept: None,
        request_id: Some("test-bot-001".to_string()),
        timestamp: None,
        extra: None,
    }
}

fn browser_request() -> models::request::ClassifyRequest {
    use std::collections::HashMap;
    let mut headers = HashMap::new();
    headers.insert(
        "accept".to_string(),
        "text/html,application/xhtml+xml".to_string(),
    );
    headers.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());

    models::request::ClassifyRequest {
        ip: Some("203.0.113.1".to_string()),
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                .to_string(),
        ),
        path: Some("/index.html".to_string()),
        method: Some("GET".to_string()),
        headers: Some(headers),
        body_snippet: None,
        referer: Some("https://www.google.com".to_string()),
        accept: None,
        request_id: Some("test-browser-001".to_string()),
        timestamp: None,
        extra: None,
    }
}

#[tokio::test]
async fn gptbot_is_blocked_or_flagged() {
    let state = make_state();
    let resp = tools::classify::run(&state, bot_request()).await.unwrap();
    assert!(
        matches!(
            resp.verdict,
            models::enums::Verdict::Block | models::enums::Verdict::Flag
        ),
        "expected block or flag for GPTBot, got {:?}",
        resp.verdict
    );
    assert!(resp.score >= 0.55, "score too low: {}", resp.score);
    assert!(!resp.request_id.is_empty());
    assert!(!resp.model_version.is_empty());
}

#[tokio::test]
async fn browser_request_is_allowed() {
    let state = make_state();
    let resp = tools::classify::run(&state, browser_request())
        .await
        .unwrap();
    assert_eq!(
        resp.verdict,
        models::enums::Verdict::Allow,
        "expected allow for clean browser, got {:?}",
        resp.verdict
    );
    assert!(resp.score < 0.40, "score too high: {}", resp.score);
}

#[tokio::test]
async fn response_has_required_fields() {
    let state = make_state();
    let resp = tools::classify::run(&state, bot_request()).await.unwrap();
    assert!(!resp.request_id.is_empty());
    assert!(!resp.model_version.is_empty());
    // Score must be in [0, 1]
    assert!(
        resp.score >= 0.0 && resp.score <= 1.0,
        "score out of range: {}",
        resp.score
    );
}

#[tokio::test]
async fn classify_preserves_request_id() {
    let state = make_state();
    let mut req = browser_request();
    req.request_id = Some("my-custom-id".to_string());
    let resp = tools::classify::run(&state, req).await.unwrap();
    assert_eq!(resp.request_id, "my-custom-id");
}

#[tokio::test]
async fn scrapy_ua_is_flagged_or_blocked() {
    let state = make_state();
    let req = models::request::ClassifyRequest {
        ip: None,
        user_agent: Some("Scrapy/2.11 (+https://scrapy.org)".to_string()),
        path: Some("/products".to_string()),
        method: Some("GET".to_string()),
        headers: None,
        body_snippet: None,
        referer: None,
        accept: None,
        request_id: None,
        timestamp: None,
        extra: None,
    };
    let resp = tools::classify::run(&state, req).await.unwrap();
    assert!(
        !matches!(resp.verdict, models::enums::Verdict::Allow),
        "expected non-allow for Scrapy, got {:?}",
        resp.verdict
    );
}

#[tokio::test]
async fn sensitive_path_raises_score() {
    let state = make_state();
    let req = models::request::ClassifyRequest {
        ip: None,
        user_agent: None,
        path: Some("/.env".to_string()),
        method: Some("GET".to_string()),
        headers: None,
        body_snippet: None,
        referer: None,
        accept: None,
        request_id: None,
        timestamp: None,
        extra: None,
    };
    let resp = tools::classify::run(&state, req).await.unwrap();
    assert!(resp.score > 0.0, "expected non-zero score for .env path");
}

#[tokio::test]
async fn cache_key_includes_method_and_headers() {
    let state = make_state();
    let mut first = browser_request();
    first.ip = Some("198.51.100.20".to_string());
    first.user_agent = Some("Mozilla/5.0".to_string());
    first.path = Some("/same".to_string());
    first.method = Some("GET".to_string());
    let first_response = tools::classify::run(&state, first.clone()).await.unwrap();

    first.method = Some("BREW".to_string());
    first.headers = None;
    first.request_id = Some("different-request".to_string());
    let second_response = tools::classify::run(&state, first).await.unwrap();

    assert!(second_response.score > first_response.score);
    assert!(second_response
        .signals
        .iter()
        .any(|signal| signal.name == "method_unusual"));
}
