/// Contract tests for the explain tool.
use ai_scraping_defense_mcp::*;

fn make_state() -> state::AppState {
    state::AppState::new(config::Config::default())
}

#[tokio::test]
async fn explain_returns_explanation() {
    let state = make_state();
    let classification = serde_json::json!({
        "ip": "1.2.3.4",
        "user_agent": "GPTBot/1.0",
        "path": "/articles",
        "method": "GET"
    });
    let req = models::request::ExplainRequest {
        classification,
        format: None,
    };
    let resp = tools::explain::run(&state, req).await;
    assert!(!resp.explanation.is_empty());
    assert!(!resp.request_id.is_empty());
}

#[tokio::test]
async fn explain_includes_recommendations() {
    let state = make_state();
    let classification = serde_json::json!({
        "user_agent": "GPTBot/1.0",
        "path": "/"
    });
    let req = models::request::ExplainRequest {
        classification,
        format: None,
    };
    let resp = tools::explain::run(&state, req).await;
    assert!(!resp.recommendations.is_empty());
}

#[tokio::test]
async fn explain_handles_non_classify_input() {
    let state = make_state();
    let classification = serde_json::json!({
        "verdict": "block",
        "score": 0.9
    });
    let req = models::request::ExplainRequest {
        classification,
        format: None,
    };
    // Should not panic; returns a generic explanation
    let resp = tools::explain::run(&state, req).await;
    assert!(!resp.explanation.is_empty());
}
