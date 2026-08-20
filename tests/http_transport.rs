use axum::http::{header::AUTHORIZATION, HeaderValue, StatusCode};
use axum_test::TestServer;
use request_guard_mcp::config::Config;
use request_guard_mcp::mcp::{
    server::{build_router, ServerState},
    tool_registry::build_registry,
};
use request_guard_mcp::state::AppState;
use serde_json::{json, Value};
use std::sync::Arc;

fn server(auth_enabled: bool) -> TestServer {
    let mut config = Config::default();
    config.auth.enabled = auth_enabled;
    config.auth.tokens = vec!["http-test-token".to_string()];
    let max_body = config.limits.max_request_bytes;
    let state = ServerState {
        app: Arc::new(AppState::new(config)),
        registry: Arc::new(build_registry()),
    };
    TestServer::new(build_router(state, max_body))
}

#[tokio::test]
async fn post_mcp_dispatches_json_rpc_request() {
    let response = server(false)
        .post("/mcp")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "classify",
            "params": {"user_agent": "GPTBot/1.0", "path": "/"}
        }))
        .await;
    response.assert_status_ok();
    let value: Value = response.json();
    assert_eq!(value["id"], 7);
    assert!(value["result"]["score"].as_f64().unwrap() > 0.0);
}

#[tokio::test]
async fn post_mcp_enforces_same_auth_as_websocket_upgrade() {
    let response = server(true)
        .post("/mcp")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "health"}))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);

    let authorized = server(true)
        .post("/mcp")
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer http-test-token"),
        )
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "health"}))
        .await;
    authorized.assert_status_ok();
}

#[tokio::test]
async fn post_mcp_notifications_return_no_content() {
    let response = server(false)
        .post("/mcp")
        .json(&json!({"jsonrpc": "2.0", "method": "warmup", "params": {}}))
        .await;
    response.assert_status(StatusCode::NO_CONTENT);
}
