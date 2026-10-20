use axum::http::{
    header::{AUTHORIZATION, ORIGIN, X_CONTENT_TYPE_OPTIONS},
    HeaderValue, StatusCode,
};
use axum_test::TestServer;
use request_guard_mcp::config::Config;
use request_guard_mcp::mcp::{
    server::{build_router, ServerState},
    tool_registry::build_registry,
};
use request_guard_mcp::state::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

fn server(auth_enabled: bool) -> TestServer {
    server_with_origins(auth_enabled, &[])
}

fn server_with_origins(auth_enabled: bool, origins: &[&str]) -> TestServer {
    let mut config = Config::default();
    config.auth.enabled = auth_enabled;
    config.auth.tokens = vec!["http-test-token".to_string()];
    config.auth.allowed_origins = origins.iter().map(|origin| (*origin).to_string()).collect();
    let max_body = config.limits.max_request_bytes;
    let state = ServerState {
        app: Arc::new(AppState::new(config)),
        registry: Arc::new(build_registry()),
    };
    TestServer::new(build_router(state, max_body))
}

#[tokio::test]
async fn mcp_post_requires_explicit_browser_origin_allowlist() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let rejected = server(false)
        .post("/mcp")
        .add_header(ORIGIN, HeaderValue::from_static("https://evil.example"))
        .json(&request)
        .await;
    rejected.assert_status(StatusCode::FORBIDDEN);

    let accepted = server_with_origins(false, &["https://console.example"])
        .post("/mcp")
        .add_header(ORIGIN, HeaderValue::from_static("https://console.example"))
        .json(&request)
        .await;
    accepted.assert_status_ok();

    let rebind = server_with_origins(false, &["https://console.example"])
        .post("/mcp")
        .add_header(ORIGIN, HeaderValue::from_static("https://evil.example"))
        .add_header("host", HeaderValue::from_static("evil.example"))
        .json(&request)
        .await;
    rebind.assert_status(StatusCode::FORBIDDEN);
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
async fn post_mcp_rejects_invalid_json_rpc_envelopes() {
    let server = server(false);
    for payload in [
        json!({"jsonrpc": "1.0", "id": 1, "method": "ping"}),
        json!({"id": 1, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": true, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": {}, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": [], "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 1}),
        json!({"jsonrpc": "2.0", "id": 1, "method": 42}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "result": {}}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": 42}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": null}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}),
        json!([]),
    ] {
        let response = server.post("/mcp").json(&payload).await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["error"]["code"], -32600, "payload: {payload}");
        assert_eq!(body["id"], Value::Null);
        assert!(body.get("result").is_none());
    }
}

#[tokio::test]
async fn post_mcp_enforces_same_auth_as_websocket_upgrade() {
    let response = server(true)
        .post("/mcp")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "health"}))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(response.header(X_CONTENT_TYPE_OPTIONS), "nosniff");

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
async fn unauthenticated_post_is_rejected_before_body_arrives() {
    let mut config = Config::default();
    config.auth.enabled = true;
    config.auth.tokens = vec!["http-test-token".to_string()];
    let max_body = config.limits.max_request_bytes;
    let state = ServerState {
        app: Arc::new(AppState::new(config)),
        registry: Arc::new(build_registry()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        axum::serve(listener, build_router(state, max_body))
            .await
            .unwrap();
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\nx")
        .await
        .unwrap();
    let status_line = timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            assert!(line.len() < 256, "HTTP status line is too long");
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).await.unwrap();
            assert_ne!(read, 0, "connection closed before HTTP status line");
            line.push(byte[0]);
        }
        line
    })
    .await
    .expect("authentication must not wait for the incomplete body");
    assert!(std::str::from_utf8(&status_line)
        .unwrap()
        .starts_with("HTTP/1.1 401 "));
    server_task.abort();
}

#[tokio::test]
async fn post_mcp_notifications_and_client_responses_return_accepted() {
    let response = server(false)
        .post("/mcp")
        .json(&json!({"jsonrpc": "2.0", "method": "warmup", "params": {}}))
        .await;
    response.assert_status(StatusCode::ACCEPTED);
    assert!(response.as_bytes().is_empty());

    let response = server(false)
        .post("/mcp")
        .json(&json!({"jsonrpc": "2.0", "id": 9, "result": {}}))
        .await;
    response.assert_status(StatusCode::ACCEPTED);
    assert!(response.as_bytes().is_empty());
}

#[tokio::test]
async fn initialize_counteroffers_supported_revision_over_http() {
    let response = server(false)
        .post("/mcp")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "initialize",
            "params": {"protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "probe", "version": "1"}}
        }))
        .await;
    response.assert_status_ok();
    let value: Value = response.json();
    assert_eq!(value["result"]["protocolVersion"], "2025-06-18");
}
