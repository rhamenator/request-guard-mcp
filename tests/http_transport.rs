use axum::http::{
    header::{ALLOW, AUTHORIZATION, CONTENT_TYPE, ORIGIN, X_CONTENT_TYPE_OPTIONS},
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
async fn plain_mcp_get_reports_no_sse_stream_after_auth_and_origin_checks() {
    let unauthenticated = server(true).get("/mcp").await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);

    let denied_origin = server_with_origins(false, &["https://console.example"])
        .get("/mcp")
        .add_header(ORIGIN, HeaderValue::from_static("https://evil.example"))
        .await;
    denied_origin.assert_status(StatusCode::FORBIDDEN);

    let no_sse = server(true)
        .get("/mcp")
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer http-test-token"),
        )
        .add_header("accept", HeaderValue::from_static("text/event-stream"))
        .await;
    no_sse.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    assert!(no_sse.as_bytes().is_empty());
    assert_eq!(no_sse.header(ALLOW), "POST, GET");

    let unrelated_upgrade = server(false)
        .get("/mcp")
        .add_header("upgrade", HeaderValue::from_static("h2c"))
        .add_header("connection", HeaderValue::from_static("upgrade"))
        .await;
    unrelated_upgrade.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(unrelated_upgrade.header(ALLOW), "POST, GET");
}

#[tokio::test]
async fn explicit_mcp_protocol_version_is_checked_before_post_body() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let accepted = server(false)
        .post("/mcp")
        .add_header(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2025-06-18"),
        )
        .json(&request)
        .await;
    accepted.assert_status_ok();

    // Missing remains accepted for older clients without a session header.
    server(false)
        .post("/mcp")
        .json(&request)
        .await
        .assert_status_ok();

    for version in [
        "2025-03-26",
        "2026-07-28",
        "2025-06-18, 2025-06-18",
        "",
        "garbage",
    ] {
        let rejected = server(false)
            .post("/mcp")
            .add_header(
                "MCP-Protocol-Version",
                HeaderValue::from_str(version).unwrap(),
            )
            .json(&request)
            .await;
        rejected.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.text(),
            "Invalid or unsupported MCP-Protocol-Version"
        );
    }

    let invalid_get = server(false)
        .get("/mcp")
        .add_header(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2026-07-28"),
        )
        .await;
    invalid_get.assert_status(StatusCode::BAD_REQUEST);

    let invalid_delete = server(false)
        .delete("/mcp")
        .add_header(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2026-07-28"),
        )
        .await;
    invalid_delete.assert_status(StatusCode::BAD_REQUEST);

    let valid_delete = server(false)
        .delete("/mcp")
        .add_header(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2025-06-18"),
        )
        .await;
    valid_delete.assert_status(StatusCode::METHOD_NOT_ALLOWED);

    let unauthenticated = server(true)
        .post("/mcp")
        .add_header("MCP-Protocol-Version", HeaderValue::from_static("garbage"))
        .json(&request)
        .await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_protocol_version_rejects_incomplete_post_body() {
    let mut config = Config::default();
    config.auth.enabled = false;
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
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nMCP-Protocol-Version: 2026-07-28\r\nContent-Length: 2000000\r\n\r\nx")
        .await
        .unwrap();
    let status_line = timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            assert!(line.len() < 256, "HTTP status line is too long");
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            line.push(byte[0]);
        }
        line
    })
    .await
    .expect("version rejection must not wait for the incomplete body");
    assert!(std::str::from_utf8(&status_line)
        .unwrap()
        .starts_with("HTTP/1.1 400 "));

    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nMCP-Protocol-Version: 2025-06-18\r\nContent-Length: 2000000\r\n\r\nx")
        .await
        .unwrap();
    let status_line = timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            assert!(line.len() < 256, "HTTP status line is too long");
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            line.push(byte[0]);
        }
        line
    })
    .await
    .expect("large valid-version request must be rejected before its body completes");
    assert!(std::str::from_utf8(&status_line)
        .unwrap()
        .starts_with("HTTP/1.1 413 "));
    server_task.abort();
}

#[tokio::test]
async fn post_body_limit_still_applies_after_version_validation() {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.limits.max_request_bytes = 128;
    let state = ServerState {
        app: Arc::new(AppState::new(config)),
        registry: Arc::new(build_registry()),
    };
    let response = TestServer::new(build_router(state, 128))
        .post("/mcp")
        .add_header(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2025-06-18"),
        )
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "padding": "x".repeat(256)}))
        .await;
    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_upgrade_requires_explicit_browser_origin_allowlist() {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.auth.allowed_origins = vec!["https://console.example".to_string()];
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

    for (origin_lines, expected) in [
        ("Origin: https://console.example\r\n", 101),
        (
            "Origin: https://console.example\r\nMCP-Protocol-Version: 2026-07-28\r\n",
            101,
        ),
        ("Origin: https://evil.example\r\n", 403),
        (
            "Origin: https://console.example\r\nOrigin: https://console.example\r\n",
            403,
        ),
    ] {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET /mcp HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{origin_lines}\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let status = timeout(Duration::from_secs(5), async {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                let mut byte = [0_u8];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
                line.push(byte[0]);
                assert!(line.len() < 256);
            }
            std::str::from_utf8(&line)
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u16>()
                .unwrap()
        })
        .await
        .expect("WebSocket handshake must finish");
        assert_eq!(status, expected, "{origin_lines}");
    }
    server_task.abort();
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
async fn explicit_post_content_type_must_be_utf8_json() {
    let payload =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})).unwrap();
    for content_type in [
        "application/json",
        "Application/JSON; charset=UTF-8",
        "application/json; charset=\"utf-8\"",
    ] {
        let response = server(false)
            .post("/mcp")
            .add_header(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap())
            .add_header(
                "accept",
                HeaderValue::from_static("application/json, text/event-stream"),
            )
            .bytes(payload.clone().into())
            .await;
        response.assert_status_ok();
    }

    // Missing remains accepted for older direct clients.
    server(false)
        .post("/mcp")
        .bytes(payload.clone().into())
        .await
        .assert_status_ok();

    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/json; charset=iso-8859-1",
        "application/json; charset=\"utf-8",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json, text/plain",
    ] {
        let response = server(false)
            .post("/mcp")
            .add_header(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap())
            .bytes(payload.clone().into())
            .await;
        response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response.text(),
            "MCP POST Content-Type must be application/json with UTF-8 charset"
        );
    }

    let unauthenticated = server(true)
        .post("/mcp")
        .add_header(CONTENT_TYPE, HeaderValue::from_static("text/plain"))
        .bytes(payload.into())
        .await;
    unauthenticated.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn explicit_accept_must_allow_json() {
    let payload =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})).unwrap();
    for accept in [
        "application/json, text/event-stream",
        "application/*",
        "*/*",
        "application/json;q=0.5",
    ] {
        server(false)
            .post("/mcp")
            .add_header("accept", HeaderValue::from_str(accept).unwrap())
            .bytes(payload.clone().into())
            .await
            .assert_status_ok();
    }
    server(false)
        .post("/mcp")
        .bytes(payload.clone().into())
        .await
        .assert_status_ok();
    for accept in [
        "text/event-stream",
        "application/json;q=0, */*;q=1",
        "*/*;q=0",
        "application/json;q=bogus",
        "multipart/form-data;boundary=\"x,application/json,y\"",
    ] {
        let response = server(false)
            .post("/mcp")
            .add_header("accept", HeaderValue::from_str(accept).unwrap())
            .bytes(payload.clone().into())
            .await;
        response.assert_status(StatusCode::NOT_ACCEPTABLE);
    }
    server(true)
        .post("/mcp")
        .add_header("accept", HeaderValue::from_static("text/event-stream"))
        .bytes(payload.into())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_media_type_rejects_incomplete_body() {
    let mut config = Config::default();
    config.auth.enabled = false;
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
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 1000000\r\n\r\nx")
        .await
        .unwrap();
    let status_line = timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            assert!(line.len() < 256, "HTTP status line is too long");
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            line.push(byte[0]);
        }
        line
    })
    .await
    .expect("media-type rejection must not wait for the incomplete body");
    assert!(std::str::from_utf8(&status_line)
        .unwrap()
        .starts_with("HTTP/1.1 415 "));
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unacceptable_response_type_rejects_incomplete_body() {
    let mut config = Config::default();
    config.auth.enabled = false;
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
    stream.write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: 1000000\r\n\r\nx")
        .await.unwrap();
    let status_line = timeout(Duration::from_secs(5), async {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            assert!(line.len() < 256);
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            line.push(byte[0]);
        }
        line
    })
    .await
    .expect("Accept rejection must not wait for the incomplete body");
    assert!(std::str::from_utf8(&status_line)
        .unwrap()
        .starts_with("HTTP/1.1 406 "));
    server_task.abort();
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
