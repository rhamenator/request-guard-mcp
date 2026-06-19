use crate::error::AppError;
use crate::mcp::protocol::{McpMessage, McpPayload};
use crate::mcp::tool_registry::ToolRegistry;
use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Handle a single WebSocket connection lifecycle.
pub async fn handle_ws_connection(
    mut socket: WebSocket,
    state: Arc<AppState>,
    registry: Arc<ToolRegistry>,
    auth_header: Option<String>,
) {
    // Authenticate once at connection establishment.
    if state.config.auth.enabled {
        let token = auth_header
            .as_deref()
            .and_then(crate::auth::extract_token)
            .unwrap_or("");
        if !state.config.auth.tokens.iter().any(|t| t == token) {
            warn!("WebSocket connection rejected: invalid auth");
            let msg = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -401, "message": "UNAUTHENTICATED" }
            });
            let _ = socket.send(Message::Text(msg.to_string())).await;
            return;
        }
    }

    state.metrics.active_connections.inc();
    info!("WebSocket connection established");

    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                let response = process_message(&text, &state, &registry).await;
                if let Err(e) = socket.send(Message::Text(response)).await {
                    warn!(error = %e, "failed to send WS response");
                    break;
                }
            }
            Some(Ok(Message::Binary(bytes))) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    let response = process_message(text, &state, &registry).await;
                    if let Err(e) = socket.send(Message::Text(response)).await {
                        warn!(error = %e, "failed to send WS response");
                        break;
                    }
                }
            }
            Some(Ok(Message::Ping(data))) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            Some(Ok(Message::Close(_))) | None => {
                info!("WebSocket connection closed");
                break;
            }
            Some(Err(e)) => {
                warn!(error = %e, "WebSocket error");
                break;
            }
            Some(Ok(Message::Pong(_))) => {}
        }
    }

    state.metrics.active_connections.dec();
}

async fn process_message(
    text: &str,
    state: &Arc<AppState>,
    registry: &Arc<ToolRegistry>,
) -> String {
    let start = Instant::now();

    // Size check
    if text.len() > state.config.limits.max_request_bytes {
        let err = McpMessage::error(Value::Null, -413, AppError::RequestTooLarge.code());
        return serde_json::to_string(&err).unwrap_or_default();
    }

    // Parse JSON-RPC message
    let msg: McpMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to parse MCP message");
            let err = McpMessage::error(Value::Null, -32700, "Parse error");
            return serde_json::to_string(&err).unwrap_or_default();
        }
    };

    let McpPayload::Request(req) = msg.payload else {
        // Notifications and responses from the client are ignored
        return String::new();
    };

    let id = req.id.clone();
    let tool_name = req
        .method
        .strip_prefix("tools/")
        .unwrap_or(&req.method)
        .to_string();

    // Acquire global concurrency semaphore
    let _permit = match state.semaphore.acquire().await {
        Ok(p) => p,
        Err(_) => {
            let err = McpMessage::error(id, -429, AppError::RateLimitExceeded.code());
            return serde_json::to_string(&err).unwrap_or_default();
        }
    };

    let tool_timeout = state.config.per_tool_timeout();
    let registry_arc = Arc::clone(registry);
    let state_arc = Arc::clone(state);

    let dispatch_result = timeout(tool_timeout, registry_arc.dispatch(state_arc, &req)).await;

    let latency = start.elapsed().as_millis() as u64;

    let response = match dispatch_result {
        Ok(Ok(value)) => {
            state
                .metrics
                .requests_total
                .with_label_values(&[&tool_name, "ok"])
                .inc();
            McpMessage::success(id, value)
        }
        Ok(Err(app_err)) => {
            warn!(tool = %tool_name, error = %app_err, "tool error");
            state
                .metrics
                .requests_total
                .with_label_values(&[&tool_name, "error"])
                .inc();
            state
                .metrics
                .tool_errors_total
                .with_label_values(&[&tool_name, app_err.code()])
                .inc();
            McpMessage::error_from_app(id, &app_err)
        }
        Err(_elapsed) => {
            error!(tool = %tool_name, latency_ms = latency, "tool timeout");
            state
                .metrics
                .requests_total
                .with_label_values(&[&tool_name, "timeout"])
                .inc();
            McpMessage::error_from_app(id, &AppError::Timeout)
        }
    };

    state
        .metrics
        .request_duration_seconds
        .with_label_values(&[&tool_name])
        .observe(latency as f64 / 1000.0);

    serde_json::to_string(&response).unwrap_or_default()
}
