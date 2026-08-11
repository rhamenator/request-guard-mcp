use crate::error::AppError;
use crate::mcp::protocol::{McpMessage, McpPayload};
use crate::mcp::tool_registry::ToolRegistry;
use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::timeout;
use tracing::{error, info, warn, Instrument};

/// Handle a single WebSocket connection lifecycle.
pub async fn handle_ws_connection(
    mut socket: WebSocket,
    state: Arc<AppState>,
    registry: Arc<ToolRegistry>,
) {
    state.metrics.active_connections.inc();
    info!("WebSocket connection established");

    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                if let Some(response) = process_message(&text, &state, &registry).await {
                    if let Err(e) = socket.send(Message::Text(response)).await {
                        warn!(error = %e, "failed to send WS response");
                        break;
                    }
                }
            }
            Some(Ok(Message::Binary(bytes))) => match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    if let Some(response) = process_message(text, &state, &registry).await {
                        if let Err(e) = socket.send(Message::Text(response)).await {
                            warn!(error = %e, "failed to send WS response");
                            break;
                        }
                    }
                }
                Err(error) => {
                    warn!(%error, "received non-UTF-8 binary MCP message");
                    let response = serialize_message(&McpMessage::error(
                        Value::Null,
                        -32700,
                        "Parse error: MCP messages must be UTF-8",
                    ));
                    if let Err(e) = socket.send(Message::Text(response)).await {
                        warn!(error = %e, "failed to send WS parse error");
                        break;
                    }
                }
            },
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

pub(crate) async fn process_message(
    text: &str,
    state: &Arc<AppState>,
    registry: &Arc<ToolRegistry>,
) -> Option<String> {
    let start = Instant::now();

    // Size check
    if text.len() > state.config.limits.max_request_bytes {
        let err = McpMessage::error(Value::Null, -413, AppError::RequestTooLarge.code());
        return Some(serialize_message(&err));
    }

    // Parse JSON-RPC message
    let msg: McpMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to parse MCP message");
            let err = McpMessage::error(Value::Null, -32700, "Parse error");
            return Some(serialize_message(&err));
        }
    };

    let McpPayload::Request(req) = msg.payload else {
        // Notifications and responses from the client are ignored
        return None;
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
            return Some(serialize_message(&err));
        }
    };

    let tool_timeout = if tool_name == "classify" {
        state.config.classify_timeout()
    } else {
        state.config.per_tool_timeout()
    };
    let registry_arc = Arc::clone(registry);
    let state_arc = Arc::clone(state);

    let operation_id = if state.redis.is_available() {
        match state
            .redis
            .record_tool_started(&tool_name, tool_timeout.as_secs().max(1))
            .await
        {
            Ok(id) => Some(id),
            Err(error) => {
                warn!(tool = %tool_name, %error, "failed to record Redis operation start");
                None
            }
        }
    } else {
        None
    };

    let dispatch_span = tracing::info_span!("mcp.tool", tool = %tool_name);
    let dispatch_result = timeout(
        tool_timeout,
        registry_arc
            .dispatch(state_arc, &req)
            .instrument(dispatch_span),
    )
    .await;

    if let Some(operation_id) = operation_id {
        if let Err(error) = state
            .redis
            .record_tool_finished(&tool_name, &operation_id)
            .await
        {
            warn!(tool = %tool_name, %error, "failed to record Redis operation completion");
        }
    }

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

    Some(serialize_message(&response))
}

fn serialize_message(message: &McpMessage) -> String {
    serde_json::to_string(message).unwrap_or_else(|error| {
        error!(%error, "failed to serialize MCP response");
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-500,"message":"INTERNAL_ERROR","data":null}}"#.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn notifications_do_not_generate_empty_response_frames() {
        let state = Arc::new(AppState::new(Config::default()));
        let registry = Arc::new(crate::mcp::tool_registry::build_registry());
        let notification = r#"{"jsonrpc":"2.0","method":"warmup","params":{}}"#;

        assert!(process_message(notification, &state, &registry)
            .await
            .is_none());
    }
}
