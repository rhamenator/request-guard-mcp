use crate::error::AppError;
use crate::mcp::protocol::{McpMessage, McpPayload};
use crate::mcp::tool_registry::ToolRegistry;
use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::{sync::OwnedSemaphorePermit, time::timeout};
use tracing::{error, info, warn, Instrument};

/// Handle a single WebSocket connection lifecycle.
pub async fn handle_ws_connection(
    mut socket: WebSocket,
    state: Arc<AppState>,
    registry: Arc<ToolRegistry>,
    caller_scope: String,
    _connection_permit: OwnedSemaphorePermit,
) {
    state.metrics.active_connections.inc();
    info!("WebSocket connection established");

    loop {
        let idle_timeout =
            std::time::Duration::from_secs(state.config.limits.websocket_idle_timeout_secs);
        match timeout(idle_timeout, socket.recv()).await {
            Err(_) => {
                warn!("WebSocket connection closed after idle timeout");
                break;
            }
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Some(response) =
                    process_message(&text, &state, &registry, &caller_scope).await
                {
                    if let Err(e) = socket.send(Message::Text(response.into())).await {
                        warn!(error = %e, "failed to send WS response");
                        break;
                    }
                }
            }
            Ok(Some(Ok(Message::Binary(bytes)))) => match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    if let Some(response) =
                        process_message(text, &state, &registry, &caller_scope).await
                    {
                        if let Err(e) = socket.send(Message::Text(response.into())).await {
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
                    if let Err(e) = socket.send(Message::Text(response.into())).await {
                        warn!(error = %e, "failed to send WS parse error");
                        break;
                    }
                }
            },
            Ok(Some(Ok(Message::Ping(data)))) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                info!("WebSocket connection closed");
                break;
            }
            Ok(Some(Err(e))) => {
                warn!(error = %e, "WebSocket error");
                break;
            }
            Ok(Some(Ok(Message::Pong(_)))) => {}
        }
    }

    state.metrics.active_connections.dec();
}

pub(crate) async fn process_message(
    text: &str,
    state: &Arc<AppState>,
    registry: &Arc<ToolRegistry>,
    caller_scope: &str,
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

    match req.method.as_str() {
        "initialize" => {
            const SUPPORTED_PROTOCOL_VERSION: &str = "2025-06-18";
            let protocol_version = req
                .params
                .as_ref()
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or(SUPPORTED_PROTOCOL_VERSION);
            if protocol_version != SUPPORTED_PROTOCOL_VERSION {
                return Some(serialize_message(&McpMessage::error(
                    id,
                    -32602,
                    "Unsupported MCP protocol version",
                )));
            }
            return Some(serialize_message(&McpMessage::success(
                id,
                serde_json::json!({
                    "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "request-guard-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )));
        }
        "ping" => {
            return Some(serialize_message(&McpMessage::success(
                id,
                serde_json::json!({}),
            )));
        }
        "tools/list" => {
            return Some(serialize_message(&McpMessage::success(
                id,
                serde_json::json!({ "tools": registry.definitions() }),
            )));
        }
        _ => {}
    }

    let standard_tool_call = req.method == "tools/call";
    let (tool_name, tool_params) = if standard_tool_call {
        let Some(params) = req.params.as_ref() else {
            return invalid_params(id, "tools/call requires params");
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return invalid_params(id, "tools/call requires a tool name");
        };
        (name.to_string(), params.get("arguments").cloned())
    } else {
        (
            req.method
                .strip_prefix("tools/")
                .unwrap_or(&req.method)
                .to_string(),
            req.params.clone(),
        )
    };

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
            .dispatch_named(state_arc, &tool_name, tool_params, caller_scope)
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
            let result = if standard_tool_call {
                let text = serde_json::to_string(&value).unwrap_or_default();
                serde_json::json!({
                    "content": [{ "type": "text", "text": text }],
                    "structuredContent": value,
                    "isError": false
                })
            } else {
                value
            };
            McpMessage::success(id, result)
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

fn invalid_params(id: Value, message: &str) -> Option<String> {
    Some(serialize_message(&McpMessage::error(id, -32602, message)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, mcp::tool_registry::build_registry};

    fn test_context() -> (Arc<AppState>, Arc<ToolRegistry>) {
        (
            Arc::new(AppState::new(Config::default())),
            Arc::new(build_registry()),
        )
    }

    #[tokio::test]
    async fn standard_mcp_initialize_and_list_tools_work() {
        let (state, registry) = test_context();
        let initialize = process_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            &state,
            &registry,
            "test-caller",
        )
        .await
        .expect("initialize response");
        let initialize: Value = serde_json::from_str(&initialize).unwrap();
        assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");
        assert!(initialize["result"]["capabilities"]["tools"].is_object());

        let list = process_message(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            &state,
            &registry,
            "test-caller",
        )
        .await
        .expect("tools/list response");
        let list: Value = serde_json::from_str(&list).unwrap();
        assert!(list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "classify"));
    }

    #[tokio::test]
    async fn initialize_rejects_unsupported_protocol_version() {
        let (state, registry) = test_context();
        let response = process_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            &state,
            &registry,
            "test-caller",
        )
        .await
        .expect("initialize response");
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "Unsupported MCP protocol version"
        );
    }

    #[tokio::test]
    async fn standard_tools_call_dispatches_named_tool() {
        let (state, registry) = test_context();
        let response = process_message(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"classify","arguments":{"ip":"192.0.2.1","user_agent":"GPTBot/1.0","path":"/"}}}"#,
            &state,
            &registry,
            "test-caller",
        )
        .await
        .expect("tools/call response");
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert!(response["result"]["structuredContent"]["score"].is_number());
    }

    #[tokio::test]
    async fn notifications_do_not_generate_empty_response_frames() {
        let (state, registry) = test_context();
        let notification = r#"{"jsonrpc":"2.0","method":"warmup","params":{}}"#;

        assert!(
            process_message(notification, &state, &registry, "test-caller")
                .await
                .is_none()
        );
    }

    #[test]
    fn error_response_omits_result() {
        let response =
            serde_json::to_value(McpMessage::error(Value::from(1), -32602, "bad")).unwrap();
        assert!(response.get("result").is_none());
        assert!(response.get("error").is_some());
    }
}
