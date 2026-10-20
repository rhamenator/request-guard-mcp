use crate::error::AppError;
use crate::mcp::protocol::{McpMessage, McpPayload};
use crate::mcp::tool_registry::ToolRegistry;
use crate::state::AppState;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use serde_json::Value;
use std::error::Error as _;
use std::sync::Arc;
use std::time::Instant;
use tokio::{sync::OwnedSemaphorePermit, time::timeout};
use tracing::{error, info, warn, Instrument};
use tungstenite::error::CapacityError;

const UNKNOWN_TOOL_METRIC_LABEL: &str = "__unknown__";
pub const SUPPORTED_PROTOCOL_VERSION: &str = "2025-06-18";

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
                if matches!(
                    e.source()
                        .and_then(|source| source.downcast_ref::<tungstenite::Error>()),
                    Some(tungstenite::Error::Capacity(
                        CapacityError::MessageTooLong { .. }
                    ))
                ) {
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 1009,
                            reason: "Message too big".into(),
                        })))
                        .await;
                }
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

    // Distinguish malformed JSON from a valid JSON value with an invalid
    // JSON-RPC envelope. Do this before deserializing the untagged payload.
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            warn!(error = %e, "failed to parse MCP message");
            let err = McpMessage::error(Value::Null, -32700, "Parse error");
            return Some(serialize_message(&err));
        }
    };
    let Some(envelope) = value.as_object() else {
        return invalid_request(Value::Null);
    };
    if envelope.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid_request(Value::Null);
    }
    if let Some(method) = envelope.get("method") {
        if !method.is_string() || envelope.contains_key("result") || envelope.contains_key("error")
        {
            return invalid_request(Value::Null);
        }
        // MCP 2025-06-18 narrows JSON-RPC request IDs to strings or
        // integers: null and fractional/exponent numbers are not valid.
        if envelope.get("id").is_some_and(|id| {
            !id.is_string()
                && !id
                    .as_number()
                    .is_some_and(|number| number.is_i64() || number.is_u64())
        }) {
            return invalid_request(Value::Null);
        }
        if envelope
            .get("params")
            .is_some_and(|params| !params.is_object())
        {
            return invalid_request(Value::Null);
        }
    } else if !envelope.contains_key("id")
        || envelope.contains_key("result") == envelope.contains_key("error")
    {
        return invalid_request(Value::Null);
    }
    if envelope.get("method").is_none()
        && envelope.get("id").is_some_and(|id| {
            !id.is_string()
                && !id
                    .as_number()
                    .is_some_and(|number| number.is_i64() || number.is_u64())
                && !(id.is_null()
                    && envelope
                        .get("error")
                        .and_then(Value::as_object)
                        .and_then(|error| error.get("code"))
                        .and_then(Value::as_i64)
                        .is_some_and(|code| code == -32700 || code == -32600))
        })
    {
        return invalid_request(Value::Null);
    }
    // MCP Result is an object, even when the JSON-RPC base protocol would
    // permit other JSON values in a successful response.
    if envelope
        .get("result")
        .is_some_and(|result| !result.is_object())
    {
        return invalid_request(Value::Null);
    }
    let msg: McpMessage = match serde_json::from_value(value) {
        Ok(message) => message,
        Err(_) => return invalid_request(Value::Null),
    };

    let McpPayload::Request(req) = msg.payload else {
        // Notifications and responses from the client are ignored
        return None;
    };

    let id = req.id.clone();

    match req.method.as_str() {
        "initialize" => {
            let Some(_requested_version) = req
                .params
                .as_ref()
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
            else {
                return invalid_params(id, "initialize requires a protocolVersion string");
            };
            // For a different requested revision, the 2025-06-18 lifecycle
            // requires a supported counter-offer in the initialize result.
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

    // Shed excess work instead of leaving an unbounded queue of callers holding
    // request bodies and connections while all tool permits are occupied.
    let _permit = match state.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            let err = McpMessage::error(id, -429, AppError::RateLimitExceeded.code());
            return Some(serialize_message(&err));
        }
    };

    // Reject before Redis bookkeeping and label creation. A caller can choose
    // arbitrary method names, but Prometheus and Redis key cardinality must
    // remain bounded by the registered tool set.
    if registry.get(&tool_name).is_none() {
        let app_error = AppError::ToolNotFound(tool_name);
        state
            .metrics
            .requests_total
            .with_label_values(&[UNKNOWN_TOOL_METRIC_LABEL, "error"])
            .inc();
        state
            .metrics
            .tool_errors_total
            .with_label_values(&[UNKNOWN_TOOL_METRIC_LABEL, app_error.code()])
            .inc();
        state
            .metrics
            .request_duration_seconds
            .with_label_values(&[UNKNOWN_TOOL_METRIC_LABEL])
            .observe(start.elapsed().as_secs_f64());
        return Some(serialize_message(&McpMessage::error_from_app(
            id, &app_error,
        )));
    }

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

fn invalid_request(id: Value) -> Option<String> {
    Some(serialize_message(&McpMessage::error(
        id,
        -32600,
        "Invalid Request",
    )))
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
    async fn initialize_counteroffers_supported_protocol_version() {
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
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert!(response.get("error").is_none());
    }

    #[tokio::test]
    async fn initialize_requires_string_protocol_version() {
        let (state, registry) = test_context();
        for params in [r#"{}"#, r#"{"protocolVersion":42}"#] {
            let request =
                format!(r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{params}}}"#);
            let response = process_message(&request, &state, &registry, "test-caller")
                .await
                .expect("initialize response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["error"]["code"], -32602);
        }
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

    #[tokio::test]
    async fn mcp_request_ids_require_strings_or_integers() {
        let (state, registry) = test_context();
        for id in ["null", "1.5", "1e0", "true", "{}", "[]"] {
            let request = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
            let response = process_message(&request, &state, &registry, "test-caller")
                .await
                .expect("invalid request response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["error"]["code"], -32600, "id: {id}");
            assert!(response["id"].is_null(), "id: {id}");
        }
        for id in ["0", "-1", "\"request-1\""] {
            let request = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
            let response = process_message(&request, &state, &registry, "test-caller")
                .await
                .expect("valid request response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["id"], serde_json::from_str::<Value>(id).unwrap());
            assert!(response.get("result").is_some(), "id: {id}");
        }
        // A client error response may use null when the original request ID
        // could not be recovered; it is not an MCP request.
        assert!(process_message(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_none());
        assert!(process_message(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn mcp_client_response_ids_require_strings_or_integers() {
        let (state, registry) = test_context();
        for id in ["1.5", "1e0", "true", "{}", "[]"] {
            let response = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{}}}}"#);
            let rejected = process_message(&response, &state, &registry, "test-caller")
                .await
                .expect("invalid response error");
            let rejected: Value = serde_json::from_str(&rejected).unwrap();
            assert_eq!(rejected["error"]["code"], -32600, "id: {id}");
            assert!(rejected["id"].is_null(), "id: {id}");
        }
        for id in ["0", "-1", "\"response-1\""] {
            let response = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{}}}}"#);
            assert!(process_message(&response, &state, &registry, "test-caller")
                .await
                .is_none());
        }
        assert!(process_message(
            r#"{"jsonrpc":"2.0","id":null,"result":{}}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_some());
        let invalid_null_error =
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#;
        let rejected = process_message(invalid_null_error, &state, &registry, "test-caller")
            .await
            .expect("null ID on an internal error must be rejected");
        let rejected: Value = serde_json::from_str(&rejected).unwrap();
        assert_eq!(rejected["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn mcp_client_response_result_must_be_an_object() {
        let (state, registry) = test_context();
        for result in ["null", "true", "1", "\"text\"", "[]"] {
            let response = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let rejected = process_message(&response, &state, &registry, "test-caller")
                .await
                .expect("invalid response error");
            let rejected: Value = serde_json::from_str(&rejected).unwrap();
            assert_eq!(rejected["error"]["code"], -32600, "result: {result}");
        }
        assert!(process_message(
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn mcp_params_must_be_objects_when_present() {
        let (state, registry) = test_context();
        for message in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":[]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":null}"#,
        ] {
            let response = process_message(message, &state, &registry, "test-caller")
                .await
                .expect("invalid request response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["error"]["code"], -32600, "{message}");
            assert!(response["id"].is_null(), "{message}");
        }
        for message in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#,
        ] {
            let response = process_message(message, &state, &registry, "test-caller")
                .await
                .expect("valid request response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert!(response.get("result").is_some(), "{message}");
        }
        assert!(process_message(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_none());
        assert!(process_message(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            &state,
            &registry,
            "test-caller"
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn saturated_tool_capacity_rejects_without_waiting() {
        let mut config = Config::default();
        config.limits.global_concurrency = 1;
        let state = Arc::new(AppState::new(config));
        let registry = Arc::new(build_registry());
        let held = state.semaphore.acquire().await.unwrap();
        let request = r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"classify","arguments":{"user_agent":"GPTBot/1.0"}}}"#;

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            process_message(request, &state, &registry, "test-caller"),
        )
        .await
        .expect("saturated capacity must not queue")
        .expect("error response");
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["error"]["code"], -429);

        drop(held);
        let response = process_message(request, &state, &registry, "test-caller")
            .await
            .expect("capacity recovered");
        let response: Value = serde_json::from_str(&response).unwrap();
        assert!(response.get("result").is_some());
    }

    #[tokio::test]
    async fn unknown_tool_names_use_one_metric_label() {
        let (state, registry) = test_context();
        for name in ["probe_random_001", "probe_random_002"] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{{}}}}}}"#
            );
            let response = process_message(&request, &state, &registry, "test-caller")
                .await
                .expect("unknown-tool response");
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["error"]["message"], "TOOL_NOT_FOUND");
        }
        let metrics = crate::telemetry::gather_metrics();
        assert!(metrics.contains("tool=\"__unknown__\""));
        assert!(!metrics.contains("probe_random_001"));
        assert!(!metrics.contains("probe_random_002"));
    }

    #[test]
    fn error_response_omits_result() {
        let response =
            serde_json::to_value(McpMessage::error(Value::from(1), -32602, "bad")).unwrap();
        assert!(response.get("result").is_none());
        assert!(response.get("error").is_some());
    }
}
