use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP protocol message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    pub jsonrpc: String,
    #[serde(flatten)]
    pub payload: McpPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpPayload {
    Request(McpRequest),
    Response(McpResponse),
    Notification(McpNotification),
}

/// Outbound call from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub id: Value,
    pub method: String,
    pub params: Option<Value>,
}

/// Successful response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub id: Value,
    pub result: Option<Value>,
    pub error: Option<McpError>,
}

/// Error payload embedded in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

/// One-way notification (no id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpNotification {
    pub method: String,
    pub params: Option<Value>,
}

impl McpMessage {
    pub fn success(id: Value, result: Value) -> Self {
        McpMessage {
            jsonrpc: "2.0".to_string(),
            payload: McpPayload::Response(McpResponse {
                id,
                result: Some(result),
                error: None,
            }),
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        McpMessage {
            jsonrpc: "2.0".to_string(),
            payload: McpPayload::Response(McpResponse {
                id,
                result: None,
                error: Some(McpError {
                    code,
                    message: message.into(),
                    data: None,
                }),
            }),
        }
    }

    pub fn error_from_app(id: Value, err: &crate::error::AppError) -> Self {
        Self::error(id, -(err.status_code() as i32), err.code())
    }
}
