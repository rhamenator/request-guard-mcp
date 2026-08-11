use request_guard_mcp::{
    config::Config,
    error::AppError,
    mcp::{
        protocol::McpRequest,
        tool_registry::{build_registry, McpTool, ModelInfoTool},
    },
    state::AppState,
};
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::test]
async fn placeholder_tools_fail_explicitly() {
    let state = Arc::new(AppState::new(Config::default()));
    let registry = build_registry();
    let request = McpRequest {
        id: json!(1),
        method: "feedback".to_string(),
        params: Some(json!({
            "request_id": "request-1",
            "correct_verdict": "allow"
        })),
    };

    let result = registry.dispatch(state, &request).await;
    assert!(matches!(result, Err(AppError::IntegrationUnavailable(_))));
}

#[tokio::test]
async fn model_info_marks_placeholder_tools_disabled() {
    let state = Arc::new(AppState::new(Config::default()));
    let value = ModelInfoTool.call(state, None).await.unwrap();
    let tools = value["tools"].as_array().unwrap();
    let feedback = tools
        .iter()
        .find(|tool| tool["name"] == Value::String("feedback".to_string()))
        .unwrap();
    assert_eq!(feedback["enabled"], Value::Bool(false));
}
