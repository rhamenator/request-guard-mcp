/// Contract tests for the explain tool.
use request_guard_mcp::*;

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
    let resp = tools::explain::run(&state, req).await.unwrap();
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
    let resp = tools::explain::run(&state, req).await.unwrap();
    assert!(!resp.recommendations.is_empty());
}

#[tokio::test]
async fn explain_rejects_incomplete_response_instead_of_reporting_clean() {
    let state = make_state();
    let classification = serde_json::json!({
        "verdict": "block",
        "score": 0.9
    });
    let req = models::request::ExplainRequest {
        classification,
        format: None,
    };
    let error = tools::explain::run(&state, req).await.unwrap_err();
    assert_eq!(error.code(), "INVALID_REQUEST");
}

#[tokio::test]
async fn explain_rejects_contradictory_supplied_response() {
    let state = make_state();
    let classified = tools::classify::run(
        &state,
        serde_json::from_value(serde_json::json!({"path":"/admin"})).unwrap(),
    )
    .await
    .unwrap();
    let mut supplied = serde_json::to_value(classified).unwrap();
    supplied["signals"] = serde_json::json!([]);
    let error = tools::explain::run(
        &state,
        models::request::ExplainRequest {
            classification: supplied,
            format: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "INVALID_REQUEST");
}

#[tokio::test]
async fn explain_uses_supplied_block_response_without_rescoring_empty_request() {
    let state = make_state();
    let classified = tools::classify::run(
        &state,
        serde_json::from_value(serde_json::json!({
            "request_id": "blocked-path", "path": "/admin", "method": "GET"
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(classified.verdict.to_string(), "block");
    let response = tools::explain::run(
        &state,
        models::request::ExplainRequest {
            classification: serde_json::to_value(classified).unwrap(),
            format: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.request_id, "blocked-path");
    assert!(response.explanation.contains("verdict 'block'"));
    assert!(response
        .explanation
        .contains("not verified against a stored decision"));
    assert!(response
        .factors
        .iter()
        .any(|factor| factor.name == "path_sensitive"));
    assert!(!response
        .recommendations
        .iter()
        .any(|item| item.contains("No action required")));
}

#[tokio::test]
async fn explain_rejects_unknown_raw_request_fields() {
    let state = make_state();
    let error = tools::explain::run(
        &state,
        models::request::ExplainRequest {
            classification: serde_json::json!({"pah":"/admin"}),
            format: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), "INVALID_REQUEST");
}

#[tokio::test]
async fn explain_raw_request_uses_configured_attested_tls_rules() {
    let key = format!("synthetic-explain-{}", uuid::Uuid::new_v4());
    let ja3 = "72a589da586844d7f0818ce684948eea";
    let mut config = config::Config::default();
    config.tls_fingerprints.attestation_key = Some(key.clone());
    config.tls_fingerprints.known_bad_ja3 = vec![ja3.to_string()];
    let state = state::AppState::new(config);
    let token = util::tls_attestation::create_attestation(
        key.as_bytes(),
        chrono::Utc::now().timestamp(),
        "198.51.100.7",
        "GET",
        "/",
        Some(ja3),
        None,
        "envoy",
    )
    .unwrap();
    let classification = serde_json::json!({
        "request_id": "attested-explain",
        "ip": "198.51.100.7",
        "method": "GET",
        "path": "/",
        "tls_ja3": ja3,
        "tls_fingerprint_source": "envoy",
        "tls_fingerprint_attestation": token,
    });
    let response = tools::explain::run(
        &state,
        models::request::ExplainRequest {
            classification,
            format: None,
        },
    )
    .await
    .unwrap();
    assert!(response
        .factors
        .iter()
        .any(|factor| factor.name == "tls_fingerprint_known_bad"));
    assert!(response
        .explanation
        .contains("Recomputed from supplied request metadata"));
}
