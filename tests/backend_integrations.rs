use request_guard_mcp::config::Config;
use request_guard_mcp::integrations::redis::{CanaryRecord, ThreatRecord};
use request_guard_mcp::models::request::{
    CalibrationReportRequest, CanaryEvalRequest, ClassifyRequest, DriftReportRequest,
    EnrichAsnRequest, EnrichIpRequest, FeedbackRequest, QueueStatusRequest, ReplayRequest,
    ThreatLookupRequest,
};
use request_guard_mcp::{state::AppState, tools};
use serde_json::json;
use uuid::Uuid;

fn classify_request(request_id: String, user_agent: &str) -> ClassifyRequest {
    ClassifyRequest {
        ip: Some("203.0.113.25".to_string()),
        user_agent: Some(user_agent.to_string()),
        path: Some("/integration-test".to_string()),
        method: Some("GET".to_string()),
        headers: None,
        body_snippet: None,
        referer: None,
        accept: Some("text/html".to_string()),
        request_id: Some(request_id),
        timestamp: None,
        tls_ja3: None,
        tls_ja4: None,
        tls_fingerprint_source: None,
        tls_fingerprint_attestation: None,
        tls_fingerprint_verified: false,
        extra: None,
    }
}

#[tokio::test]
async fn maxmind_city_asn_and_anonymous_databases_enrich_real_records() {
    let (Ok(city_path), Ok(asn_path), Ok(anonymous_path)) = (
        std::env::var("TEST_GEOIP_CITY_DB"),
        std::env::var("TEST_GEOIP_ASN_DB"),
        std::env::var("TEST_GEOIP_ANONYMOUS_DB"),
    ) else {
        eprintln!("skipping GeoIP integration test: TEST_GEOIP_*_DB paths not set");
        return;
    };

    let mut config = Config::default();
    config.geoip.city_mmdb_path = Some(city_path);
    config.geoip.asn_mmdb_path = Some(asn_path);
    config.geoip.anonymous_ip_mmdb_path = Some(anonymous_path);
    let state = AppState::initialize(config).await.unwrap();

    let ip = tools::enrich_ip::run(
        &state,
        EnrichIpRequest {
            ip: "81.2.69.160".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(ip.country.as_deref(), Some("GB"));
    assert_eq!(ip.city.as_deref(), Some("London"));
    assert!(ip.is_proxy);
    assert!(ip.is_datacenter);
    assert!(ip.is_tor);
    assert_eq!(ip.risk_score, 0.9);

    let unknown = tools::enrich_ip::run(
        &state,
        EnrichIpRequest {
            ip: "203.0.113.25".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(unknown.country, None);
    assert_eq!(unknown.risk_score, 0.1);

    let asn_ip = state.geoip.lookup_ip(&"1.0.0.1".parse().unwrap()).unwrap();
    assert_eq!(asn_ip.asn, Some(15169));
    assert_eq!(asn_ip.org.as_deref(), Some("Google Inc."));
    let asn = tools::enrich_asn::run(&state, EnrichAsnRequest { asn: 15169 })
        .await
        .unwrap();
    assert_eq!(asn.organization.as_deref(), Some("Google Inc."));
    assert!(asn.is_hosting);
}

#[tokio::test]
async fn redis_and_postgres_backed_tools_complete_real_round_trip() {
    let (Ok(redis_url), Ok(postgres_url)) = (
        std::env::var("TEST_REDIS_URL"),
        std::env::var("TEST_POSTGRES_URL"),
    ) else {
        eprintln!("skipping backend integration test: TEST_REDIS_URL/TEST_POSTGRES_URL not set");
        return;
    };

    let suffix = Uuid::new_v4().simple().to_string();
    let mut config = Config::default();
    config.redis.url = Some(redis_url);
    config.redis.key_prefix = format!("request_guard_test_{suffix}");
    config.postgres.url = Some(postgres_url);
    let state = AppState::initialize(config).await.unwrap();

    assert!(state.redis.ping().await);
    assert!(state.postgres.ping().await);

    let request_id = format!("backend-integration-{suffix}");
    let original = tools::classify::run(&state, classify_request(request_id.clone(), "GPTBot/1.0"))
        .await
        .unwrap();
    let persisted = state
        .postgres
        .get_decision(&request_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.response.request_id, request_id);
    assert_eq!(persisted.response.verdict, original.verdict);

    let feedback = tools::feedback::run(
        &state,
        FeedbackRequest {
            request_id: request_id.clone(),
            correct_verdict: original.verdict.to_string(),
            notes: Some("backend integration test".to_string()),
            reporter: Some("test-suite".to_string()),
        },
    )
    .await
    .unwrap();
    assert!(feedback.accepted);

    let replay = tools::replay_decision::run(
        &state,
        ReplayRequest {
            request_id: request_id.clone(),
            deterministic: Some(true),
        },
    )
    .await
    .unwrap();
    assert!(replay.matches_original);

    let calibration = tools::calibration_report::run(
        &state,
        CalibrationReportRequest {
            window_hours: Some(1),
        },
    )
    .await
    .unwrap();
    assert!(calibration.samples >= 1);

    let drift = tools::drift_report::run(
        &state,
        DriftReportRequest {
            since: None,
            window_hours: Some(1),
        },
    )
    .await
    .unwrap();
    assert!(drift.metrics.samples >= 1);

    let second_state = AppState::initialize((*state.config).clone()).await.unwrap();
    let cached = tools::classify::run(
        &second_state,
        classify_request(format!("cached-{suffix}"), "GPTBot/1.0"),
    )
    .await
    .unwrap();
    assert!((cached.score - original.score).abs() < 1e-12);

    state
        .redis
        .store_threat(
            "ip",
            "198.51.100.9",
            &ThreatRecord {
                threat_type: "scanner".to_string(),
                severity: "high".to_string(),
                source: "integration-test".to_string(),
                last_seen: Some("2026-08-11T00:00:00Z".to_string()),
                metadata: None,
            },
        )
        .await
        .unwrap();
    let threat = tools::threat_lookup::run(
        &state,
        ThreatLookupRequest {
            indicator: "198.51.100.9".to_string(),
            indicator_type: Some("ip".to_string()),
        },
    )
    .await
    .unwrap();
    assert!(threat.found);
    assert_eq!(threat.source.as_deref(), Some("integration-test"));
    let reputation = tools::enrich_ip::run(
        &state,
        EnrichIpRequest {
            ip: "198.51.100.9".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(reputation.risk_score, 0.9);

    state
        .redis
        .store_threat(
            "asn",
            "64501",
            &ThreatRecord {
                threat_type: "hostile_network".to_string(),
                severity: "critical".to_string(),
                source: "integration-test".to_string(),
                last_seen: None,
                metadata: None,
            },
        )
        .await
        .unwrap();
    let asn_reputation = tools::enrich_asn::run(&state, EnrichAsnRequest { asn: 64501 })
        .await
        .unwrap();
    assert_eq!(asn_reputation.risk_score, 1.0);

    let canary_token = format!("canary-secret-{suffix}");
    state
        .redis
        .register_canary(
            &canary_token,
            &CanaryRecord {
                canary_id: format!("canary-{suffix}"),
                metadata: Some(json!({"owner": "integration-test"})),
            },
        )
        .await
        .unwrap();
    let canary = tools::canary_eval::run(
        &state,
        CanaryEvalRequest {
            token: canary_token,
            context: Some(json!({"path": "/protected"})),
        },
    )
    .await
    .unwrap();
    assert!(canary.triggered);

    let operation_id = state
        .redis
        .record_tool_started("integration", 30)
        .await
        .unwrap();
    let active = tools::queue_status::run(
        &state,
        QueueStatusRequest {
            queue: Some("integration".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(active.queues[0].depth, 1);
    state
        .redis
        .record_tool_finished("integration", &operation_id)
        .await
        .unwrap();
    let completed = tools::queue_status::run(
        &state,
        QueueStatusRequest {
            queue: Some("integration".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(completed.queues[0].depth, 0);
    assert!(completed.queues[0].rate_per_second > 0.0);

    let health = tools::health::run(&state).await;
    assert_eq!(health.status, "healthy");
}
