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

#[tokio::test]
async fn changed_tls_threat_set_does_not_reuse_distributed_classification_verdict() {
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        assert!(
            !matches!(std::env::var("REQUIRE_TEST_BACKENDS").as_deref(), Ok("1")),
            "required Redis integration URL is missing"
        );
        return;
    };
    eprintln!("running real Redis classification cache-domain regression");

    let ja3 = "72a589da586844d7f0818ce684948eea";
    let attestation_key = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let prefix = format!(
        "request_guard_cache_domain_test_{}",
        Uuid::new_v4().simple()
    );
    let mut config = Config::default();
    config.redis.url = Some(redis_url);
    config.redis.key_prefix = prefix;
    config.tls_fingerprints.attestation_key = Some(attestation_key.clone());
    let first_state = AppState::initialize(config.clone()).await.unwrap();

    let mut request = classify_request(Uuid::new_v4().to_string(), "Mozilla/5.0");
    request.path = Some("/products".into());
    request.tls_ja3 = Some(ja3.into());
    request.tls_fingerprint_source = Some("envoy".into());
    request.tls_fingerprint_attestation = Some(
        request_guard_mcp::util::tls_attestation::create_attestation(
            attestation_key.as_bytes(),
            chrono::Utc::now().timestamp(),
            request.ip.as_deref().unwrap(),
            request.method.as_deref().unwrap(),
            request.path.as_deref().unwrap(),
            request.tls_ja3.as_deref(),
            None,
            request.tls_fingerprint_source.as_deref().unwrap(),
        )
        .unwrap(),
    );
    let first = tools::classify::run(&first_state, request.clone())
        .await
        .unwrap();
    assert_eq!(first.verdict.to_string(), "allow");
    let mut cached_request = request.clone();
    cached_request.tls_fingerprint_verified = true;
    let old_key = request_guard_mcp::util::hashing::request_fingerprint(
        "internal",
        &cached_request,
        &first_state.classification_cache_domain,
    );
    assert!(first_state
        .redis
        .cache_get(&old_key)
        .await
        .unwrap()
        .is_some());

    config.tls_fingerprints.known_bad_ja3 = vec![ja3.into()];
    let second_state = AppState::initialize(config).await.unwrap();
    let second = tools::classify::run(&second_state, request).await.unwrap();
    assert_eq!(second.verdict.to_string(), "block");
    assert!(second
        .signals
        .iter()
        .any(|signal| signal.name == "tls_fingerprint_known_bad"));
}

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
async fn non_public_ip_enrichment_needs_no_optional_backend() {
    let state = AppState::initialize(Config::default()).await.unwrap();
    for ip in ["::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
        let response = tools::enrich_ip::run(&state, EnrichIpRequest { ip: ip.into() })
            .await
            .unwrap();
        assert_eq!(response.risk_score, 0.0, "{ip}");
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
        assert!(
            !matches!(std::env::var("REQUIRE_TEST_BACKENDS").as_deref(), Ok("1")),
            "required Redis/PostgreSQL integration URLs are missing"
        );
        eprintln!("skipping backend integration test: TEST_REDIS_URL/TEST_POSTGRES_URL not set");
        return;
    };

    eprintln!("running real Redis and PostgreSQL integration round trip");

    let suffix = Uuid::new_v4().simple().to_string();
    let mut config = Config::default();
    config.redis.url = Some(redis_url.clone());
    config.redis.key_prefix = format!("request_guard_test_{suffix}");
    config.postgres.url = Some(postgres_url);
    config.auth.cache_scope_hmac_key = Some("integration-test-scope-key-32-bytes-long".to_string());
    let state = AppState::initialize(config).await.unwrap();

    assert!(state.redis.ping().await);
    assert!(state.postgres.ping().await);

    let request_id = format!("backend-integration-{suffix}");
    let original = tools::classify::run(&state, classify_request(request_id.clone(), "GPTBot/1.0"))
        .await
        .unwrap();
    let persisted = state
        .postgres
        .get_decision("internal", &request_id)
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
    let mapped_threat = tools::threat_lookup::run(
        &state,
        ThreatLookupRequest {
            indicator: "::ffff:198.51.100.9".to_string(),
            indicator_type: Some("ip".to_string()),
        },
    )
    .await
    .unwrap();
    assert!(mapped_threat.found);
    assert_eq!(mapped_threat.source.as_deref(), Some("integration-test"));
    let reputation = tools::enrich_ip::run(
        &state,
        EnrichIpRequest {
            ip: "198.51.100.9".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(reputation.risk_score, 0.9);
    let mapped_reputation = tools::enrich_ip::run(
        &state,
        EnrichIpRequest {
            ip: "::ffff:198.51.100.9".to_string(),
        },
    )
    .await
    .unwrap();
    assert_eq!(mapped_reputation.risk_score, reputation.risk_score);
    assert_eq!(mapped_reputation.ip, "::ffff:198.51.100.9");

    state
        .redis
        .store_threat(
            "ip",
            "::ffff:198.51.100.10",
            &ThreatRecord {
                threat_type: "legacy_mapped".to_string(),
                severity: "medium".to_string(),
                source: "integration-test".to_string(),
                last_seen: None,
                metadata: None,
            },
        )
        .await
        .unwrap();
    let legacy_mapped = tools::threat_lookup::run(
        &state,
        ThreatLookupRequest {
            indicator: "::ffff:198.51.100.10".to_string(),
            indicator_type: Some("ip".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(legacy_mapped.threat_type.as_deref(), Some("legacy_mapped"));

    #[cfg(feature = "redis-integration")]
    {
        let client = deadpool_redis::redis::Client::open(redis_url).unwrap();
        let mut redis = client.get_multiplexed_async_connection().await.unwrap();
        let blocklist_key = format!("{}:blocklist:ips", state.config.redis.key_prefix);
        let _: usize = deadpool_redis::redis::cmd("SADD")
            .arg(&blocklist_key)
            .arg("198.51.100.11")
            .query_async(&mut redis)
            .await
            .unwrap();
        let listed = tools::threat_lookup::run(
            &state,
            ThreatLookupRequest {
                indicator: "::ffff:198.51.100.11".to_string(),
                indicator_type: Some("ip".to_string()),
            },
        )
        .await
        .unwrap();
        assert_eq!(listed.threat_type.as_deref(), Some("blocklisted_ip"));
        let _: usize = deadpool_redis::redis::cmd("DEL")
            .arg(&blocklist_key)
            .query_async(&mut redis)
            .await
            .unwrap();
    }

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
    #[cfg(feature = "redis-integration")]
    {
        let client =
            deadpool_redis::redis::Client::open(state.config.redis.url.as_ref().unwrap().as_str())
                .unwrap();
        let mut redis = client.get_multiplexed_async_connection().await.unwrap();
        let event: Option<String> = deadpool_redis::redis::cmd("LINDEX")
            .arg(format!("{}:canary_events", state.config.redis.key_prefix))
            .arg(0)
            .query_async(&mut redis)
            .await
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event.unwrap()).unwrap();
        assert_eq!(event["context"], json!({"path": "/protected"}));
    }

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
    assert_eq!(
        active.queues[0].consumers,
        state
            .config
            .limits
            .global_concurrency
            .min(u32::MAX as usize) as u32
    );
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

    let unknown = tools::queue_status::run(
        &state,
        QueueStatusRequest {
            queue: Some("not-recorded".to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(unknown.queues[0].name, "not-recorded");
    assert_eq!(unknown.queues[0].depth, 0);
    assert_eq!(unknown.queues[0].consumers, active.queues[0].consumers);

    let health = tools::health::run(&state).await;
    assert_eq!(health.status, "healthy");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_postgres_schema_initialization_completes() {
    let Ok(postgres_url) = std::env::var("TEST_POSTGRES_URL") else {
        assert!(
            !matches!(std::env::var("REQUIRE_TEST_BACKENDS").as_deref(), Ok("1")),
            "required PostgreSQL integration URL is missing"
        );
        return;
    };

    // Isolate the first-run DDL race from the other parallel backend tests.
    let schema = format!("request_guard_{}", Uuid::new_v4().simple());
    let admin = sqlx::PgPool::connect(&postgres_url).await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let separator = if postgres_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{postgres_url}{separator}options[search_path]={schema}");

    let initialize = || {
        let mut config = Config::default();
        config.postgres.url = Some(scoped_url.clone());
        AppState::initialize(config)
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::try_join!(initialize(), initialize(), initialize(), initialize())
    })
    .await
    .expect("concurrent PostgreSQL schema initialization timed out");
    let (a, b, c, d) = result.expect("concurrent PostgreSQL schema initialization failed");
    assert!(a.postgres.ping().await);
    assert!(b.postgres.ping().await);
    assert!(c.postgres.ping().await);
    assert!(d.postgres.ping().await);
    let created: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name = 'mcp_decisions'",
    )
    .bind(&schema)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(created.0, 1, "schema URL did not isolate the first-run DDL");
    drop((a, b, c, d));
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn initialized_postgres_schema_does_not_wait_for_ddl_lock() {
    let Ok(postgres_url) = std::env::var("TEST_POSTGRES_URL") else {
        assert!(
            !matches!(std::env::var("REQUIRE_TEST_BACKENDS").as_deref(), Ok("1")),
            "required PostgreSQL integration URL is missing"
        );
        return;
    };

    let schema = format!("request_guard_{}", Uuid::new_v4().simple());
    let admin = sqlx::PgPool::connect(&postgres_url).await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let separator = if postgres_url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{postgres_url}{separator}options[search_path]={schema}");
    let mut config = Config::default();
    config.postgres.url = Some(scoped_url);
    let first = AppState::initialize(config.clone()).await.unwrap();

    // ACCESS SHARE permits ordinary feedback DML but blocks the unnecessary
    // ACCESS EXCLUSIVE table lock of CREATE TABLE IF NOT EXISTS. The second
    // initializer must finish while this transaction still holds the lock.
    let mut writer = admin.begin().await.unwrap();
    sqlx::query(&format!(
        "LOCK TABLE {schema}.mcp_decisions IN ACCESS SHARE MODE"
    ))
    .execute(&mut *writer)
    .await
    .unwrap();
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        AppState::initialize(config.clone()),
    )
    .await
    .expect("initialized schema unexpectedly waited for table DDL lock")
    .unwrap();
    assert!(second.postgres.ping().await);
    writer.rollback().await.unwrap();
    // A legacy or incomplete schema must still take the migration path.
    sqlx::query(&format!(
        "DROP INDEX {schema}.idx_mcp_feedback_caller_created"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let repaired = AppState::initialize(config).await.unwrap();
    let restored: (bool,) = sqlx::query_as("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("{schema}.idx_mcp_feedback_caller_created"))
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(
        restored.0,
        "schema initialization did not restore missing index"
    );
    drop((first, second, repaired));
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn replacing_a_decision_does_not_relabel_its_old_feedback() {
    let Ok(postgres_url) = std::env::var("TEST_POSTGRES_URL") else {
        assert!(
            !matches!(std::env::var("REQUIRE_TEST_BACKENDS").as_deref(), Ok("1")),
            "required PostgreSQL integration URL is missing"
        );
        return;
    };
    let mut config = Config::default();
    config.postgres.url = Some(postgres_url);
    config.auth.cache_scope_hmac_key = Some("integration-test-scope-key-32-bytes-long".to_string());
    let state = AppState::initialize(config).await.unwrap();
    let request_id = format!("replace-feedback-{}", Uuid::new_v4());
    let caller_scope = format!("caller:replace-feedback-{}", Uuid::new_v4());

    let mut suspicious = classify_request(request_id.clone(), "sqlmap/1.7");
    suspicious.path = Some("/.env".to_string());
    let first = tools::classify::run_scoped(&state, suspicious, &caller_scope)
        .await
        .unwrap();
    assert_eq!(first.verdict.to_string(), "block");
    let feedback = tools::feedback::run_scoped(
        &state,
        FeedbackRequest {
            request_id: request_id.clone(),
            correct_verdict: "allow".to_string(),
            notes: None,
            reporter: None,
        },
        &caller_scope,
    )
    .await
    .unwrap();
    assert!(feedback.accepted);
    let report_request = CalibrationReportRequest {
        window_hours: Some(1),
    };
    let before =
        tools::calibration_report::run_scoped(&state, report_request.clone(), &caller_scope)
            .await
            .unwrap();
    assert_eq!(before.samples, 1);
    assert_eq!(before.false_positive_rate, 1.0);

    let mut retry = classify_request(request_id.clone(), "sqlmap/1.7");
    retry.path = Some("/.env".to_string());
    tools::classify::run_scoped(&state, retry, &caller_scope)
        .await
        .unwrap();
    let after_retry =
        tools::calibration_report::run_scoped(&state, report_request.clone(), &caller_scope)
            .await
            .unwrap();
    assert_eq!(
        after_retry.samples, 1,
        "equivalent retry must keep feedback"
    );
    assert_eq!(after_retry.false_positive_rate, 1.0);

    let mut benign = classify_request(request_id.clone(), "Mozilla/5.0");
    benign.path = Some("/welcome".to_string());
    let replacement = tools::classify::run_scoped(&state, benign, &caller_scope)
        .await
        .unwrap();
    assert_eq!(replacement.verdict.to_string(), "allow");
    let after =
        tools::calibration_report::run_scoped(&state, report_request.clone(), &caller_scope)
            .await
            .unwrap();
    assert_eq!(
        after.samples, 0,
        "old feedback must not label a new decision"
    );

    tools::feedback::run_scoped(
        &state,
        FeedbackRequest {
            request_id,
            correct_verdict: "allow".to_string(),
            notes: None,
            reporter: None,
        },
        &caller_scope,
    )
    .await
    .unwrap();
    let latest = tools::calibration_report::run_scoped(&state, report_request, &caller_scope)
        .await
        .unwrap();
    assert_eq!(latest.samples, 1);
    assert_eq!(latest.false_positive_rate, 0.0);
}

#[tokio::test]
async fn postgres_decisions_and_reports_are_isolated_by_caller() {
    let Ok(postgres_url) = std::env::var("TEST_POSTGRES_URL") else {
        eprintln!("skipping PostgreSQL isolation test: TEST_POSTGRES_URL not set");
        return;
    };
    let mut config = Config::default();
    config.postgres.url = Some(postgres_url);
    config.auth.cache_scope_hmac_key = Some("integration-test-scope-key-32-bytes-long".to_string());
    let state = AppState::initialize(config).await.unwrap();
    let request_id = format!("scope-test-{}", Uuid::new_v4());
    let a = "caller:integration-a";
    let b = "caller:integration-b";
    let original = tools::classify::run_scoped(
        &state,
        classify_request(request_id.clone(), "GPTBot/1.0"),
        a,
    )
    .await
    .unwrap();
    assert!(state
        .postgres
        .get_decision(a, &request_id)
        .await
        .unwrap()
        .is_some());
    assert!(state
        .postgres
        .get_decision(b, &request_id)
        .await
        .unwrap()
        .is_none());
    assert!(tools::replay_decision::run_scoped(
        &state,
        ReplayRequest {
            request_id: request_id.clone(),
            deterministic: Some(true)
        },
        b,
    )
    .await
    .is_err());
    assert!(tools::feedback::run_scoped(
        &state,
        FeedbackRequest {
            request_id: request_id.clone(),
            correct_verdict: "allow".into(),
            notes: None,
            reporter: None
        },
        b,
    )
    .await
    .is_err());
    let a_report = tools::drift_report::run_scoped(
        &state,
        DriftReportRequest {
            since: None,
            window_hours: Some(1),
        },
        a,
    )
    .await
    .unwrap();
    let b_report = tools::drift_report::run_scoped(
        &state,
        DriftReportRequest {
            since: None,
            window_hours: Some(1),
        },
        b,
    )
    .await
    .unwrap();
    assert!(a_report.metrics.samples >= 1);
    assert_eq!(b_report.metrics.samples, 0);
    let other = tools::classify::run_scoped(
        &state,
        classify_request(request_id.clone(), "Mozilla/5.0"),
        b,
    )
    .await
    .unwrap();
    assert_ne!(original.verdict, other.verdict);
    assert_eq!(
        state
            .postgres
            .get_decision(a, &request_id)
            .await
            .unwrap()
            .unwrap()
            .response
            .verdict,
        original.verdict
    );
    assert_eq!(
        state
            .postgres
            .get_decision(b, &request_id)
            .await
            .unwrap()
            .unwrap()
            .response
            .verdict,
        other.verdict
    );
}
