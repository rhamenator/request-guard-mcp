use crate::models::{request::ClassifyRequest, response::ClassifyResponse};
use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Never use a caller-supplied request ID as a global persistence key.
/// The caller scope is already a server-keyed digest of the bearer token.
fn scoped_decision_key(caller_scope: &str, request_id: &str) -> String {
    let mut input = Vec::with_capacity(caller_scope.len() + request_id.len() + 1);
    input.extend_from_slice(caller_scope.as_bytes());
    input.push(0);
    input.extend_from_slice(request_id.as_bytes());
    crate::util::hashing::sha256_hex(&input)
}

/// Store only the inputs used by today's replayable rules. Header values,
/// bodies, arbitrary extra data, IPs, referrers and timestamps are not needed
/// to recompute those rules and may contain credentials or personal data.
/// Keep the presence of a header map: None and Some(empty) produce different
/// missing-header signals in the current rule engine.
fn replay_feature_snapshot(request: &ClassifyRequest) -> ClassifyRequest {
    let headers = request.headers.as_ref().map(|original| {
        let mut names = HashMap::new();
        for name in original.keys() {
            match name.to_ascii_lowercase().as_str() {
                "accept" => {
                    names.insert("accept".to_string(), String::new());
                }
                "accept-language" => {
                    names.insert("accept-language".to_string(), String::new());
                }
                _ => {}
            }
        }
        names
    });
    ClassifyRequest {
        ip: None,
        user_agent: request.user_agent.clone(),
        path: request.path.clone(),
        method: request.method.clone(),
        headers,
        body_snippet: None,
        referer: None,
        accept: None,
        // The response payload already retains the ID for caller-scoped
        // lookup; replay assigns a fresh ID before classification.
        request_id: None,
        timestamp: None,
        // Attested TLS provenance is intentionally not persisted. Replay of
        // an attested fingerprint cannot reproduce the original trusted TLS
        // signals after the short-lived attestation has expired.
        tls_ja3: None,
        tls_ja4: None,
        tls_fingerprint_source: None,
        tls_fingerprint_attestation: None,
        tls_fingerprint_verified: false,
        extra: None,
    }
}

#[derive(Debug, Clone)]
pub struct PersistedDecision {
    pub request: ClassifyRequest,
    pub response: ClassifyResponse,
    /// Exact stored JSON, retained to reject feedback if this row changes
    /// between the tool's read and its locked insert.
    pub request_payload: serde_json::Value,
    pub response_payload: serde_json::Value,
}

fn responses_match(mut old: serde_json::Value, mut new: serde_json::Value) -> bool {
    // PostgreSQL JSONB canonicalizes decimal numbers (for example,
    // 0.9437499999999999 to 0.94375), and a retry has a new latency.
    // All other response fields must still match for feedback to survive.
    let score_matches = old["score"]
        .as_f64()
        .zip(new["score"].as_f64())
        .is_some_and(|(a, b)| (a - b).abs() <= 1e-12);
    for response in [&mut old, &mut new] {
        if let Some(fields) = response.as_object_mut() {
            fields.remove("score");
            fields.remove("latency_ms");
        }
    }
    score_matches && old == new
}

#[derive(Debug, Clone, Default)]
pub struct DriftSummary {
    pub samples: u64,
    pub previous_samples: u64,
    pub current_samples: u64,
    pub score_mean: f64,
    pub score_stddev: f64,
    pub previous_score_mean: f64,
    pub verdict_distribution: HashMap<String, u64>,
    pub signal_drift: HashMap<String, f64>,
}

#[derive(Debug, Clone, Default)]
pub struct CalibrationSummary {
    pub samples: u64,
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
}

#[cfg(feature = "postgres-integration")]
mod inner {
    use super::*;
    use crate::config::PostgresConfig;
    use anyhow::Context;
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use sqlx::{PgPool, Row};
    use std::time::Duration;
    use tracing::info;
    use uuid::Uuid;

    // Fixed project namespace for schema DDL. PostgreSQL advisory locks are
    // scoped to a database, so independent installations do not contend.
    const SCHEMA_INIT_LOCK_KEY: i64 = 0x5251_474d_4350_5343;

    pub struct PostgresClient {
        pool: Option<PgPool>,
    }

    impl PostgresClient {
        pub fn disabled() -> Self {
            Self { pool: None }
        }

        pub async fn connect(config: &PostgresConfig) -> Result<Self> {
            let Some(url) = &config.url else {
                return Ok(Self::disabled());
            };
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(config.max_connections)
                .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
                .connect(url)
                .await
                .context("failed to connect to configured PostgreSQL")?;
            let client = Self { pool: Some(pool) };
            client.initialize_schema().await?;
            info!("PostgreSQL persistence initialized");
            Ok(client)
        }

        pub fn is_available(&self) -> bool {
            self.pool.is_some()
        }

        fn pool(&self) -> Result<&PgPool> {
            self.pool
                .as_ref()
                .ok_or_else(|| anyhow!("PostgreSQL is not configured"))
        }

        pub async fn ping(&self) -> bool {
            let Ok(pool) = self.pool() else {
                return false;
            };
            sqlx::query("SELECT 1").execute(pool).await.is_ok()
        }

        async fn initialize_schema(&self) -> Result<()> {
            let pool = self.pool()?;
            // Multiple server replicas may initialize the same database at once.
            // Serialize DDL across processes; the lock releases on commit or rollback.
            let mut transaction = pool
                .begin()
                .await
                .context("failed to begin PostgreSQL schema initialization")?;
            sqlx::query("SET LOCAL lock_timeout = '30s'")
                .execute(&mut *transaction)
                .await
                .context("failed to bound PostgreSQL schema lock wait")?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(SCHEMA_INIT_LOCK_KEY)
                .execute(&mut *transaction)
                .await
                .context("failed to lock PostgreSQL schema initialization")?;
            // Avoid taking table DDL locks on every process startup. In a
            // rolling restart, another process can be writing feedback while
            // this one initializes; even CREATE TABLE IF NOT EXISTS can then
            // deadlock with that writer. Check the complete current schema
            // under the initializer lock, and run DDL only for a new or legacy
            // schema that actually needs it. Keep this object list in sync
            // with the DDL below; the real-PostgreSQL integration test holds
            // a read lock across a second startup and checks index repair.
            let schema_complete: bool = sqlx::query_scalar(
                r#"
                SELECT to_regclass('mcp_decisions') IS NOT NULL
                   AND to_regclass('mcp_feedback') IS NOT NULL
                   AND to_regclass('idx_mcp_decisions_created_at') IS NOT NULL
                   AND to_regclass('idx_mcp_decisions_verdict') IS NOT NULL
                   AND to_regclass('idx_mcp_feedback_request_id') IS NOT NULL
                   AND to_regclass('idx_mcp_feedback_created_at') IS NOT NULL
                   AND to_regclass('idx_mcp_decisions_caller_created') IS NOT NULL
                   AND to_regclass('idx_mcp_feedback_caller_created') IS NOT NULL
                   AND EXISTS (
                       SELECT 1 FROM pg_attribute
                       WHERE attrelid = to_regclass('mcp_decisions')
                         AND attname = 'caller_scope' AND NOT attisdropped
                   )
                   AND EXISTS (
                       SELECT 1 FROM pg_attribute
                       WHERE attrelid = to_regclass('mcp_feedback')
                         AND attname = 'caller_scope' AND NOT attisdropped
                   )
                   AND EXISTS (
                       SELECT 1 FROM pg_constraint
                       WHERE conrelid = to_regclass('mcp_feedback')
                         AND conname = 'mcp_feedback_request_id_fkey'
                   )
                "#,
            )
            .fetch_one(&mut *transaction)
            .await
            .context("failed to inspect PostgreSQL persistence schema")?;
            if schema_complete {
                transaction
                    .commit()
                    .await
                    .context("failed to commit PostgreSQL schema inspection")?;
                return Ok(());
            }
            sqlx::raw_sql(
                r#"
                CREATE TABLE IF NOT EXISTS mcp_decisions (
                    request_id TEXT PRIMARY KEY,
                    caller_scope TEXT,
                    request_payload JSONB NOT NULL,
                    response_payload JSONB NOT NULL,
                    verdict TEXT NOT NULL,
                    score DOUBLE PRECISION NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_decisions_created_at
                    ON mcp_decisions (created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_mcp_decisions_verdict
                    ON mcp_decisions (verdict, created_at DESC);

                CREATE TABLE IF NOT EXISTS mcp_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL REFERENCES mcp_decisions(request_id) ON DELETE CASCADE,
                    caller_scope TEXT,
                    correct_verdict TEXT NOT NULL,
                    notes TEXT,
                    reporter TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_feedback_request_id
                    ON mcp_feedback (request_id);
                CREATE INDEX IF NOT EXISTS idx_mcp_feedback_created_at
                    ON mcp_feedback (created_at DESC);

                -- Existing unscoped rows are retained for offline migration, but
                -- are invisible to authenticated replay and reporting.
                ALTER TABLE mcp_decisions ADD COLUMN IF NOT EXISTS caller_scope TEXT;
                ALTER TABLE mcp_feedback ADD COLUMN IF NOT EXISTS caller_scope TEXT;
                CREATE INDEX IF NOT EXISTS idx_mcp_decisions_caller_created
                    ON mcp_decisions (caller_scope, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_mcp_feedback_caller_created
                    ON mcp_feedback (caller_scope, created_at DESC);

                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'mcp_feedback_request_id_fkey'
                    ) THEN
                        ALTER TABLE mcp_feedback
                            ADD CONSTRAINT mcp_feedback_request_id_fkey
                            FOREIGN KEY (request_id) REFERENCES mcp_decisions(request_id)
                            ON DELETE CASCADE;
                    END IF;
                END $$;
                "#,
            )
            .execute(&mut *transaction)
            .await
            .context("failed to initialize PostgreSQL persistence schema")?;
            transaction
                .commit()
                .await
                .context("failed to commit PostgreSQL persistence schema")?;
            Ok(())
        }

        pub async fn record_decision(
            &self,
            caller_scope: &str,
            request: &ClassifyRequest,
            response: &ClassifyResponse,
        ) -> Result<()> {
            let pool = self.pool()?;
            let request_payload = serde_json::to_value(replay_feature_snapshot(request))?;
            let response_payload = serde_json::to_value(response)?;
            let decision_key = scoped_decision_key(caller_scope, &response.request_id);
            let mut transaction = pool
                .begin()
                .await
                .context("failed to begin classification decision update")?;
            // Lock the logical key before looking for a row. A row lock alone
            // cannot serialize two first inserts: both could see no row, then
            // the second upsert could replace the first without clearing its
            // newly submitted feedback.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(&decision_key)
                .execute(&mut *transaction)
                .await
                .context("failed to lock classification decision key")?;
            let previous = sqlx::query(
                "SELECT request_payload, response_payload FROM mcp_decisions WHERE request_id = $1 AND caller_scope = $2 FOR UPDATE",
            )
            .bind(&decision_key)
            .bind(caller_scope)
            .fetch_optional(&mut *transaction)
            .await
            .context("failed to inspect existing classification decision")?;
            let replaces_distinct_decision = previous.is_some_and(|row| {
                let old_request: Value = row.get("request_payload");
                let old_response: Value = row.get("response_payload");
                old_request != request_payload
                    || !responses_match(old_response, response_payload.clone())
            });
            sqlx::query(
                r#"
                INSERT INTO mcp_decisions
                    (request_id, caller_scope, request_payload, response_payload, verdict, score, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (request_id) DO UPDATE SET
                    caller_scope = EXCLUDED.caller_scope,
                    request_payload = EXCLUDED.request_payload,
                    response_payload = EXCLUDED.response_payload,
                    verdict = EXCLUDED.verdict,
                    score = EXCLUDED.score,
                    created_at = EXCLUDED.created_at
                "#,
            )
            .bind(&decision_key)
            .bind(caller_scope)
            .bind(request_payload)
            .bind(response_payload)
            .bind(response.verdict.to_string())
            .bind(response.score)
            .execute(&mut *transaction)
            .await
            .context("failed to persist classification decision")?;
            if replaces_distinct_decision {
                // A changed decision invalidates old labels; an identical
                // retry does not. The row lock also orders concurrent feedback
                // inserts against this replacement.
                sqlx::query("DELETE FROM mcp_feedback WHERE request_id = $1 AND caller_scope = $2")
                    .bind(&decision_key)
                    .bind(caller_scope)
                    .execute(&mut *transaction)
                    .await
                    .context("failed to clear feedback for replaced decision")?;
            }
            transaction
                .commit()
                .await
                .context("failed to commit classification decision update")?;
            Ok(())
        }

        pub async fn get_decision(
            &self,
            caller_scope: &str,
            request_id: &str,
        ) -> Result<Option<PersistedDecision>> {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT request_payload, response_payload FROM mcp_decisions WHERE request_id = $1 AND caller_scope = $2",
            )
            .bind(scoped_decision_key(caller_scope, request_id))
            .bind(caller_scope)
            .fetch_optional(pool)
            .await
            .context("failed to load persisted decision")?;
            row.map(|row| {
                let request_payload: Value = row.try_get("request_payload")?;
                let response_payload: Value = row.try_get("response_payload")?;
                Ok(PersistedDecision {
                    request: serde_json::from_value(request_payload.clone())?,
                    response: serde_json::from_value(response_payload.clone())?,
                    request_payload,
                    response_payload,
                })
            })
            .transpose()
        }

        pub async fn record_feedback(
            &self,
            caller_scope: &str,
            request_id: &str,
            correct_verdict: &str,
            notes: Option<&str>,
            reporter: Option<&str>,
            expected: &PersistedDecision,
        ) -> Result<Option<String>> {
            let pool = self.pool()?;
            let decision_key = scoped_decision_key(caller_scope, request_id);
            let mut transaction = pool
                .begin()
                .await
                .context("failed to begin classification feedback update")?;
            let current = sqlx::query(
                "SELECT request_payload, response_payload FROM mcp_decisions WHERE request_id = $1 AND caller_scope = $2 FOR UPDATE",
            )
            .bind(&decision_key)
            .bind(caller_scope)
            .fetch_optional(&mut *transaction)
            .await
            .context("failed to lock feedback decision")?;
            let Some(current) = current else {
                return Ok(None);
            };
            let request_payload: Value = current.try_get("request_payload")?;
            let response_payload: Value = current.try_get("response_payload")?;
            if request_payload != expected.request_payload
                || !responses_match(response_payload, expected.response_payload.clone())
            {
                return Ok(None);
            }
            let feedback_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO mcp_feedback
                    (feedback_id, request_id, caller_scope, correct_verdict, notes, reporter)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(&feedback_id)
            .bind(&decision_key)
            .bind(caller_scope)
            .bind(correct_verdict)
            .bind(notes)
            .bind(reporter)
            .execute(&mut *transaction)
            .await
            .context("failed to persist classification feedback")?;
            transaction
                .commit()
                .await
                .context("failed to commit classification feedback update")?;
            Ok(Some(feedback_id))
        }

        pub async fn drift_summary(
            &self,
            caller_scope: &str,
            start: DateTime<Utc>,
            midpoint: DateTime<Utc>,
        ) -> Result<DriftSummary> {
            let pool = self.pool()?;
            let aggregate = sqlx::query(
                r#"
                SELECT COUNT(*)::BIGINT AS samples,
                       COUNT(*) FILTER (WHERE created_at < $2)::BIGINT AS previous_samples,
                       COUNT(*) FILTER (WHERE created_at >= $2)::BIGINT AS current_samples,
                       COALESCE(AVG(score) FILTER (WHERE created_at >= $2), 0)::DOUBLE PRECISION
                           AS score_mean,
                       COALESCE(STDDEV_POP(score), 0)::DOUBLE PRECISION AS score_stddev,
                       COALESCE(AVG(score) FILTER (WHERE created_at < $2), 0)::DOUBLE PRECISION
                           AS previous_score_mean
                FROM mcp_decisions
                WHERE created_at >= $1 AND caller_scope = $3
                "#,
            )
            .bind(start)
            .bind(midpoint)
            .bind(caller_scope)
            .fetch_one(pool)
            .await
            .context("failed to aggregate decision drift")?;

            let verdict_rows = sqlx::query(
                r#"
                SELECT verdict, COUNT(*)::BIGINT AS count
                FROM mcp_decisions
                WHERE created_at >= $1 AND caller_scope = $2
                GROUP BY verdict
                "#,
            )
            .bind(start)
            .bind(caller_scope)
            .fetch_all(pool)
            .await
            .context("failed to aggregate verdict distribution")?;

            let signal_rows = sqlx::query(
                r#"
                SELECT signal->>'name' AS name,
                       COUNT(*) FILTER (WHERE d.created_at < $2)::BIGINT AS previous_count,
                       COUNT(*) FILTER (WHERE d.created_at >= $2)::BIGINT AS current_count
                FROM mcp_decisions d
                CROSS JOIN LATERAL jsonb_array_elements(d.response_payload->'signals') signal
                WHERE d.created_at >= $1 AND d.caller_scope = $3
                GROUP BY signal->>'name'
                "#,
            )
            .bind(start)
            .bind(midpoint)
            .bind(caller_scope)
            .fetch_all(pool)
            .await
            .context("failed to aggregate signal drift")?;

            let verdict_distribution = verdict_rows
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get("verdict")?,
                        row.try_get::<i64, _>("count")? as u64,
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            let previous_samples = aggregate.try_get::<i64, _>("previous_samples")? as f64;
            let current_samples = aggregate.try_get::<i64, _>("current_samples")? as f64;
            let signal_drift = signal_rows
                .into_iter()
                .map(|row| {
                    let name: String = row.try_get("name")?;
                    let previous = row.try_get::<i64, _>("previous_count")? as f64;
                    let current = row.try_get::<i64, _>("current_count")? as f64;
                    let previous_rate = previous / previous_samples.max(1.0);
                    let current_rate = current / current_samples.max(1.0);
                    let change = current_rate - previous_rate;
                    Ok((name, change))
                })
                .collect::<Result<HashMap<_, _>>>()?;

            Ok(DriftSummary {
                samples: aggregate.try_get::<i64, _>("samples")? as u64,
                previous_samples: previous_samples as u64,
                current_samples: current_samples as u64,
                score_mean: aggregate.try_get("score_mean")?,
                score_stddev: aggregate.try_get("score_stddev")?,
                previous_score_mean: aggregate.try_get("previous_score_mean")?,
                verdict_distribution,
                signal_drift,
            })
        }

        pub async fn calibration_summary(
            &self,
            caller_scope: &str,
            start: DateTime<Utc>,
        ) -> Result<CalibrationSummary> {
            let pool = self.pool()?;
            let row = sqlx::query(
                r#"
                SELECT COUNT(*)::BIGINT AS samples,
                    COUNT(*) FILTER (
                        WHERE d.verdict IN ('block', 'flag', 'challenge')
                          AND f.correct_verdict IN ('block', 'flag', 'challenge')
                    )::BIGINT AS true_positives,
                    COUNT(*) FILTER (
                        WHERE d.verdict IN ('block', 'flag', 'challenge')
                          AND f.correct_verdict = 'allow'
                    )::BIGINT AS false_positives,
                    COUNT(*) FILTER (
                        WHERE d.verdict = 'allow' AND f.correct_verdict = 'allow'
                    )::BIGINT AS true_negatives,
                    COUNT(*) FILTER (
                        WHERE d.verdict = 'allow'
                          AND f.correct_verdict IN ('block', 'flag', 'challenge')
                    )::BIGINT AS false_negatives
                FROM (
                    SELECT DISTINCT ON (request_id)
                           request_id, correct_verdict, created_at
                    FROM mcp_feedback
                    WHERE created_at >= $1 AND caller_scope = $2
                    ORDER BY request_id, created_at DESC
                ) f
                JOIN mcp_decisions d ON d.request_id = f.request_id AND d.caller_scope = $2
                "#,
            )
            .bind(start)
            .bind(caller_scope)
            .fetch_one(pool)
            .await
            .context("failed to aggregate calibration data")?;
            Ok(CalibrationSummary {
                samples: row.try_get::<i64, _>("samples")? as u64,
                true_positives: row.try_get::<i64, _>("true_positives")? as u64,
                false_positives: row.try_get::<i64, _>("false_positives")? as u64,
                true_negatives: row.try_get::<i64, _>("true_negatives")? as u64,
                false_negatives: row.try_get::<i64, _>("false_negatives")? as u64,
            })
        }
    }
}

#[cfg(not(feature = "postgres-integration"))]
mod inner {
    use super::*;
    use crate::config::PostgresConfig;
    use chrono::{DateTime, Utc};

    pub struct PostgresClient;

    impl PostgresClient {
        pub fn disabled() -> Self {
            Self
        }
        pub async fn connect(_config: &PostgresConfig) -> Result<Self> {
            Ok(Self)
        }
        pub fn is_available(&self) -> bool {
            false
        }
        pub async fn ping(&self) -> bool {
            false
        }
        pub async fn record_decision(
            &self,
            _caller_scope: &str,
            _request: &ClassifyRequest,
            _response: &ClassifyResponse,
        ) -> Result<()> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn get_decision(
            &self,
            _caller_scope: &str,
            _request_id: &str,
        ) -> Result<Option<PersistedDecision>> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn record_feedback(
            &self,
            _caller_scope: &str,
            _request_id: &str,
            _correct_verdict: &str,
            _notes: Option<&str>,
            _reporter: Option<&str>,
            _expected: &PersistedDecision,
        ) -> Result<Option<String>> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn drift_summary(
            &self,
            _caller_scope: &str,
            _start: DateTime<Utc>,
            _midpoint: DateTime<Utc>,
        ) -> Result<DriftSummary> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn calibration_summary(
            &self,
            _caller_scope: &str,
            _start: DateTime<Utc>,
        ) -> Result<CalibrationSummary> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
    }
}

pub use inner::PostgresClient;

#[cfg(test)]
mod scoped_key_tests {
    use super::{replay_feature_snapshot, scoped_decision_key};
    use crate::{engines::RuleEngine, models::request::ClassifyRequest};

    #[test]
    fn identical_request_ids_have_distinct_persistence_keys_per_caller() {
        let first = scoped_decision_key("caller:first", "same-id");
        let second = scoped_decision_key("caller:second", "same-id");
        assert_ne!(first, second);
        assert_eq!(first, scoped_decision_key("caller:first", "same-id"));
        assert!(!first.contains("same-id"));
    }

    #[test]
    fn replay_snapshot_drops_sensitive_values_without_changing_current_rule_signals() {
        let request: ClassifyRequest = serde_json::from_value(serde_json::json!({
            "ip": "198.51.100.42",
            "user_agent": "Nikto",
            "path": "/internal",
            "method": "GET",
            "headers": {
                "ACCEPT": "application/json; synthetic-header-secret",
                "Cookie": "synthetic-cookie-secret",
                "Authorization": "synthetic-auth-secret"
            },
            "body_snippet": "synthetic-body-secret",
            "referer": "https://example.test/synthetic-referer-secret",
            "accept": "synthetic-accept-secret",
            "request_id": "synthetic-request-id-secret",
            "timestamp": "synthetic-timestamp-secret",
            "extra": {"token": "synthetic-extra-secret"}
        }))
        .unwrap();
        let snapshot = replay_feature_snapshot(&request);
        let payload = serde_json::to_string(&snapshot).unwrap();
        for marker in [
            "synthetic-header-secret",
            "synthetic-cookie-secret",
            "synthetic-auth-secret",
            "synthetic-body-secret",
            "synthetic-referer-secret",
            "synthetic-accept-secret",
            "synthetic-timestamp-secret",
            "synthetic-extra-secret",
            "synthetic-request-id-secret",
            "198.51.100.42",
        ] {
            assert!(
                !payload.contains(marker),
                "persisted replay payload contains {marker}"
            );
        }
        assert_eq!(
            snapshot.headers.unwrap().get("accept"),
            Some(&String::new())
        );
        let original_signals = RuleEngine::new().evaluate(&request);
        let replayed: ClassifyRequest = serde_json::from_str(&payload).unwrap();
        let replayed_signals = RuleEngine::new().evaluate(&replayed);
        assert_eq!(
            serde_json::to_value(original_signals).unwrap(),
            serde_json::to_value(replayed_signals).unwrap()
        );
    }

    #[test]
    fn replay_snapshot_preserves_absent_versus_empty_header_map() {
        let absent: ClassifyRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        let empty: ClassifyRequest =
            serde_json::from_value(serde_json::json!({"headers": {}})).unwrap();
        assert!(replay_feature_snapshot(&absent).headers.is_none());
        assert!(replay_feature_snapshot(&empty).headers.unwrap().is_empty());
    }
}
