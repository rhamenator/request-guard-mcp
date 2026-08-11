use crate::models::{request::ClassifyRequest, response::ClassifyResponse};
use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PersistedDecision {
    pub request: ClassifyRequest,
    pub response: ClassifyResponse,
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
            sqlx::raw_sql(
                r#"
                CREATE TABLE IF NOT EXISTS mcp_decisions (
                    request_id TEXT PRIMARY KEY,
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
                    correct_verdict TEXT NOT NULL,
                    notes TEXT,
                    reporter TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_feedback_request_id
                    ON mcp_feedback (request_id);
                CREATE INDEX IF NOT EXISTS idx_mcp_feedback_created_at
                    ON mcp_feedback (created_at DESC);

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
            .execute(pool)
            .await
            .context("failed to initialize PostgreSQL persistence schema")?;
            Ok(())
        }

        pub async fn record_decision(
            &self,
            request: &ClassifyRequest,
            response: &ClassifyResponse,
        ) -> Result<()> {
            let pool = self.pool()?;
            let request_payload = serde_json::to_value(request)?;
            let response_payload = serde_json::to_value(response)?;
            sqlx::query(
                r#"
                INSERT INTO mcp_decisions
                    (request_id, request_payload, response_payload, verdict, score, created_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (request_id) DO UPDATE SET
                    request_payload = EXCLUDED.request_payload,
                    response_payload = EXCLUDED.response_payload,
                    verdict = EXCLUDED.verdict,
                    score = EXCLUDED.score,
                    created_at = EXCLUDED.created_at
                "#,
            )
            .bind(&response.request_id)
            .bind(request_payload)
            .bind(response_payload)
            .bind(response.verdict.to_string())
            .bind(response.score)
            .execute(pool)
            .await
            .context("failed to persist classification decision")?;
            Ok(())
        }

        pub async fn get_decision(&self, request_id: &str) -> Result<Option<PersistedDecision>> {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT request_payload, response_payload FROM mcp_decisions WHERE request_id = $1",
            )
            .bind(request_id)
            .fetch_optional(pool)
            .await
            .context("failed to load persisted decision")?;
            row.map(|row| {
                let request: Value = row.try_get("request_payload")?;
                let response: Value = row.try_get("response_payload")?;
                Ok(PersistedDecision {
                    request: serde_json::from_value(request)?,
                    response: serde_json::from_value(response)?,
                })
            })
            .transpose()
        }

        pub async fn record_feedback(
            &self,
            request_id: &str,
            correct_verdict: &str,
            notes: Option<&str>,
            reporter: Option<&str>,
        ) -> Result<String> {
            let pool = self.pool()?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mcp_decisions WHERE request_id = $1)",
            )
            .bind(request_id)
            .fetch_one(pool)
            .await
            .context("failed to verify feedback request id")?;
            if !exists {
                return Err(anyhow!("classification request id was not found"));
            }
            let feedback_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO mcp_feedback
                    (feedback_id, request_id, correct_verdict, notes, reporter)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(&feedback_id)
            .bind(request_id)
            .bind(correct_verdict)
            .bind(notes)
            .bind(reporter)
            .execute(pool)
            .await
            .context("failed to persist classification feedback")?;
            Ok(feedback_id)
        }

        pub async fn drift_summary(
            &self,
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
                WHERE created_at >= $1
                "#,
            )
            .bind(start)
            .bind(midpoint)
            .fetch_one(pool)
            .await
            .context("failed to aggregate decision drift")?;

            let verdict_rows = sqlx::query(
                r#"
                SELECT verdict, COUNT(*)::BIGINT AS count
                FROM mcp_decisions
                WHERE created_at >= $1
                GROUP BY verdict
                "#,
            )
            .bind(start)
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
                WHERE d.created_at >= $1
                GROUP BY signal->>'name'
                "#,
            )
            .bind(start)
            .bind(midpoint)
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
                    WHERE created_at >= $1
                    ORDER BY request_id, created_at DESC
                ) f
                JOIN mcp_decisions d ON d.request_id = f.request_id
                "#,
            )
            .bind(start)
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
            _request: &ClassifyRequest,
            _response: &ClassifyResponse,
        ) -> Result<()> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn get_decision(&self, _request_id: &str) -> Result<Option<PersistedDecision>> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn record_feedback(
            &self,
            _request_id: &str,
            _correct_verdict: &str,
            _notes: Option<&str>,
            _reporter: Option<&str>,
        ) -> Result<String> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn drift_summary(
            &self,
            _start: DateTime<Utc>,
            _midpoint: DateTime<Utc>,
        ) -> Result<DriftSummary> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
        pub async fn calibration_summary(
            &self,
            _start: DateTime<Utc>,
        ) -> Result<CalibrationSummary> {
            Err(anyhow!("PostgreSQL integration feature is disabled"))
        }
    }
}

pub use inner::PostgresClient;
