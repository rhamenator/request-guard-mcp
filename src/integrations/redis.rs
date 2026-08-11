use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatRecord {
    pub threat_type: String,
    pub severity: String,
    pub source: String,
    pub last_seen: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanaryRecord {
    pub canary_id: String,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueueStats {
    pub name: String,
    pub active: u64,
    pub completed_last_minute: u64,
}

#[cfg(feature = "redis-integration")]
mod inner {
    use super::*;
    use crate::config::RedisConfig;
    use crate::util::hashing::sha256_hex;
    use anyhow::Context;
    use deadpool_redis::{Config as DConfig, Pool, PoolConfig, Runtime};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::info;
    use uuid::Uuid;

    pub struct RedisClient {
        pool: Option<Pool>,
        key_prefix: String,
        cache_ttl_secs: u64,
    }

    impl RedisClient {
        pub fn disabled() -> Self {
            Self {
                pool: None,
                key_prefix: "request_guard".to_string(),
                cache_ttl_secs: 300,
            }
        }

        pub async fn connect(config: &RedisConfig) -> Result<Self> {
            let Some(url) = &config.url else {
                return Ok(Self {
                    pool: None,
                    key_prefix: config.key_prefix.clone(),
                    cache_ttl_secs: config.cache_ttl_secs,
                });
            };
            let mut cfg = DConfig::from_url(url);
            cfg.pool = Some(PoolConfig::new(config.pool_size));
            let pool = cfg
                .create_pool(Some(Runtime::Tokio1))
                .context("failed to create configured Redis pool")?;
            let client = Self {
                pool: Some(pool),
                key_prefix: config.key_prefix.clone(),
                cache_ttl_secs: config.cache_ttl_secs,
            };
            if !client.ping().await {
                return Err(anyhow!("configured Redis did not respond to PING"));
            }
            info!("Redis integration initialized");
            Ok(client)
        }

        pub fn is_available(&self) -> bool {
            self.pool.is_some()
        }

        fn pool(&self) -> Result<&Pool> {
            self.pool
                .as_ref()
                .ok_or_else(|| anyhow!("Redis is not configured"))
        }

        fn key(&self, suffix: &str) -> String {
            format!("{}:{}", self.key_prefix, suffix)
        }

        async fn connection(&self) -> Result<deadpool_redis::Connection> {
            self.pool()?
                .get()
                .await
                .context("failed to obtain Redis connection")
        }

        pub async fn ping(&self) -> bool {
            let Ok(mut connection) = self.connection().await else {
                return false;
            };
            deadpool_redis::redis::cmd("PING")
                .query_async::<_, String>(&mut connection)
                .await
                .map(|reply| reply == "PONG")
                .unwrap_or(false)
        }

        pub async fn cache_get(&self, fingerprint: &str) -> Result<Option<Value>> {
            let mut connection = self.connection().await?;
            let value: Option<String> = deadpool_redis::redis::cmd("GET")
                .arg(self.key(&format!("cache:{fingerprint}")))
                .query_async(&mut connection)
                .await
                .context("failed to read distributed classification cache")?;
            value
                .map(|json| serde_json::from_str(&json).context("invalid JSON in Redis cache"))
                .transpose()
        }

        pub async fn cache_set(&self, fingerprint: &str, value: &Value) -> Result<()> {
            let mut connection = self.connection().await?;
            let json = serde_json::to_string(value)?;
            deadpool_redis::redis::cmd("SETEX")
                .arg(self.key(&format!("cache:{fingerprint}")))
                .arg(self.cache_ttl_secs)
                .arg(json)
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to write distributed classification cache")
        }

        pub async fn threat_lookup(
            &self,
            indicator_type: &str,
            indicator: &str,
        ) -> Result<Option<ThreatRecord>> {
            let mut connection = self.connection().await?;
            let value: Option<String> = deadpool_redis::redis::cmd("HGET")
                .arg(self.key(&format!("threats:{indicator_type}")))
                .arg(indicator)
                .query_async(&mut connection)
                .await
                .context("failed to query Redis threat intelligence")?;
            if let Some(json) = value {
                return Ok(Some(
                    serde_json::from_str(&json).context("invalid Redis threat record")?,
                ));
            }
            if indicator_type == "ip" {
                let listed: bool = deadpool_redis::redis::cmd("SISMEMBER")
                    .arg(self.key("blocklist:ips"))
                    .arg(indicator)
                    .query_async(&mut connection)
                    .await
                    .context("failed to query Redis IP blocklist")?;
                if listed {
                    return Ok(Some(ThreatRecord {
                        threat_type: "blocklisted_ip".to_string(),
                        severity: "high".to_string(),
                        source: "redis_blocklist".to_string(),
                        last_seen: None,
                        metadata: None,
                    }));
                }
            }
            Ok(None)
        }

        pub async fn store_threat(
            &self,
            indicator_type: &str,
            indicator: &str,
            record: &ThreatRecord,
        ) -> Result<()> {
            let mut connection = self.connection().await?;
            deadpool_redis::redis::cmd("HSET")
                .arg(self.key(&format!("threats:{indicator_type}")))
                .arg(indicator)
                .arg(serde_json::to_string(record)?)
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to store Redis threat record")
        }

        pub async fn canary_lookup(
            &self,
            token: &str,
            context: Option<&Value>,
        ) -> Result<Option<CanaryRecord>> {
            let mut connection = self.connection().await?;
            let token_hash = sha256_hex(token.as_bytes());
            let value: Option<String> = deadpool_redis::redis::cmd("HGET")
                .arg(self.key("canaries"))
                .arg(&token_hash)
                .query_async(&mut connection)
                .await
                .context("failed to query Redis canary registry")?;
            let Some(json) = value else {
                return Ok(None);
            };
            let record: CanaryRecord =
                serde_json::from_str(&json).context("invalid Redis canary record")?;
            let event_context = context.map(bounded_context).transpose()?;
            let event = serde_json::json!({
                "canary_id": record.canary_id,
                "token_hash": token_hash,
                "triggered_at": chrono::Utc::now().to_rfc3339(),
                "context": event_context,
            });
            deadpool_redis::redis::cmd("LPUSH")
                .arg(self.key("canary_events"))
                .arg(serde_json::to_string(&event)?)
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to record Redis canary event")?;
            deadpool_redis::redis::cmd("LTRIM")
                .arg(self.key("canary_events"))
                .arg(0)
                .arg(9_999)
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to trim Redis canary events")?;
            Ok(Some(record))
        }

        pub async fn register_canary(&self, token: &str, record: &CanaryRecord) -> Result<()> {
            let mut connection = self.connection().await?;
            deadpool_redis::redis::cmd("HSET")
                .arg(self.key("canaries"))
                .arg(sha256_hex(token.as_bytes()))
                .arg(serde_json::to_string(record)?)
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to register Redis canary")
        }

        pub async fn record_tool_started(&self, tool: &str, timeout_secs: u64) -> Result<String> {
            let mut connection = self.connection().await?;
            let operation_id = Uuid::new_v4().to_string();
            let now = unix_seconds()?;
            let active_key = self.key(&format!("queue:{tool}:active"));
            deadpool_redis::redis::pipe()
                .atomic()
                .cmd("ZREMRANGEBYSCORE")
                .arg(&active_key)
                .arg(0)
                .arg(now - timeout_secs as f64 * 2.0)
                .ignore()
                .cmd("ZADD")
                .arg(&active_key)
                .arg(now)
                .arg(&operation_id)
                .ignore()
                .cmd("EXPIRE")
                .arg(&active_key)
                .arg(timeout_secs.saturating_mul(4).max(60))
                .ignore()
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to record Redis tool start")?;
            Ok(operation_id)
        }

        pub async fn record_tool_finished(&self, tool: &str, operation_id: &str) -> Result<()> {
            let mut connection = self.connection().await?;
            let now = unix_seconds()?;
            let active_key = self.key(&format!("queue:{tool}:active"));
            let completed_key = self.key(&format!("queue:{tool}:completed"));
            deadpool_redis::redis::pipe()
                .atomic()
                .cmd("ZREM")
                .arg(active_key)
                .arg(operation_id)
                .ignore()
                .cmd("ZADD")
                .arg(&completed_key)
                .arg(now)
                .arg(operation_id)
                .ignore()
                .cmd("ZREMRANGEBYSCORE")
                .arg(&completed_key)
                .arg(0)
                .arg(now - 300.0)
                .ignore()
                .cmd("EXPIRE")
                .arg(completed_key)
                .arg(600)
                .ignore()
                .query_async::<_, ()>(&mut connection)
                .await
                .context("failed to record Redis tool completion")
        }

        pub async fn queue_stats(&self, requested: Option<&str>) -> Result<Vec<QueueStats>> {
            let mut connection = self.connection().await?;
            let names = if let Some(name) = requested {
                vec![name.to_string()]
            } else {
                self.scan_queue_names(&mut connection).await?
            };
            let now = unix_seconds()?;
            let mut stats = Vec::with_capacity(names.len());
            for name in names {
                let active: u64 = deadpool_redis::redis::cmd("ZCARD")
                    .arg(self.key(&format!("queue:{name}:active")))
                    .query_async(&mut connection)
                    .await
                    .context("failed to query active Redis operations")?;
                let completed_last_minute: u64 = deadpool_redis::redis::cmd("ZCOUNT")
                    .arg(self.key(&format!("queue:{name}:completed")))
                    .arg(now - 60.0)
                    .arg("+inf")
                    .query_async(&mut connection)
                    .await
                    .context("failed to query Redis completion rate")?;
                stats.push(QueueStats {
                    name,
                    active,
                    completed_last_minute,
                });
            }
            stats.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(stats)
        }

        async fn scan_queue_names(
            &self,
            connection: &mut deadpool_redis::Connection,
        ) -> Result<Vec<String>> {
            let pattern = self.key("queue:*:active");
            let prefix = self.key("queue:");
            let mut cursor = 0_u64;
            let mut names = Vec::new();
            loop {
                let (next, keys): (u64, Vec<String>) = deadpool_redis::redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(connection)
                    .await
                    .context("failed to scan Redis operation queues")?;
                names.extend(keys.into_iter().filter_map(|key| {
                    key.strip_prefix(&prefix)
                        .and_then(|rest| rest.strip_suffix(":active"))
                        .map(str::to_string)
                }));
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
            names.sort();
            names.dedup();
            Ok(names)
        }
    }

    fn unix_seconds() -> Result<f64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs_f64())
    }

    fn bounded_context(context: &Value) -> Result<Value> {
        let encoded = serde_json::to_vec(context)?;
        if encoded.len() <= 4096 {
            return Ok(context.clone());
        }
        Ok(serde_json::json!({
            "truncated": true,
            "sha256": sha256_hex(&encoded),
            "original_bytes": encoded.len(),
        }))
    }
}

#[cfg(not(feature = "redis-integration"))]
mod inner {
    use super::*;
    use crate::config::RedisConfig;

    pub struct RedisClient;
    impl RedisClient {
        pub fn disabled() -> Self {
            Self
        }
        pub async fn connect(_config: &RedisConfig) -> Result<Self> {
            Ok(Self)
        }
        pub fn is_available(&self) -> bool {
            false
        }
        pub async fn ping(&self) -> bool {
            false
        }
        pub async fn cache_get(&self, _fingerprint: &str) -> Result<Option<Value>> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn cache_set(&self, _fingerprint: &str, _value: &Value) -> Result<()> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn threat_lookup(
            &self,
            _indicator_type: &str,
            _indicator: &str,
        ) -> Result<Option<ThreatRecord>> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn store_threat(
            &self,
            _indicator_type: &str,
            _indicator: &str,
            _record: &ThreatRecord,
        ) -> Result<()> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn canary_lookup(
            &self,
            _token: &str,
            _context: Option<&Value>,
        ) -> Result<Option<CanaryRecord>> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn register_canary(&self, _token: &str, _record: &CanaryRecord) -> Result<()> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn record_tool_started(&self, _tool: &str, _timeout_secs: u64) -> Result<String> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn record_tool_finished(&self, _tool: &str, _operation_id: &str) -> Result<()> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
        pub async fn queue_stats(&self, _requested: Option<&str>) -> Result<Vec<QueueStats>> {
            Err(anyhow!("Redis integration feature is disabled"))
        }
    }
}

pub use inner::RedisClient;
