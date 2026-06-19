/// Redis integration (enabled when the `redis-integration` feature is active).
#[cfg(feature = "redis-integration")]
pub mod inner {
    use crate::config::RedisConfig;
    use deadpool_redis::{Config as DConfig, Pool, Runtime};
    use tracing::{info, warn};

    pub struct RedisClient {
        pool: Option<Pool>,
    }

    impl RedisClient {
        pub fn new(config: &RedisConfig) -> Self {
            let pool = config.url.as_ref().and_then(|url| {
                let cfg = DConfig::from_url(url);
                match cfg.create_pool(Some(Runtime::Tokio1)) {
                    Ok(p) => {
                        info!(url = %url, "Redis pool created");
                        Some(p)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to create Redis pool");
                        None
                    }
                }
            });
            RedisClient { pool }
        }

        pub fn is_available(&self) -> bool {
            self.pool.is_some()
        }

        pub async fn ping(&self) -> bool {
            let Some(ref pool) = self.pool else {
                return false;
            };
            let Ok(mut conn) = pool.get().await else {
                return false;
            };
            deadpool_redis::redis::cmd("PING")
                .query_async::<_, String>(&mut conn)
                .await
                .map(|s| s == "PONG")
                .unwrap_or(false)
        }
    }
}

#[cfg(not(feature = "redis-integration"))]
pub mod inner {
    use crate::config::RedisConfig;

    pub struct RedisClient;

    impl RedisClient {
        pub fn new(_config: &RedisConfig) -> Self {
            RedisClient
        }
        pub fn is_available(&self) -> bool {
            false
        }
        pub async fn ping(&self) -> bool {
            false
        }
    }
}

#[allow(unused_imports)]
pub use inner::RedisClient;
