use moka::future::Cache;
use serde_json::Value;
use std::time::Duration;

/// In-process LRU cache with TTL eviction.
pub struct CacheStore {
    inner: Cache<String, Value>,
}

impl CacheStore {
    pub fn new() -> Self {
        let inner = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(300))
            .build();
        CacheStore { inner }
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        self.inner.get(key).await
    }

    pub async fn set(&self, key: &str, value: Value) {
        self.inner.insert(key.to_string(), value).await;
    }

    pub async fn set_ttl(&self, key: &str, value: Value, _ttl: Duration) {
        // moka cache-level TTL; per-entry TTL requires different config
        self.inner.insert(key.to_string(), value).await;
    }

    pub async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }
}

impl Default for CacheStore {
    fn default() -> Self {
        Self::new()
    }
}
