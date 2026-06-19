use crate::config::Config;
use crate::integrations::cache::CacheStore;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Shared application state passed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub semaphore: Arc<Semaphore>,
    pub cache: Arc<CacheStore>,
    pub metrics: Arc<AppMetrics>,
    pub feature_flags: Arc<DashMap<String, bool>>,
    pub request_counter: Arc<AtomicU64>,
    pub build_info: Arc<BuildInfo>,
}

use once_cell::sync::Lazy;

static REQUESTS_TOTAL: Lazy<prometheus::IntCounterVec> = Lazy::new(|| {
    prometheus::register_int_counter_vec!(
        "mcp_requests_total",
        "Total number of MCP tool requests",
        &["tool", "status"]
    )
    .expect("metric registration")
});

static REQUEST_DURATION: Lazy<prometheus::HistogramVec> = Lazy::new(|| {
    prometheus::register_histogram_vec!(
        "mcp_request_duration_seconds",
        "MCP tool request duration in seconds",
        &["tool"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("metric registration")
});

static ACTIVE_CONNECTIONS: Lazy<prometheus::IntGauge> = Lazy::new(|| {
    prometheus::register_int_gauge!(
        "mcp_active_connections",
        "Number of active WebSocket connections"
    )
    .expect("metric registration")
});

static TOOL_ERRORS_TOTAL: Lazy<prometheus::IntCounterVec> = Lazy::new(|| {
    prometheus::register_int_counter_vec!(
        "mcp_tool_errors_total",
        "Total number of tool errors by type",
        &["tool", "error_code"]
    )
    .expect("metric registration")
});

pub struct AppMetrics {
    pub requests_total: &'static prometheus::IntCounterVec,
    pub request_duration_seconds: &'static prometheus::HistogramVec,
    pub active_connections: &'static prometheus::IntGauge,
    pub tool_errors_total: &'static prometheus::IntCounterVec,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: &REQUESTS_TOTAL,
            request_duration_seconds: &REQUEST_DURATION,
            active_connections: &ACTIVE_CONNECTIONS,
            tool_errors_total: &TOOL_ERRORS_TOTAL,
        }
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct BuildInfo {
    pub version: String,
    pub git_commit: String,
    pub build_date: String,
    pub rust_version: String,
}

impl BuildInfo {
    pub fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            build_date: option_env!("BUILD_DATE").unwrap_or("unknown").to_string(),
            rust_version: option_env!("RUST_VERSION").unwrap_or("unknown").to_string(),
        }
    }
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let concurrency = config.limits.global_concurrency;
        let config = Arc::new(config);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let cache = Arc::new(CacheStore::new());
        let metrics = Arc::new(AppMetrics::new());
        let feature_flags = Arc::new(DashMap::new());
        let request_counter = Arc::new(AtomicU64::new(0));
        let build_info = Arc::new(BuildInfo::current());

        // Initialize default feature flags
        feature_flags.insert("batch_classify".to_string(), config.features.enable_batch);
        feature_flags.insert("enrichment".to_string(), config.features.enable_enrichment);
        feature_flags.insert("feedback".to_string(), config.features.enable_feedback);
        feature_flags.insert("drift_report".to_string(), true);
        feature_flags.insert("canary_eval".to_string(), true);

        Self {
            config,
            semaphore,
            cache,
            metrics,
            feature_flags,
            request_counter,
            build_info,
        }
    }

    pub fn next_request_id(&self) -> u64 {
        self.request_counter.fetch_add(1, Ordering::Relaxed)
    }
}
