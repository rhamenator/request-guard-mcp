use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::time::Duration;

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "defaults::host")]
    pub host: String,
    #[serde(default = "defaults::port")]
    pub port: u16,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub postgres: PostgresConfig,
    #[serde(default)]
    pub geoip: GeoipConfig,
    #[serde(default)]
    pub features: FeatureConfig,
    #[serde(default)]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Comma-separated list of valid bearer tokens (or path to file).
    #[serde(default)]
    pub tokens: Vec<String>,
    /// If true, auth is enforced.
    #[serde(default = "defaults::auth_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "defaults::max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "defaults::max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default = "defaults::global_concurrency")]
    pub global_concurrency: usize,
    #[serde(default = "defaults::per_tool_timeout_secs")]
    pub per_tool_timeout_secs: u64,
    #[serde(default = "defaults::classify_timeout_secs")]
    pub classify_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "defaults::metrics_path")]
    pub metrics_path: String,
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    #[serde(default = "defaults::service_name")]
    pub service_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "defaults::redis_pool_size")]
    pub pool_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "defaults::pg_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeoipConfig {
    #[serde(default)]
    pub mmdb_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeatureConfig {
    #[serde(default = "defaults::enable_batch")]
    pub enable_batch: bool,
    #[serde(default = "defaults::enable_enrichment")]
    pub enable_enrichment: bool,
    #[serde(default = "defaults::enable_feedback")]
    pub enable_feedback: bool,
}

impl Config {
    /// Load configuration from environment variables and optional config file.
    pub fn load() -> Result<Self> {
        let _ = dotenvy::dotenv();
        let mut builder = config::Config::builder();

        // Optional config file
        if let Ok(path) = std::env::var("CONFIG_FILE") {
            builder = builder.add_source(config::File::with_name(&path).required(false));
        }

        // Environment variables with prefix MCP_
        builder = builder.add_source(
            config::Environment::with_prefix("MCP")
                .separator("__")
                .try_parsing(true),
        );

        // Also read plain env vars for common settings
        if let Ok(val) = std::env::var("AUTH_TOKENS") {
            let tokens: Vec<String> = val.split(',').map(|s| s.trim().to_string()).collect();
            if !tokens.is_empty() {
                builder = builder.set_override("auth.tokens", tokens)?;
            }
        }

        if let Ok(val) = std::env::var("LOG_LEVEL") {
            builder = builder.set_override("log_level", val)?;
        }

        let cfg: Config = builder
            .build()
            .context("failed to build config")?
            .try_deserialize()
            .context("failed to deserialize config")?;

        Ok(cfg)
    }

    pub fn bind_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:8085".parse().unwrap())
    }

    pub fn per_tool_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.per_tool_timeout_secs)
    }

    pub fn classify_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.classify_timeout_secs)
    }
}

mod defaults {
    pub fn host() -> String {
        "0.0.0.0".to_string()
    }
    pub fn port() -> u16 {
        8085
    }
    pub fn auth_enabled() -> bool {
        true
    }
    pub fn max_request_bytes() -> usize {
        1024 * 1024 // 1 MiB
    }
    pub fn max_batch_size() -> usize {
        50
    }
    pub fn global_concurrency() -> usize {
        256
    }
    pub fn per_tool_timeout_secs() -> u64 {
        30
    }
    pub fn classify_timeout_secs() -> u64 {
        5
    }
    pub fn metrics_path() -> String {
        "/metrics".to_string()
    }
    pub fn service_name() -> String {
        "ai-scraping-defense-mcp".to_string()
    }
    pub fn redis_pool_size() -> usize {
        16
    }
    pub fn pg_max_connections() -> u32 {
        10
    }
    pub fn enable_batch() -> bool {
        true
    }
    pub fn enable_enrichment() -> bool {
        true
    }
    pub fn enable_feedback() -> bool {
        true
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            tokens: vec![],
            enabled: defaults::auth_enabled(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: defaults::max_request_bytes(),
            max_batch_size: defaults::max_batch_size(),
            global_concurrency: defaults::global_concurrency(),
            per_tool_timeout_secs: defaults::per_tool_timeout_secs(),
            classify_timeout_secs: defaults::classify_timeout_secs(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_path: defaults::metrics_path(),
            otlp_endpoint: None,
            service_name: defaults::service_name(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: None,
            pool_size: defaults::redis_pool_size(),
        }
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: defaults::pg_max_connections(),
        }
    }
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            enable_batch: defaults::enable_batch(),
            enable_enrichment: defaults::enable_enrichment(),
            enable_feedback: defaults::enable_feedback(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: defaults::host(),
            port: defaults::port(),
            auth: AuthConfig::default(),
            limits: LimitsConfig::default(),
            telemetry: TelemetryConfig::default(),
            redis: RedisConfig::default(),
            postgres: PostgresConfig::default(),
            geoip: GeoipConfig::default(),
            features: FeatureConfig::default(),
            log_level: "info".to_string(),
        }
    }
}
