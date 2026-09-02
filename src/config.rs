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
    pub tls_fingerprints: TlsFingerprintConfig,
    #[serde(default = "defaults::log_level")]
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
    /// Server-side HMAC key (>= 32 bytes) for deriving per-caller cache
    /// scopes from bearer tokens. Leave unset to use a process-local random
    /// key; configure it to keep scopes stable across restarts and replicas.
    #[serde(default)]
    pub cache_scope_hmac_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "defaults::max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "defaults::max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default = "defaults::global_concurrency")]
    pub global_concurrency: usize,
    #[serde(default = "defaults::max_connections")]
    pub max_connections: usize,
    #[serde(default = "defaults::websocket_idle_timeout_secs")]
    pub websocket_idle_timeout_secs: u64,
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
    #[serde(default = "defaults::redis_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "defaults::redis_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "defaults::pg_max_connections")]
    pub max_connections: u32,
    #[serde(default = "defaults::integration_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeoipConfig {
    /// Backwards-compatible City database path.
    #[serde(default)]
    pub mmdb_path: Option<String>,
    #[serde(default)]
    pub city_mmdb_path: Option<String>,
    #[serde(default)]
    pub asn_mmdb_path: Option<String>,
    #[serde(default)]
    pub anonymous_ip_mmdb_path: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct TlsFingerprintConfig {
    #[serde(default)]
    pub attestation_key: Option<String>,
    #[serde(default)]
    pub previous_attestation_key: Option<String>,
    #[serde(default = "defaults::tls_attestation_max_age_seconds")]
    pub max_age_seconds: u64,
    #[serde(default)]
    pub known_bad_ja3: Vec<String>,
    #[serde(default)]
    pub known_bad_ja4: Vec<String>,
}

impl Config {
    /// Load configuration from environment variables and optional config file.
    pub fn load() -> Result<Self> {
        if let Err(error) = dotenvy::dotenv() {
            match &error {
                dotenvy::Error::Io(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
                }
                _ => return Err(error).context("failed to load .env"),
            }
        }
        let mut builder = config::Config::builder();

        // Optional config file
        if let Ok(path) = std::env::var("CONFIG_FILE") {
            builder = builder.add_source(config::File::with_name(&path).required(true));
        }

        // Environment variables with prefix MCP_
        builder = builder.add_source(
            config::Environment::with_prefix("MCP")
                .separator("__")
                .try_parsing(true),
        );

        // Also read plain env vars for common settings
        if let Ok(val) = std::env::var("AUTH_TOKENS") {
            let tokens: Vec<String> = val
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect();
            if !tokens.is_empty() {
                builder = builder.set_override("auth.tokens", tokens)?;
            }
        }

        if let Ok(val) = std::env::var("CACHE_SCOPE_HMAC_KEY") {
            if !val.trim().is_empty() {
                builder = builder.set_override("auth.cache_scope_hmac_key", val)?;
            }
        }

        if let Ok(val) = std::env::var("TLS_FINGERPRINT_ATTESTATION_KEY") {
            if !val.trim().is_empty() {
                builder = builder.set_override("tls_fingerprints.attestation_key", val)?;
            }
        }
        if let Ok(val) = std::env::var("TLS_FINGERPRINT_ATTESTATION_PREVIOUS_KEY") {
            if !val.trim().is_empty() {
                builder = builder.set_override("tls_fingerprints.previous_attestation_key", val)?;
            }
        }
        if let Ok(val) = std::env::var("TLS_FINGERPRINT_ATTESTATION_MAX_AGE_SECONDS") {
            let max_age = val
                .parse::<u64>()
                .context("TLS_FINGERPRINT_ATTESTATION_MAX_AGE_SECONDS must be an integer")?;
            builder = builder.set_override("tls_fingerprints.max_age_seconds", max_age)?;
        }
        if let Ok(val) = std::env::var("TLS_KNOWN_BAD_JA3") {
            let values = val
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            builder = builder.set_override("tls_fingerprints.known_bad_ja3", values)?;
        }
        if let Ok(val) = std::env::var("TLS_KNOWN_BAD_JA4") {
            let values = val
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            builder = builder.set_override("tls_fingerprints.known_bad_ja4", values)?;
        }

        if let Ok(val) = std::env::var("LOG_LEVEL") {
            builder = builder.set_override("log_level", val)?;
        }

        let cfg: Config = builder
            .build()
            .context("failed to build config")?
            .try_deserialize()
            .context("failed to deserialize config")?;

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .with_context(|| format!("invalid bind address {}:{}", self.host, self.port))
    }

    pub fn per_tool_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.per_tool_timeout_secs)
    }

    pub fn classify_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.classify_timeout_secs)
    }

    fn validate(&self) -> Result<()> {
        if self.auth.enabled {
            if self.auth.tokens.is_empty() {
                anyhow::bail!("authentication is enabled but AUTH_TOKENS is empty");
            }
            if self.auth.tokens.iter().any(|token| {
                token.len() < 32
                    || token == "replace_me"
                    || token == "replace_me_with_a_strong_token"
            }) {
                anyhow::bail!(
                    "AUTH_TOKENS entries must contain at least 32 characters and cannot be placeholders; run python scripts/configure_credentials.py"
                );
            }
        } else if !self.bind_addr()?.ip().is_loopback() {
            anyhow::bail!(
                "authentication may only be disabled when MCP__HOST is a loopback address"
            );
        }
        if self
            .auth
            .cache_scope_hmac_key
            .as_deref()
            .is_some_and(|key| key.len() < 32)
        {
            anyhow::bail!("CACHE_SCOPE_HMAC_KEY must contain at least 32 bytes when configured");
        }
        if self
            .tls_fingerprints
            .attestation_key
            .as_deref()
            .is_some_and(|key| key.len() < 32)
        {
            anyhow::bail!(
                "TLS_FINGERPRINT_ATTESTATION_KEY must contain at least 32 bytes when configured"
            );
        }
        if self
            .tls_fingerprints
            .previous_attestation_key
            .as_deref()
            .is_some_and(|key| key.len() < 32)
        {
            anyhow::bail!(
                "TLS_FINGERPRINT_ATTESTATION_PREVIOUS_KEY must contain at least 32 bytes when configured"
            );
        }
        if self.tls_fingerprints.max_age_seconds == 0 {
            anyhow::bail!("TLS fingerprint attestation max age must be positive");
        }
        if self
            .tls_fingerprints
            .known_bad_ja3
            .iter()
            .any(|value| crate::util::tls_attestation::normalize_ja3(Some(value)).is_none())
        {
            anyhow::bail!("TLS_KNOWN_BAD_JA3 contains a malformed JA3 digest");
        }
        if self
            .tls_fingerprints
            .known_bad_ja4
            .iter()
            .any(|value| crate::util::tls_attestation::normalize_ja4(Some(value)).is_none())
        {
            anyhow::bail!("TLS_KNOWN_BAD_JA4 contains a malformed JA4 fingerprint");
        }
        if self.limits.max_request_bytes == 0
            || self.limits.max_batch_size == 0
            || self.limits.global_concurrency == 0
            || self.limits.max_connections == 0
            || self.limits.websocket_idle_timeout_secs == 0
            || self.limits.per_tool_timeout_secs == 0
            || self.limits.classify_timeout_secs == 0
        {
            anyhow::bail!("all request, batch, concurrency, and timeout limits must be positive");
        }
        if !self.telemetry.metrics_path.starts_with('/') {
            anyhow::bail!("telemetry.metrics_path must start with '/'");
        }
        if matches!(
            self.telemetry.metrics_path.as_str(),
            "/mcp" | "/health" | "/ready"
        ) {
            anyhow::bail!("telemetry.metrics_path conflicts with a reserved route");
        }
        if let Some(endpoint) = self.telemetry.otlp_endpoint.as_deref() {
            if endpoint.trim().is_empty()
                || !(endpoint.starts_with("http://") || endpoint.starts_with("https://"))
            {
                anyhow::bail!("telemetry.otlp_endpoint must be a non-empty HTTP(S) URL");
            }
        }
        if self.redis.pool_size == 0 || self.redis.cache_ttl_secs == 0 {
            anyhow::bail!("Redis pool size and cache TTL must be positive");
        }
        if self.redis.key_prefix.is_empty()
            || !self.redis.key_prefix.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            anyhow::bail!("redis.key_prefix must contain only ASCII letters, digits, '_' or '-'");
        }
        if self
            .redis
            .url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            anyhow::bail!("redis.url cannot be empty when configured");
        }
        if self.postgres.max_connections == 0 || self.postgres.connect_timeout_secs == 0 {
            anyhow::bail!("PostgreSQL connection count and timeout must be positive");
        }
        if self
            .postgres
            .url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            anyhow::bail!("postgres.url cannot be empty when configured");
        }
        for (name, path) in [
            ("geoip.mmdb_path", self.geoip.mmdb_path.as_deref()),
            ("geoip.city_mmdb_path", self.geoip.city_mmdb_path.as_deref()),
            ("geoip.asn_mmdb_path", self.geoip.asn_mmdb_path.as_deref()),
            (
                "geoip.anonymous_ip_mmdb_path",
                self.geoip.anonymous_ip_mmdb_path.as_deref(),
            ),
        ] {
            if path.is_some_and(|value| value.trim().is_empty()) {
                anyhow::bail!("{name} cannot be empty when configured");
            }
        }
        Ok(())
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
    pub fn max_connections() -> usize {
        256
    }
    pub fn websocket_idle_timeout_secs() -> u64 {
        60
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
        "request-guard-mcp".to_string()
    }
    pub fn log_level() -> String {
        "info".to_string()
    }
    pub fn redis_pool_size() -> usize {
        16
    }
    pub fn redis_key_prefix() -> String {
        "request_guard".to_string()
    }
    pub fn redis_cache_ttl_secs() -> u64 {
        300
    }
    pub fn pg_max_connections() -> u32 {
        10
    }
    pub fn integration_connect_timeout_secs() -> u64 {
        5
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
    pub fn tls_attestation_max_age_seconds() -> u64 {
        60
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            tokens: vec![],
            enabled: defaults::auth_enabled(),
            cache_scope_hmac_key: None,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: defaults::max_request_bytes(),
            max_batch_size: defaults::max_batch_size(),
            global_concurrency: defaults::global_concurrency(),
            max_connections: defaults::max_connections(),
            websocket_idle_timeout_secs: defaults::websocket_idle_timeout_secs(),
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
            key_prefix: defaults::redis_key_prefix(),
            cache_ttl_secs: defaults::redis_cache_ttl_secs(),
        }
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: defaults::pg_max_connections(),
            connect_timeout_secs: defaults::integration_connect_timeout_secs(),
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

impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            attestation_key: None,
            previous_attestation_key: None,
            max_age_seconds: defaults::tls_attestation_max_age_seconds(),
            known_bad_ja3: vec![],
            known_bad_ja4: vec![],
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
            tls_fingerprints: TlsFingerprintConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bind_address_is_reported() {
        let config = Config {
            host: "not a valid address".to_string(),
            ..Config::default()
        };
        assert!(config.bind_addr().is_err());
    }

    #[test]
    fn enabled_auth_requires_a_real_token() {
        assert!(Config::default().validate().is_err());

        let placeholder = Config {
            auth: AuthConfig {
                tokens: vec!["replace_me_with_a_strong_token".to_string()],
                ..AuthConfig::default()
            },
            ..Config::default()
        };
        assert!(placeholder.validate().is_err());

        let valid = Config {
            auth: AuthConfig {
                tokens: vec!["a-real-test-token-with-32-characters".to_string()],
                ..AuthConfig::default()
            },
            ..Config::default()
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn disabled_auth_requires_a_loopback_bind_address() {
        let exposed = Config {
            auth: AuthConfig {
                enabled: false,
                ..AuthConfig::default()
            },
            ..Config::default()
        };
        assert!(exposed.validate().is_err());

        let loopback = Config {
            host: "127.0.0.1".to_string(),
            ..exposed
        };
        assert!(loopback.validate().is_ok());
    }

    #[test]
    fn short_cache_scope_hmac_keys_are_rejected() {
        let base = AuthConfig {
            tokens: vec!["a-real-test-token-with-32-characters".to_string()],
            ..AuthConfig::default()
        };

        let short = Config {
            auth: AuthConfig {
                cache_scope_hmac_key: Some("too-short".to_string()),
                ..base.clone()
            },
            ..Config::default()
        };
        assert!(short.validate().is_err());

        let long_enough = Config {
            auth: AuthConfig {
                cache_scope_hmac_key: Some("0123456789abcdef0123456789abcdef".to_string()),
                ..base
            },
            ..Config::default()
        };
        assert!(long_enough.validate().is_ok());
    }

    #[test]
    fn tls_fingerprint_configuration_is_validated() {
        let auth = AuthConfig {
            enabled: false,
            ..AuthConfig::default()
        };
        let short_previous = Config {
            auth: auth.clone(),
            tls_fingerprints: TlsFingerprintConfig {
                attestation_key: Some("0123456789abcdef0123456789abcdef".into()),
                previous_attestation_key: Some("too-short".into()),
                ..TlsFingerprintConfig::default()
            },
            ..Config::default()
        };
        assert!(short_previous.validate().is_err());

        let malformed_list = Config {
            auth,
            tls_fingerprints: TlsFingerprintConfig {
                known_bad_ja3: vec!["not-a-ja3".into()],
                ..TlsFingerprintConfig::default()
            },
            ..Config::default()
        };
        assert!(malformed_list.validate().is_err());
    }

    #[test]
    fn zero_limits_are_rejected() {
        let config = Config {
            auth: AuthConfig {
                enabled: false,
                ..AuthConfig::default()
            },
            limits: LimitsConfig {
                global_concurrency: 0,
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }
}
