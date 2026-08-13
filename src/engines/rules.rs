use crate::models::{
    request::ClassifyRequest,
    signals::{Signal, SignalSet, SignalSource},
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static AI_BOT_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(GPTBot|ChatGPT-User|Claude-Web|anthropic-ai|Bytespider|CCBot|\
         cohere-ai|DuckAssistBot|FacebookBot|Google-Extended|ImagesiftBot|\
         PerplexityBot|Scrapy|python-httpx|python-requests|aiohttp|curl/|wget/|\
         libwww-perl|Go-http-client|Java/|okhttp)",
    )
    .expect("compile regex")
});

static SCRAPING_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(scrapy|beautifulsoup|mechanize|selenium|phantom|puppeteer|playwright|\
         headless|crawler|spider|bot|scraper)",
    )
    .expect("compile regex")
});

static SENSITIVE_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(\.env|/admin|/api/internal|/wp-admin|/phpmyadmin|\.git/|\
         /etc/passwd|/proc/|/debug|/actuator|/swagger|/graphql|/config)",
    )
    .expect("compile regex")
});

/// Rule-based signal extraction engine.
pub struct RuleEngine {
    known_bad_ja3: HashSet<String>,
    known_bad_ja4: HashSet<String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine {
            known_bad_ja3: HashSet::new(),
            known_bad_ja4: HashSet::new(),
        }
    }

    pub fn with_tls_config(config: &crate::config::TlsFingerprintConfig) -> Self {
        RuleEngine {
            known_bad_ja3: config
                .known_bad_ja3
                .iter()
                .filter_map(|value| {
                    crate::util::tls_attestation::normalize_ja3(Some(value.as_str()))
                })
                .collect(),
            known_bad_ja4: config
                .known_bad_ja4
                .iter()
                .filter_map(|value| {
                    crate::util::tls_attestation::normalize_ja4(Some(value.as_str()))
                })
                .collect(),
        }
    }

    /// Run all rules against a classify request and return a signal set.
    pub fn evaluate(&self, req: &ClassifyRequest) -> SignalSet {
        let mut signals = SignalSet::default();

        if let Some(ua) = &req.user_agent {
            self.eval_user_agent(ua, &mut signals);
        }

        if let Some(path) = &req.path {
            self.eval_path(path, &mut signals);
        }

        if let Some(headers) = &req.headers {
            self.eval_headers(headers, &mut signals);
        }

        if let Some(method) = &req.method {
            self.eval_method(method, &mut signals);
        }

        self.eval_tls_fingerprint(req, &mut signals);

        signals
    }

    fn eval_user_agent(&self, ua: &str, signals: &mut SignalSet) {
        if AI_BOT_UA.is_match(ua) {
            signals.push(Signal::new(
                "ua_ai_bot",
                1.0,
                0.8,
                SignalSource::RuleEngine,
                "User-agent matches known AI bot pattern",
            ));
        } else if SCRAPING_UA.is_match(ua) {
            signals.push(Signal::new(
                "ua_scraper",
                1.0,
                0.7,
                SignalSource::RuleEngine,
                "User-agent matches scraping tool pattern",
            ));
        }

        if ua.is_empty() {
            signals.push(Signal::new(
                "ua_empty",
                1.0,
                0.4,
                SignalSource::RuleEngine,
                "Empty user-agent string",
            ));
        }

        // Check for raw version strings without browser context (e.g. "python-requests/2.x")
        if ua.contains('/') && !ua.to_lowercase().contains("mozilla") {
            signals.push(Signal::new(
                "ua_non_browser",
                0.7,
                0.3,
                SignalSource::RuleEngine,
                "Non-browser user-agent string",
            ));
        }
    }

    fn eval_path(&self, path: &str, signals: &mut SignalSet) {
        if SENSITIVE_PATH.is_match(path) {
            signals.push(Signal::new(
                "path_sensitive",
                1.0,
                0.6,
                SignalSource::RuleEngine,
                "Request targets a sensitive path",
            ));
        }

        // Bulk / enumeration pattern: many path segments or numeric IDs
        let segments = path.trim_matches('/').split('/').count();
        if segments > 8 {
            signals.push(Signal::new(
                "path_deep",
                0.6,
                0.2,
                SignalSource::RuleEngine,
                "Unusually deep path traversal",
            ));
        }
    }

    fn eval_headers(
        &self,
        headers: &std::collections::HashMap<String, String>,
        signals: &mut SignalSet,
    ) {
        let keys_lc: Vec<String> = headers.keys().map(|k| k.to_lowercase()).collect();

        if !keys_lc.contains(&"accept".to_string()) {
            signals.push(Signal::new(
                "header_missing_accept",
                0.6,
                0.2,
                SignalSource::RuleEngine,
                "Missing Accept header",
            ));
        }

        if !keys_lc.contains(&"accept-language".to_string()) {
            signals.push(Signal::new(
                "header_missing_accept_language",
                0.5,
                0.15,
                SignalSource::RuleEngine,
                "Missing Accept-Language header",
            ));
        }
    }

    fn eval_method(&self, method: &str, signals: &mut SignalSet) {
        match method.to_uppercase().as_str() {
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => {}
            _ => {
                signals.push(Signal::new(
                    "method_unusual",
                    0.7,
                    0.2,
                    SignalSource::RuleEngine,
                    "Unusual HTTP method",
                ));
            }
        }
    }

    fn eval_tls_fingerprint(&self, req: &ClassifyRequest, signals: &mut SignalSet) {
        if !req.tls_fingerprint_verified {
            return;
        }
        let known_bad = req
            .tls_ja3
            .as_ref()
            .is_some_and(|value| self.known_bad_ja3.contains(value))
            || req
                .tls_ja4
                .as_ref()
                .is_some_and(|value| self.known_bad_ja4.contains(value));
        if known_bad {
            signals.push(Signal::new(
                "tls_fingerprint_known_bad",
                1.0,
                0.85,
                SignalSource::RuleEngine,
                "Verified TLS fingerprint matches the configured threat set",
            ));
        }

        let ua = req
            .user_agent
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let claims_modern_browser = ua.contains("mozilla/5.0")
            && ["chrome/", "crios/", "firefox/", "fxios/", "safari/", "edg/"]
                .iter()
                .any(|marker| ua.contains(marker));
        let browser_profile_mismatch = claims_modern_browser
            && req
                .tls_ja4
                .as_deref()
                .is_some_and(|ja4| !matches!(ja4.get(..3), Some("t12" | "t13" | "q12" | "q13")));
        if browser_profile_mismatch {
            signals.push(Signal::new(
                "ua_tls_profile_mismatch",
                1.0,
                0.45,
                SignalSource::RuleEngine,
                "Browser user-agent conflicts with the verified JA4 transport profile",
            ));
        }
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(ua: Option<&str>, path: Option<&str>) -> ClassifyRequest {
        ClassifyRequest {
            ip: None,
            user_agent: ua.map(str::to_string),
            path: path.map(str::to_string),
            method: Some("GET".to_string()),
            headers: None,
            body_snippet: None,
            referer: None,
            accept: None,
            request_id: None,
            timestamp: None,
            tls_ja3: None,
            tls_ja4: None,
            tls_fingerprint_source: None,
            tls_fingerprint_attestation: None,
            tls_fingerprint_verified: false,
            extra: None,
        }
    }

    #[test]
    fn detects_gptbot() {
        let engine = RuleEngine::new();
        let req = make_req(Some("GPTBot/1.0"), None);
        let signals = engine.evaluate(&req);
        assert!(signals.as_slice().iter().any(|s| s.name == "ua_ai_bot"));
    }

    #[test]
    fn clean_request_has_no_high_signals() {
        let engine = RuleEngine::new();
        let req = make_req(
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            Some("/index.html"),
        );
        let signals = engine.evaluate(&req);
        let score = signals.aggregate_score();
        assert!(score < 0.5, "clean request score too high: {score}");
    }

    #[test]
    fn tls_rules_require_verified_provenance() {
        let config = crate::config::TlsFingerprintConfig {
            known_bad_ja3: vec!["72a589da586844d7f0818ce684948eea".into()],
            ..crate::config::TlsFingerprintConfig::default()
        };
        let engine = RuleEngine::with_tls_config(&config);
        let mut req = make_req(Some("Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36"), None);
        req.tls_ja3 = Some("72a589da586844d7f0818ce684948eea".into());
        req.tls_ja4 = Some("z99d1516h2_8daaf6152771_e5627efa2ab1".into());
        assert!(engine.evaluate(&req).as_slice().iter().all(|signal| {
            signal.name != "tls_fingerprint_known_bad" && signal.name != "ua_tls_profile_mismatch"
        }));
        req.tls_fingerprint_verified = true;
        let signals = engine.evaluate(&req);
        assert!(signals
            .as_slice()
            .iter()
            .any(|signal| signal.name == "tls_fingerprint_known_bad"));
        assert!(signals
            .as_slice()
            .iter()
            .any(|signal| signal.name == "ua_tls_profile_mismatch"));
    }
}
