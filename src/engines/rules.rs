use crate::models::{
    request::ClassifyRequest,
    signals::{Signal, SignalSet, SignalSource},
};
use once_cell::sync::Lazy;
use regex::Regex;

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
pub struct RuleEngine;

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine
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
}
