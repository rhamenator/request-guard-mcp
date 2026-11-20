use crate::models::{
    request::ClassifyRequest,
    signals::{Signal, SignalSet, SignalSource},
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static AI_BOT_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)(GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|",
        r"Claude-Web|anthropic-ai|Bytespider|CCBot|cohere-ai|cohere-training-data-crawler|",
        r"DuckAssistBot|FacebookBot|meta-externalagent|meta-externalfetcher|Google-Extended|",
        r"ImagesiftBot|PerplexityBot|Perplexity-User|Applebot-Extended|Amazonbot|Diffbot|",
        r"omgili(?:bot)?|Timpibot|YouBot|AI2Bot|Scrapy)"
    ))
    .expect("compile regex")
});

/// Ordinary programmatic HTTP clients. Scripts, monitors and developers use
/// them as much as scrapers do, so they are weak evidence, never an AI-bot claim.
static GENERIC_CLIENT_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)(python-httpx|python-requests|aiohttp|\bcurl/|\bwget/|libwww-perl|",
        r"Go-http-client|\bJava/|okhttp)"
    ))
    .expect("compile regex")
});

/// Named automation tools. The bare words "bot", "crawler" and "spider" are
/// deliberately absent: they also name Googlebot, Bingbot, UptimeRobot and
/// Slackbot. Real AI crawlers are matched by name in `AI_BOT_UA`.
static SCRAPING_UA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)(scrapy|beautifulsoup|mechanize|selenium|phantom|puppeteer|playwright|",
        r"headless|scraper|",
        r"\bmasscan\b|\bnikto\b|\bsqlmap\b|\bhttpclient\b)"
    ))
    .expect("compile regex")
});

/// The same automation patterns drive rule signals and the standalone
/// user-agent enrichment risk hint. A match is a heuristic, not an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserAgentPattern {
    AiBot,
    Scraper,
    GenericClient,
}

pub(crate) fn user_agent_pattern(ua: &str) -> Option<UserAgentPattern> {
    if AI_BOT_UA.is_match(ua) {
        Some(UserAgentPattern::AiBot)
    } else if SCRAPING_UA.is_match(ua) {
        Some(UserAgentPattern::Scraper)
    } else if GENERIC_CLIENT_UA.is_match(ua) {
        Some(UserAgentPattern::GenericClient)
    } else {
        None
    }
}

static SENSITIVE_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)(?:^|/)(?:[^/]*\.env(?:[-_~][a-z0-9_-]+|rc|s|[0-9]+)?|[^/]*\.git|",
        r"admin(?:istrator|istration|panel|s|[-_](?:panel|old|login|console|dashboard|area|ajax|api|users|cp|settings|portal|backup|dev|new|ui|v[0-9]+)|[0-9]+)?|",
        r"adminer|api/internal(?:[-_](?:v[0-9]+|tools|api))?|",
        r"wp-admin|phpmyadmin(?:[-_][a-z0-9.-]+|[0-9]+)?|",
        r"wp-config\.php(?:[._~-](?:bak|old|[0-9]+))?|\.aws|\.ssh|\.svn|\.htaccess|",
        r"server-status|phpinfo\.php|backup\.sql(?:[._~-](?:bak|old|[0-9]+))?|\.git-credentials|",
        r"etc/passwd(?:-[a-z0-9]+)?|debug(?:ger|_toolbar|_info|-info|-bar|-toolbar)?|actuator|",
        r"swagger(?:-ui(?:-bundle|-dist)?|-resources|_ui|ui|-config|-docs)?|graphql(?:-playground|v?[0-9]+)?|",
        r"config(?:uration|ure|s|[-_](?:backup|bak|dev|old|prod|local|staging|test|new))?)(?:[/;~\x00\s?#.]|$)|",
        r"(?:^|/)proc(?:/|$)|(?:^|/)(?:internal|xmlrpc\.php)(?:[/;~\x00\s?#]|$)"
    ))
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

        if req.robots_violation {
            signals.push(Signal::new(
                "robots_violation",
                1.0,
                0.9,
                SignalSource::RuleEngine,
                "Caller reports the client requested a path disallowed by robots.txt",
            ));
        }

        signals
    }

    fn eval_user_agent(&self, ua: &str, signals: &mut SignalSet) {
        let pattern = user_agent_pattern(ua);
        if pattern == Some(UserAgentPattern::AiBot) {
            signals.push(Signal::new(
                "ua_ai_bot",
                1.0,
                0.8,
                SignalSource::RuleEngine,
                "User-agent matches known AI bot pattern",
            ));
        } else if pattern == Some(UserAgentPattern::Scraper) {
            signals.push(Signal::new(
                "ua_scraper",
                1.0,
                0.7,
                SignalSource::RuleEngine,
                "User-agent matches scraping tool pattern",
            ));
        } else if pattern == Some(UserAgentPattern::GenericClient) {
            signals.push(Signal::new(
                "ua_generic_client",
                0.5,
                0.25,
                SignalSource::RuleEngine,
                "User-agent is a generic programmatic HTTP client (weak evidence)",
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
        // Query and fragment text are not URL path segments. Decode the path
        // portion only, so an indicator in a search parameter does not become
        // a false path-sensitive verdict.
        let path_only = path.split(['?', '#']).next().unwrap_or(path);
        let normalized = normalize_path_for_signals(path_only);
        // Encoded delimiters are path bytes to some origins; retain segments
        // after them rather than hiding a sensitive route during decoding.
        let route = normalized.as_str();
        if SENSITIVE_PATH.is_match(route) {
            signals.push(Signal::new(
                "path_sensitive",
                1.0,
                0.6,
                SignalSource::RuleEngine,
                "Request targets a sensitive path",
            ));
        }

        // Bulk / enumeration pattern: many path segments or numeric IDs
        let segments = route.trim_matches('/').split('/').count();
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

// Inspect common encoded spellings as well as the raw path. Four bounded rounds
// catch repeated percent-encoding without relying on any origin's URL router.
// The original request is never rewritten or used for enforcement by this tool.
fn normalize_path_for_signals(path: &str) -> String {
    let mut bytes = path.as_bytes().to_vec();
    for _ in 0..4 {
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                if let (Some(high), Some(low)) =
                    (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
                {
                    let byte = (high << 4) | low;
                    decoded.push(if byte == b'\\' { b'/' } else { byte });
                    index += 3;
                    continue;
                }
            }
            decoded.push(if bytes[index] == b'\\' {
                b'/'
            } else {
                bytes[index]
            });
            index += 1;
        }
        bytes = decoded;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
            robots_violation: false,
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
    fn every_ai_bot_pattern_is_active() {
        for sample in [
            "GPTBot",
            "ChatGPT-User",
            "ClaudeBot",
            "Claude-User",
            "OAI-SearchBot",
            "Amazonbot",
            "Applebot-Extended",
            "meta-externalagent",
            "Claude-Web",
            "anthropic-ai",
            "Bytespider",
            "CCBot",
            "cohere-ai",
            "DuckAssistBot",
            "FacebookBot",
            "Google-Extended",
            "ImagesiftBot",
            "PerplexityBot",
            "Scrapy",
        ] {
            assert!(AI_BOT_UA.is_match(sample), "AI bot pattern missed {sample}");
        }
    }

    #[test]
    fn generic_http_clients_are_weak_evidence_not_ai_bots() {
        for sample in [
            "python-httpx/0.27",
            "python-requests/2.31.0",
            "aiohttp/3.9",
            "curl/8.5.0",
            "Wget/1.21.4",
            "libwww-perl/6.72",
            "Go-http-client/1.1",
            "Java/17.0.2",
            "okhttp/4.12.0",
        ] {
            assert!(
                !AI_BOT_UA.is_match(sample),
                "{sample} must not be an AI bot"
            );
            assert_eq!(
                user_agent_pattern(sample),
                Some(UserAgentPattern::GenericClient),
                "{sample}"
            );
            let signals = RuleEngine::new().evaluate(&make_req(Some(sample), None));
            assert!(signals
                .as_slice()
                .iter()
                .any(|s| s.name == "ua_generic_client"));
            assert!(!signals.as_slice().iter().any(|s| s.name == "ua_ai_bot"));
            let verdict = crate::engines::scorer::Scorer::new()
                .score(&signals)
                .verdict;
            assert_ne!(verdict, crate::models::enums::Verdict::Block, "{sample}");
        }
    }

    #[test]
    fn well_known_benign_crawlers_are_not_scrapers() {
        for sample in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        ] {
            assert_eq!(user_agent_pattern(sample), None, "{sample}");
            let signals = RuleEngine::new().evaluate(&make_req(Some(sample), Some("/")));
            let verdict = crate::engines::scorer::Scorer::new()
                .score(&signals)
                .verdict;
            assert_ne!(verdict, crate::models::enums::Verdict::Block, "{sample}");
        }
    }

    #[test]
    fn robots_violation_is_a_strong_standalone_signal() {
        let mut req = make_req(
            Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0"),
            Some("/"),
        );
        let quiet = crate::engines::scorer::Scorer::new().score(&RuleEngine::new().evaluate(&req));
        req.robots_violation = true;
        let signals = RuleEngine::new().evaluate(&req);
        assert!(signals
            .as_slice()
            .iter()
            .any(|s| s.name == "robots_violation"));
        let flagged = crate::engines::scorer::Scorer::new().score(&signals);
        assert_eq!(flagged.verdict, crate::models::enums::Verdict::Block);
        assert!(flagged.score > quiet.score);
        assert_eq!(quiet.verdict, crate::models::enums::Verdict::Allow);
    }

    #[test]
    fn absent_robots_violation_changes_nothing() {
        let a = make_req(Some("curl/8.5.0"), Some("/admin"));
        let mut b = a.clone();
        b.robots_violation = false;
        let sa = RuleEngine::new().evaluate(&a);
        let sb = RuleEngine::new().evaluate(&b);
        assert_eq!(sa.aggregate_score(), sb.aggregate_score());
        assert!(!sa.as_slice().iter().any(|s| s.name == "robots_violation"));
    }

    #[test]
    fn every_scraper_pattern_is_active() {
        for sample in [
            "scrapy",
            "beautifulsoup",
            "mechanize",
            "selenium",
            "phantom",
            "puppeteer",
            "playwright",
            "headless",
            "scraper",
            "masscan",
            "nikto",
            "sqlmap",
            "httpclient",
        ] {
            assert!(
                SCRAPING_UA.is_match(sample),
                "scraper pattern missed {sample}"
            );
        }
        let signals = RuleEngine::new().evaluate(&make_req(Some("HeadlessChrome/120"), None));
        assert!(signals
            .as_slice()
            .iter()
            .any(|signal| signal.name == "ua_scraper"));
        assert!(!SCRAPING_UA.is_match("masscanary browser"));
    }

    #[test]
    fn every_sensitive_path_pattern_is_active() {
        for sample in [
            "/.env",
            "/admin",
            "/api/internal",
            "/wp-admin",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php_bak",
            "/wp-config.php-old",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/.svn/entries",
            "/.htaccess",
            "/server-status",
            "/phpinfo.php",
            "/backup.sql",
            "/backup.sql_old",
            "/.git-credentials",
            "/phpmyadmin",
            "/.git/config",
            "/etc/passwd",
            "/proc/self/environ",
            "/debug",
            "/actuator",
            "/swagger",
            "/graphql",
            "/config",
            "/internal",
            "/internal/metrics",
            "/xmlrpc.php",
        ] {
            assert!(
                SENSITIVE_PATH.is_match(sample),
                "sensitive path missed {sample}"
            );
        }
        let signals = RuleEngine::new().evaluate(&make_req(None, Some("/etc/passwd")));
        assert!(signals
            .as_slice()
            .iter()
            .any(|signal| signal.name == "path_sensitive"));
        assert!(!SENSITIVE_PATH.is_match("/internalized"));
        assert!(!SENSITIVE_PATH.is_match("/xmlrpc.phpish"));
        for ordinary in [
            "/products/configurable-shirt",
            "/docs/administrator-guide",
            "/docs/admin-guide",
            "/blog/node.environment-setup",
            "/api/internalized",
            "/xmlrpc.phpish",
            "/internal.example.com",
            "/proc.html",
            "/wp-config.phpish",
            "/backup.sqlish",
            "/docs/server-status-guide",
            "/wp-login.php",
            "/cgi-bin/status",
        ] {
            assert!(
                !SENSITIVE_PATH.is_match(ordinary),
                "false positive {ordinary}"
            );
        }
    }

    #[test]
    fn encoded_sensitive_paths_remain_visible_to_rules() {
        for path in [
            "/%2eenv",
            "/%252eenv",
            "/%25252eenv",
            "/%2525252eenv",
            "/%61dmin",
            "/%2fadmin",
            "\\admin",
            "/%255cadmin",
            "/config.json",
            "/.env.production",
            "/.env-backup",
            "/.env_prod",
            "/.env_local",
            "/.env-sample",
            "/.envrc",
            "/administrator",
            "/admin-panel",
            "/admin_old",
            "/admin123",
            "/adminer.php",
            "/admin-login",
            "/admin_console",
            "/admin-dashboard",
            "/admin_area",
            "/admin-ajax.php",
            "/admin-api",
            "/admin-users",
            "/adminpanel",
            "/admin-settings",
            "/admin-portal",
            "/admin_backup",
            "/api/internal-api",
            "/.envs/",
            "/administration",
            "/admin;jsessionid=1",
            "/admin%00.png",
            "/admin%3fx",
            "/%3f/admin",
            "/x%23/admin",
            "/etc/passwd%00.jpg",
            "/phpMyAdmin-4.9.1",
            "/phpmyadmin2",
            "/prod.env",
            "/repo.git/config",
            "/configuration.php",
            "/config-prod",
            "/config_local",
            "/config-staging",
            "/config-bak",
            "/configs",
            "/debug_toolbar",
            "/debug-info",
            "/graphql-playground",
            "/graphqlv1",
            "/swagger-ui-dist/",
            "/swagger-docs",
            "/debug-toolbar",
            "/api/internal-v2",
            "/.env~1",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/swagger-resources",
        ] {
            let signals = RuleEngine::new().evaluate(&make_req(Some("Mozilla/5.0"), Some(path)));
            assert!(
                signals
                    .as_slice()
                    .iter()
                    .any(|signal| signal.name == "path_sensitive"),
                "missed {path}"
            );
        }
        let ordinary = RuleEngine::new().evaluate(&make_req(Some("Mozilla/5.0"), Some("/welcome")));
        assert!(!ordinary
            .as_slice()
            .iter()
            .any(|signal| signal.name == "path_sensitive"));
        for path in [
            "/products/configurable-shirt",
            "/docs/administrator-guide",
            "/docs/admin-guide",
            "/blog/node.environment-setup",
            "/search?q=/admin",
            "/search?q=/%61dmin",
            "/search#fragment=/admin",
        ] {
            let signals = RuleEngine::new().evaluate(&make_req(Some("Mozilla/5.0"), Some(path)));
            assert!(
                !signals
                    .as_slice()
                    .iter()
                    .any(|signal| signal.name == "path_sensitive"),
                "false positive {path}"
            );
        }
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
