use crate::models::{
    request::AbusePatternMatchRequest,
    response::{AbusePatternMatchResponse, PatternMatch},
};
use crate::state::AppState;
use once_cell::sync::Lazy;
use regex::Regex;

struct AbusePattern {
    name: &'static str,
    category: &'static str,
    regex: Regex,
}

static PATTERNS: Lazy<Vec<AbusePattern>> = Lazy::new(|| {
    vec![
        AbusePattern {
            name: "sql_injection",
            category: "injection",
            regex: Regex::new(r"(?i)(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b)").unwrap(),
        },
        AbusePattern {
            name: "xss",
            category: "injection",
            regex: Regex::new(r"(?i)(<script[\s\S]*?>|javascript:|on\w+\s*=)").unwrap(),
        },
        AbusePattern {
            name: "path_traversal",
            category: "traversal",
            regex: Regex::new(r"(\.\./|\.\.\\|%2e%2e)").unwrap(),
        },
        AbusePattern {
            name: "ai_prompt_injection",
            category: "ai_attack",
            regex: Regex::new(r"(?i)(ignore previous instructions|you are now|forget your|disregard all|act as if you)").unwrap(),
        },
        AbusePattern {
            name: "sensitive_data_probe",
            category: "data_extraction",
            regex: Regex::new(r"(?i)(ssn|social security|credit card|cvv|api.?key|password|secret)").unwrap(),
        },
    ]
});

pub async fn run(_state: &AppState, req: AbusePatternMatchRequest) -> AbusePatternMatchResponse {
    let categories = req.categories.as_deref().unwrap_or(&[]);
    let mut matches = Vec::new();

    for p in PATTERNS.iter() {
        if !categories.is_empty() && !categories.contains(&p.category.to_string()) {
            continue;
        }
        if let Some(m) = p.regex.find(&req.text) {
            matches.push(PatternMatch {
                pattern: p.name.to_string(),
                category: p.category.to_string(),
                confidence: 0.9,
                matched_text: Some(m.as_str().chars().take(64).collect()),
            });
        }
    }

    let risk_score = if matches.is_empty() {
        0.0
    } else {
        (matches.len() as f64 * 0.3).clamp(0.0, 1.0)
    };

    AbusePatternMatchResponse {
        matched: !matches.is_empty(),
        patterns: matches,
        risk_score,
    }
}
