use crate::error::AppError;
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
            regex: Regex::new(r"(?is)(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b)").unwrap(),
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

const CATEGORIES: [&str; 4] = ["injection", "traversal", "ai_attack", "data_extraction"];

pub async fn run(
    _state: &AppState,
    req: AbusePatternMatchRequest,
) -> Result<AbusePatternMatchResponse, AppError> {
    match_patterns(req)
}

fn match_patterns(req: AbusePatternMatchRequest) -> Result<AbusePatternMatchResponse, AppError> {
    let categories: Vec<String> = req
        .categories
        .unwrap_or_default()
        .into_iter()
        .map(|category| category.trim().to_ascii_lowercase())
        .collect();
    if categories
        .iter()
        .any(|category| !CATEGORIES.contains(&category.as_str()))
    {
        return Err(AppError::InvalidRequest(
            "categories must be injection, traversal, ai_attack, or data_extraction".to_string(),
        ));
    }
    let mut matches = Vec::new();

    for p in PATTERNS.iter() {
        if !categories.is_empty() && !categories.iter().any(|category| category == p.category) {
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

    Ok(AbusePatternMatchResponse {
        matched: !matches.is_empty(),
        patterns: matches,
        risk_score,
    })
}

#[cfg(test)]
mod tests {
    use super::{match_patterns, CATEGORIES, PATTERNS};
    use crate::models::request::AbusePatternMatchRequest;

    fn request(text: &str, categories: &[&str]) -> AbusePatternMatchRequest {
        AbusePatternMatchRequest {
            text: text.to_string(),
            categories: Some(categories.iter().map(|value| value.to_string()).collect()),
        }
    }

    #[test]
    fn category_variants_do_not_produce_a_false_clean_result() {
        let result = match_patterns(request("SELECT a FROM t", &[" Injection "])).unwrap();
        assert!(result.matched);
        assert_eq!(result.patterns[0].pattern, "sql_injection");
        assert!(match_patterns(request("SELECT a FROM t", &["injecton"])).is_err());
        assert!(match_patterns(request("SELECT a FROM t", &["injection", "wrong"])).is_err());
    }

    #[test]
    fn multiline_sql_is_detected() {
        let result = match_patterns(request("SELECT a\nFROM t", &["injection"])).unwrap();
        assert!(result.matched);
        assert_eq!(result.patterns[0].pattern, "sql_injection");
    }

    #[test]
    fn every_pattern_category_is_selectable() {
        assert!(PATTERNS
            .iter()
            .all(|pattern| CATEGORIES.contains(&pattern.category)));
    }
}
