use crate::models::{
    response::{ExplainResponse, ExplanationFactor},
    signals::SignalSet,
};

/// Generate a human-readable explanation for a classification result.
pub fn explain_signals(
    request_id: &str,
    signals: &SignalSet,
    score: f64,
    verdict: &str,
) -> ExplainResponse {
    let total_weight: f64 = signals.as_slice().iter().map(|s| s.weight).sum();

    let factors: Vec<ExplanationFactor> = signals
        .as_slice()
        .iter()
        .map(|s| {
            let pct = if total_weight > 0.0 {
                (s.contribution() / total_weight) * 100.0
            } else {
                0.0
            };
            ExplanationFactor {
                name: s.name.clone(),
                contribution: pct,
                description: s.description.clone(),
            }
        })
        .collect();

    let explanation = build_explanation(score, verdict, &factors);
    let recommendations = build_recommendations(score, verdict, signals);

    ExplainResponse {
        request_id: request_id.to_string(),
        explanation,
        factors,
        recommendations,
    }
}

fn build_explanation(score: f64, verdict: &str, factors: &[ExplanationFactor]) -> String {
    let pct = (score * 100.0).round();
    if factors.is_empty() {
        return format!("No suspicious signals detected. Score: {pct:.0}%. Verdict: {verdict}.");
    }
    let top: Vec<String> = factors
        .iter()
        .take(3)
        .map(|f| format!("{} ({:.0}%)", f.name, f.contribution))
        .collect();
    format!(
        "Score {pct:.0}% → verdict '{verdict}'. Top contributing signals: {}.",
        top.join(", ")
    )
}

fn build_recommendations(score: f64, verdict: &str, signals: &SignalSet) -> Vec<String> {
    let mut recs = Vec::new();
    if score >= 0.75 {
        recs.push("Consider blocking this request at the WAF or load balancer level.".to_string());
        recs.push("Review and update blocklists for matching patterns.".to_string());
    } else if score >= 0.40 {
        recs.push("Consider serving a CAPTCHA challenge.".to_string());
        recs.push("Monitor for repeated requests from this source.".to_string());
    }
    if signals.as_slice().iter().any(|s| s.name == "ua_ai_bot") {
        recs.push("Add robots.txt disallow rules for identified AI bots.".to_string());
    }
    if verdict == "allow" && recs.is_empty() {
        recs.push("No action required. Request appears legitimate.".to_string());
    }
    recs
}
