use crate::models::{
    request::SelfTestRequest,
    response::{SelfTestResponse, SelfTestResult},
};
use crate::state::AppState;
use crate::util::time::elapsed_ms;
use std::time::Instant;

pub async fn run(state: &AppState, req: SelfTestRequest) -> SelfTestResponse {
    let _suite = req.suite.as_deref().unwrap_or("all");
    let mut results = Vec::new();

    // Test 1: classify a known bot UA
    {
        let start = Instant::now();
        let dummy = crate::models::request::ClassifyRequest {
            ip: None,
            user_agent: Some("GPTBot/1.0".to_string()),
            path: Some("/".to_string()),
            method: Some("GET".to_string()),
            headers: None,
            body_snippet: None,
            referer: None,
            accept: None,
            request_id: Some("self_test_1".to_string()),
            timestamp: None,
            extra: None,
        };
        let resp = crate::tools::classify::run(state, dummy).await;
        let passed = matches!(
            resp.verdict,
            crate::models::enums::Verdict::Block | crate::models::enums::Verdict::Flag
        );
        results.push(SelfTestResult {
            name: "classify_gptbot".to_string(),
            passed,
            message: if passed {
                None
            } else {
                Some(format!("expected block/flag, got {:?}", resp.verdict))
            },
            latency_ms: elapsed_ms(start),
        });
    }

    // Test 2: classify clean browser UA
    {
        let start = Instant::now();
        let dummy = crate::models::request::ClassifyRequest {
            ip: None,
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()),
            path: Some("/index.html".to_string()),
            method: Some("GET".to_string()),
            headers: Some([
                ("accept".to_string(), "text/html".to_string()),
                ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
            ].into_iter().collect()),
            body_snippet: None,
            referer: None,
            accept: None,
            request_id: Some("self_test_2".to_string()),
            timestamp: None,
            extra: None,
        };
        let resp = crate::tools::classify::run(state, dummy).await;
        let passed = resp.verdict == crate::models::enums::Verdict::Allow;
        results.push(SelfTestResult {
            name: "classify_clean_browser".to_string(),
            passed,
            message: if passed {
                None
            } else {
                Some(format!("expected allow, got {:?}", resp.verdict))
            },
            latency_ms: elapsed_ms(start),
        });
    }

    // Test 3: health check
    {
        let start = Instant::now();
        let health = crate::tools::health::run(state).await;
        let passed = health.status == "healthy";
        results.push(SelfTestResult {
            name: "health_check".to_string(),
            passed,
            message: if passed {
                None
            } else {
                Some(format!("unexpected status: {}", health.status))
            },
            latency_ms: elapsed_ms(start),
        });
    }

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    let overall_status = if failed == 0 { "pass" } else { "fail" }.to_string();

    SelfTestResponse {
        passed,
        failed,
        skipped: 0,
        results,
        overall_status,
    }
}
