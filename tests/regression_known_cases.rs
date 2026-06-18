/// Regression tests against known attack/benign patterns.
use ai_scraping_defense_mcp::*;

fn make_state() -> state::AppState {
    state::AppState::new(config::Config::default())
}

struct Case {
    name: &'static str,
    ua: Option<&'static str>,
    path: Option<&'static str>,
    method: Option<&'static str>,
    expected_verdict: models::enums::Verdict,
}

fn make_req(c: &Case) -> models::request::ClassifyRequest {
    models::request::ClassifyRequest {
        ip: None,
        user_agent: c.ua.map(str::to_string),
        path: c.path.map(str::to_string),
        method: c.method.map(str::to_string),
        headers: None,
        body_snippet: None,
        referer: None,
        accept: None,
        request_id: Some(c.name.to_string()),
        timestamp: None,
        extra: None,
    }
}

#[tokio::test]
async fn known_cases_match_expected_verdicts() {
    let state = make_state();

    let cases = vec![
        Case {
            name: "gptbot",
            ua: Some("GPTBot/1.0"),
            path: Some("/"),
            method: Some("GET"),
            expected_verdict: models::enums::Verdict::Block,
        },
        Case {
            name: "anthropic",
            ua: Some("anthropic-ai/1.0"),
            path: Some("/"),
            method: Some("GET"),
            expected_verdict: models::enums::Verdict::Block,
        },
        Case {
            name: "scrapy",
            ua: Some("Scrapy/2.11"),
            path: Some("/"),
            method: Some("GET"),
            expected_verdict: models::enums::Verdict::Block,
        },
    ];

    for case in &cases {
        let req = make_req(case);
        let resp = tools::classify::run(&state, req).await;
        assert_eq!(
            resp.verdict, case.expected_verdict,
            "case '{}': expected {:?}, got {:?} (score={})",
            case.name, case.expected_verdict, resp.verdict, resp.score
        );
    }
}

#[tokio::test]
async fn clean_browser_always_allowed() {
    use std::collections::HashMap;
    let state = make_state();
    let mut headers = HashMap::new();
    headers.insert("accept".to_string(), "text/html".to_string());
    headers.insert("accept-language".to_string(), "en-US".to_string());

    let req = models::request::ClassifyRequest {
        ip: Some("203.0.113.5".to_string()),
        user_agent: Some(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
                .to_string(),
        ),
        path: Some("/blog/post-1".to_string()),
        method: Some("GET".to_string()),
        headers: Some(headers),
        body_snippet: None,
        referer: Some("https://www.google.com".to_string()),
        accept: None,
        request_id: Some("regression-clean-browser".to_string()),
        timestamp: None,
        extra: None,
    };
    let resp = tools::classify::run(&state, req).await;
    assert_eq!(
        resp.verdict,
        models::enums::Verdict::Allow,
        "expected allow for clean Safari browser, got {:?} (score={})",
        resp.verdict,
        resp.score
    );
}
