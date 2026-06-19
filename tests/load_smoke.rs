/// Smoke load test – classifies 500 requests concurrently and checks all succeed.
use ai_scraping_defense_mcp::*;
use std::sync::Arc;
use tokio::task::JoinSet;

fn make_state() -> Arc<state::AppState> {
    Arc::new(state::AppState::new(config::Config::default()))
}

fn random_ua(i: usize) -> String {
    match i % 4 {
        0 => "GPTBot/1.0".to_string(),
        1 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        2 => "Scrapy/2.11".to_string(),
        _ => "curl/7.88".to_string(),
    }
}

#[tokio::test]
async fn concurrent_classify_500_requests() {
    let state = make_state();
    let mut set = JoinSet::new();

    for i in 0..500_usize {
        let s = Arc::clone(&state);
        set.spawn(async move {
            let req = models::request::ClassifyRequest {
                ip: Some(format!("10.0.{}.{}", (i / 256) % 256, i % 256)),
                user_agent: Some(random_ua(i)),
                path: Some(format!("/page/{i}")),
                method: Some("GET".to_string()),
                headers: None,
                body_snippet: None,
                referer: None,
                accept: None,
                request_id: Some(format!("load-{i}")),
                timestamp: None,
                extra: None,
            };
            tools::classify::run(&s, req).await
        });
    }

    let mut count = 0usize;
    while let Some(result) = set.join_next().await {
        let resp = result.expect("task panicked");
        assert!(resp.score >= 0.0 && resp.score <= 1.0);
        count += 1;
    }
    assert_eq!(count, 500);
}
