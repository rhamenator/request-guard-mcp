/// Contract tests for the batch_classify tool.
use ai_scraping_defense_mcp::*;

fn make_state() -> state::AppState {
    state::AppState::new(config::Config::default())
}

fn make_req(ua: &str) -> models::request::ClassifyRequest {
    models::request::ClassifyRequest {
        ip: None,
        user_agent: Some(ua.to_string()),
        path: Some("/".to_string()),
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

#[tokio::test]
async fn batch_returns_correct_count() {
    let state = make_state();
    let req = models::request::BatchClassifyRequest {
        items: vec![
            make_req("GPTBot/1.0"),
            make_req("Mozilla/5.0"),
            make_req("Scrapy/2.0"),
        ],
        options: None,
    };
    let resp = tools::batch_classify::run(&state, req).await.unwrap();
    assert_eq!(resp.total, 3);
    assert_eq!(resp.results.len(), 3);
    assert_eq!(resp.errors, 0);
}

#[tokio::test]
async fn batch_enforces_size_limit() {
    let mut cfg = config::Config::default();
    cfg.limits.max_batch_size = 2;
    let state = state::AppState::new(cfg);

    let req = models::request::BatchClassifyRequest {
        items: vec![make_req("a"), make_req("b"), make_req("c")],
        options: None,
    };
    let result = tools::batch_classify::run(&state, req).await;
    assert!(matches!(
        result,
        Err(error::AppError::BatchTooLarge { max: 2, got: 3 })
    ));
}

#[tokio::test]
async fn empty_batch_succeeds() {
    let state = make_state();
    let req = models::request::BatchClassifyRequest {
        items: vec![],
        options: None,
    };
    let resp = tools::batch_classify::run(&state, req).await.unwrap();
    assert_eq!(resp.total, 0);
    assert_eq!(resp.processed, 0);
}

#[tokio::test]
async fn batch_result_indices_are_ordered() {
    let state = make_state();
    let items: Vec<_> = (0..5).map(|_| make_req("Mozilla/5.0")).collect();
    let req = models::request::BatchClassifyRequest {
        items,
        options: None,
    };
    let resp = tools::batch_classify::run(&state, req).await.unwrap();
    for (i, item) in resp.results.iter().enumerate() {
        assert_eq!(item.index, i);
    }
}
