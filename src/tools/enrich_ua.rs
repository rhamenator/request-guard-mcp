use crate::models::{request::EnrichUaRequest, response::EnrichUaResponse};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: EnrichUaRequest) -> EnrichUaResponse {
    let ua = &req.user_agent;
    let parsed = woothee::parser::Parser::new().parse(ua);

    let (browser, os, device_type, is_bot, bot_name) = if let Some(r) = parsed {
        let is_bot = r.category == "crawler";
        let bot_name = if is_bot {
            Some(r.name.to_string())
        } else {
            None
        };
        (
            Some(r.name.to_string()),
            Some(r.os.to_string()),
            Some(r.category.to_string()),
            is_bot,
            bot_name,
        )
    } else {
        (None, None, None, false, None)
    };

    let risk_score = if is_bot { 0.8 } else { 0.1 };

    EnrichUaResponse {
        user_agent: req.user_agent,
        browser,
        os,
        device_type,
        is_bot,
        bot_name,
        risk_score,
    }
}
