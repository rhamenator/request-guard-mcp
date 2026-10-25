use crate::engines::rules::{user_agent_pattern, UserAgentPattern};
use crate::models::{request::EnrichUaRequest, response::EnrichUaResponse};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: EnrichUaRequest) -> EnrichUaResponse {
    enrich(req)
}

fn enrich(req: EnrichUaRequest) -> EnrichUaResponse {
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

    // Keep the parser's crawler classification separate from the rule engine's
    // broader automation hints. A scanner need not be a crawler, but should not
    // receive the same low diagnostic score as a recognized browser.
    let pattern_score = match user_agent_pattern(ua) {
        Some(UserAgentPattern::AiBot) => 0.8_f64,
        Some(UserAgentPattern::Scraper) => 0.7_f64,
        None => 0.1_f64,
    };
    let risk_score = if is_bot {
        pattern_score.max(0.8)
    } else {
        pattern_score
    };

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

#[cfg(test)]
mod tests {
    use super::enrich;
    use crate::models::request::EnrichUaRequest;

    #[test]
    fn known_scanners_are_not_low_risk() {
        for ua in ["sqlmap/1.7", "Nikto/2.1.6", "masscan/1.3"] {
            let result = enrich(EnrichUaRequest {
                user_agent: ua.into(),
            });
            assert!(result.risk_score >= 0.7, "{ua}");
        }
    }

    #[test]
    fn normal_browser_remains_low_diagnostic_risk() {
        let result = enrich(EnrichUaRequest { user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into() });
        assert_eq!(result.risk_score, 0.1);
        assert!(!result.is_bot);
    }
}
