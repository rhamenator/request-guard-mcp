use crate::models::{request::EnrichAsnRequest, response::EnrichAsnResponse};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: EnrichAsnRequest) -> EnrichAsnResponse {
    EnrichAsnResponse {
        asn: req.asn,
        organization: None,
        country: None,
        risk_score: 0.0,
        is_hosting: false,
    }
}
