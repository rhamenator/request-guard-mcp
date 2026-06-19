use crate::models::{request::ThreatLookupRequest, response::ThreatLookupResponse};
use crate::state::AppState;

pub async fn run(_state: &AppState, req: ThreatLookupRequest) -> ThreatLookupResponse {
    // In a production system this would query threat intelligence feeds.
    ThreatLookupResponse {
        indicator: req.indicator,
        found: false,
        threat_type: None,
        severity: None,
        source: None,
        last_seen: None,
    }
}
