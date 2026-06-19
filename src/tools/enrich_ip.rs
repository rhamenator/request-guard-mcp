use crate::models::{request::EnrichIpRequest, response::EnrichIpResponse};
use crate::state::AppState;
use crate::util::net::parse_ip;

pub async fn run(_state: &AppState, req: EnrichIpRequest) -> EnrichIpResponse {
    let parsed = parse_ip(&req.ip);
    let is_private = parsed
        .map(|ip| crate::util::net::is_private(&ip))
        .unwrap_or(false);

    EnrichIpResponse {
        ip: req.ip,
        country: None,
        city: None,
        asn: None,
        org: None,
        is_proxy: false,
        is_datacenter: false,
        is_tor: false,
        risk_score: if is_private { 0.0 } else { 0.1 },
    }
}
