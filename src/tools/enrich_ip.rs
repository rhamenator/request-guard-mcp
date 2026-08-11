use crate::error::AppError;
use crate::models::{request::EnrichIpRequest, response::EnrichIpResponse};
use crate::state::AppState;
use crate::util::net::parse_ip;

pub async fn run(state: &AppState, req: EnrichIpRequest) -> Result<EnrichIpResponse, AppError> {
    let parsed = parse_ip(&req.ip)
        .ok_or_else(|| AppError::InvalidRequest("ip is not a valid IP address".to_string()))?;
    let is_private = crate::util::net::is_private(&parsed);
    if !is_private && !state.geoip.has_ip_database() && !state.reputation.is_configured() {
        return Err(AppError::IntegrationUnavailable(
            "IP enrichment requires a MaxMind database or Redis reputation registry".to_string(),
        ));
    }
    let enrichment = if state.geoip.has_ip_database() {
        state
            .geoip
            .lookup_ip(&parsed)
            .map_err(|error| AppError::Upstream(error.to_string()))?
    } else {
        Default::default()
    };
    let reputation = state
        .reputation
        .lookup_ip(&parsed.to_string())
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    let geoip_risk: f64 = if is_private {
        0.0
    } else if enrichment.is_tor || enrichment.is_proxy {
        0.9
    } else if enrichment.is_datacenter {
        0.6
    } else {
        0.1
    };
    let risk_score = geoip_risk.max(reputation.score);
    Ok(EnrichIpResponse {
        ip: parsed.to_string(),
        country: enrichment.country,
        city: enrichment.city,
        asn: enrichment.asn,
        org: enrichment.org,
        is_proxy: enrichment.is_proxy,
        is_datacenter: enrichment.is_datacenter,
        is_tor: enrichment.is_tor,
        risk_score,
    })
}
