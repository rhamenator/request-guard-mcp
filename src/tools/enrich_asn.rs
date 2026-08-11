use crate::error::AppError;
use crate::models::{request::EnrichAsnRequest, response::EnrichAsnResponse};
use crate::state::AppState;

pub async fn run(state: &AppState, req: EnrichAsnRequest) -> Result<EnrichAsnResponse, AppError> {
    if req.asn == 0 {
        return Err(AppError::InvalidRequest(
            "asn must be greater than zero".to_string(),
        ));
    }
    if !state.geoip.has_asn_database() && !state.reputation.is_configured() {
        return Err(AppError::IntegrationUnavailable(
            "ASN enrichment requires a MaxMind ASN database or Redis reputation registry"
                .to_string(),
        ));
    }
    let enrichment = state.geoip.lookup_asn(req.asn);
    let is_hosting = enrichment.as_ref().is_some_and(|value| value.is_hosting);
    let reputation = state
        .reputation
        .lookup_asn(req.asn)
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    Ok(EnrichAsnResponse {
        asn: req.asn,
        organization: enrichment.and_then(|value| value.organization),
        country: None,
        risk_score: (if is_hosting { 0.6_f64 } else { 0.1_f64 }).max(reputation.score),
        is_hosting,
    })
}
