use crate::error::AppError;
use crate::models::{request::ThreatLookupRequest, response::ThreatLookupResponse};
use crate::state::AppState;
use std::net::IpAddr;

pub async fn run(
    state: &AppState,
    req: ThreatLookupRequest,
) -> Result<ThreatLookupResponse, AppError> {
    if !state.redis.is_available() {
        return Err(AppError::IntegrationUnavailable(
            "threat lookup requires Redis".to_string(),
        ));
    }
    let indicator = req.indicator.trim();
    if indicator.is_empty() {
        return Err(AppError::InvalidRequest(
            "indicator cannot be empty".to_string(),
        ));
    }
    let indicator_type = req
        .indicator_type
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| {
            if indicator.parse::<IpAddr>().is_ok() {
                "ip".to_string()
            } else if indicator.starts_with("http://") || indicator.starts_with("https://") {
                "url".to_string()
            } else {
                "domain".to_string()
            }
        });
    if !matches!(
        indicator_type.as_str(),
        "ip" | "domain" | "url" | "hash" | "asn"
    ) {
        return Err(AppError::InvalidRequest(
            "type must be ip, domain, url, hash, or asn".to_string(),
        ));
    }
    let normalized = match indicator_type.as_str() {
        "ip" => indicator
            .parse::<IpAddr>()
            .map_err(|_| {
                AppError::InvalidRequest("indicator is not a valid IP address".to_string())
            })?
            .to_string(),
        "domain" | "hash" => indicator.to_ascii_lowercase(),
        "asn" => indicator
            .strip_prefix("AS")
            .or_else(|| indicator.strip_prefix("as"))
            .unwrap_or(indicator)
            .parse::<u32>()
            .map_err(|_| AppError::InvalidRequest("indicator is not a valid ASN".to_string()))?
            .to_string(),
        "url" => indicator.to_string(),
        _ => unreachable!("indicator type was validated"),
    };
    let record = state
        .redis
        .threat_lookup(&indicator_type, &normalized)
        .await
        .map_err(|error| AppError::Upstream(error.to_string()))?;
    Ok(ThreatLookupResponse {
        indicator: req.indicator,
        found: record.is_some(),
        threat_type: record.as_ref().map(|value| value.threat_type.clone()),
        severity: record.as_ref().map(|value| value.severity.clone()),
        source: record.as_ref().map(|value| value.source.clone()),
        last_seen: record.and_then(|value| value.last_seen),
    })
}
