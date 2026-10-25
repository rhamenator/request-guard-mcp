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
    let lower_indicator = indicator.to_ascii_lowercase();
    let indicator_type = req
        .indicator_type
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| {
            if indicator.parse::<IpAddr>().is_ok() {
                "ip".to_string()
            } else if lower_indicator.starts_with("http://")
                || lower_indicator.starts_with("https://")
            {
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
        "ip" => {
            indicator.parse::<IpAddr>().map_err(|_| {
                AppError::InvalidRequest("indicator is not a valid IP address".to_string())
            })?;
            // Redis tries the canonical key first, then this exact seeded spelling.
            indicator.to_string()
        }
        "domain" => normalize_domain(indicator)?,
        "hash" => indicator.to_ascii_lowercase(),
        "asn" => indicator
            .strip_prefix("AS")
            .or_else(|| indicator.strip_prefix("as"))
            .unwrap_or(indicator)
            .parse::<u32>()
            .map_err(|_| AppError::InvalidRequest("indicator is not a valid ASN".to_string()))?
            .to_string(),
        "url" => normalize_url(indicator)?,
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

fn normalize_domain(indicator: &str) -> Result<String, AppError> {
    let domain = indicator.strip_suffix('.').unwrap_or(indicator);
    if domain.is_empty()
        || !domain.is_ascii()
        || domain.ends_with('.')
        || domain.split('.').any(str::is_empty)
        || domain
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err(AppError::InvalidRequest(
            "indicator is not a valid domain spelling".to_string(),
        ));
    }
    Ok(domain.to_ascii_lowercase())
}

fn normalize_url(indicator: &str) -> Result<String, AppError> {
    let authority_and_path = indicator
        .strip_prefix("http://")
        .or_else(|| indicator.strip_prefix("https://"));
    let valid = authority_and_path.is_some_and(|value| {
        !value.split(['/', '?', '#']).next().unwrap_or("").is_empty()
            && !indicator.bytes().any(|byte| byte.is_ascii_whitespace())
    });
    if !valid {
        return Err(AppError::InvalidRequest(
            "URL indicator must have a host and lowercase http:// or https:// scheme".to_string(),
        ));
    }
    Ok(indicator.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_misspelled_type_before_lookup() {
        let request = serde_json::from_value::<ThreatLookupRequest>(serde_json::json!({
            "indicator": "AS64500",
            "typ": "asn"
        }));
        assert!(request.is_err());
    }

    #[test]
    fn normalizes_one_dns_dot_and_rejects_ambiguous_indicators() {
        assert_eq!(normalize_domain("Evil.Example.").unwrap(), "evil.example");
        for domain in [
            "evil.example..",
            "a..b",
            ".",
            "evil.example:80",
            "é.example",
        ] {
            assert!(normalize_domain(domain).is_err(), "{domain}");
        }
        assert_eq!(
            normalize_url("https://evil.example/").unwrap(),
            "https://evil.example/"
        );
        assert!(normalize_url("HTTP://evil.example/").is_err());
        assert!(normalize_url("http://").is_err());
    }
}
