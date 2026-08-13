use crate::config::TlsFingerprintConfig;
use crate::models::request::ClassifyRequest;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const ATTESTATION_VERSION: &str = "v1";

pub fn normalize_ja3(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    (candidate.len() == 32 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(candidate)
}

pub fn normalize_ja4(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    let sections = candidate.split('_').collect::<Vec<_>>();
    let valid = sections.len() == 3
        && sections[0].len() == 10
        && sections[0]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && sections[1].len() == 12
        && sections[2].len() == 12
        && sections[1]
            .bytes()
            .chain(sections[2].bytes())
            .all(|byte| byte.is_ascii_hexdigit());
    valid.then_some(candidate)
}

pub fn normalize_source(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    (!candidate.is_empty()
        && candidate.len() <= 32
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(candidate)
}

fn canonical_message(
    issued_at: i64,
    client_ip: &str,
    method: &str,
    path: &str,
    ja3: Option<&str>,
    ja4: Option<&str>,
    source: &str,
) -> Option<Vec<u8>> {
    let timestamp = issued_at.to_string();
    let client_ip = client_ip.trim().to_ascii_lowercase();
    let method = method.trim().to_ascii_uppercase();
    let fields = [
        ATTESTATION_VERSION,
        timestamp.as_str(),
        client_ip.as_str(),
        method.as_str(),
        path,
        ja3.unwrap_or(""),
        ja4.unwrap_or(""),
        source,
    ];
    if fields
        .iter()
        .any(|value| value.contains(['\n', '\r', '\0']))
    {
        return None;
    }
    Some(fields.join("\n").into_bytes())
}

pub fn create_attestation(
    key: &[u8],
    issued_at: i64,
    client_ip: &str,
    method: &str,
    path: &str,
    ja3: Option<&str>,
    ja4: Option<&str>,
    source: &str,
) -> Option<String> {
    if key.len() < 32 {
        return None;
    }
    let ja3 = normalize_ja3(ja3);
    let ja4 = normalize_ja4(ja4);
    let source = normalize_source(Some(source))?;
    if ja3.is_none() && ja4.is_none() {
        return None;
    }
    let canonical = canonical_message(
        issued_at,
        client_ip,
        method,
        path,
        ja3.as_deref(),
        ja4.as_deref(),
        &source,
    )?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(&canonical);
    Some(format!(
        "{ATTESTATION_VERSION}:{issued_at}:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

pub fn verify_request(request: &ClassifyRequest, config: &TlsFingerprintConfig, now: i64) -> bool {
    if config.attestation_key.is_none() && config.previous_attestation_key.is_none() {
        return false;
    }
    let Some(token) = request.tls_fingerprint_attestation.as_deref() else {
        return false;
    };
    let mut token_parts = token.trim().split(':');
    if token_parts.next() != Some(ATTESTATION_VERSION) {
        return false;
    }
    let Some(issued_at) = token_parts
        .next()
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return false;
    };
    let Some(signature) = token_parts.next() else {
        return false;
    };
    if token_parts.next().is_some()
        || signature.len() != 64
        || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        || now.abs_diff(issued_at) > config.max_age_seconds
    {
        return false;
    }
    let Ok(provided) = hex::decode(signature) else {
        return false;
    };
    let mut verified = false;
    for key in [
        config.attestation_key.as_deref(),
        config.previous_attestation_key.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some(expected) = create_attestation(
            key.as_bytes(),
            issued_at,
            request.ip.as_deref().unwrap_or(""),
            request.method.as_deref().unwrap_or("GET"),
            request.path.as_deref().unwrap_or(""),
            request.tls_ja3.as_deref(),
            request.tls_ja4.as_deref(),
            request.tls_fingerprint_source.as_deref().unwrap_or(""),
        ) else {
            continue;
        };
        let expected_signature = expected.rsplit(':').next().unwrap_or_default();
        let Ok(expected) = hex::decode(expected_signature) else {
            continue;
        };
        let matches = provided.len() == expected.len()
            && provided
                .iter()
                .zip(expected.iter())
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0;
        verified |= matches;
    }
    verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn request(token: Option<String>) -> ClassifyRequest {
        ClassifyRequest {
            ip: Some("198.51.100.7".into()),
            user_agent: None,
            path: Some("/products".into()),
            method: Some("GET".into()),
            headers: Some(HashMap::new()),
            body_snippet: None,
            referer: None,
            accept: None,
            request_id: None,
            timestamp: None,
            tls_ja3: Some("72a589da586844d7f0818ce684948eea".into()),
            tls_ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            tls_fingerprint_source: Some("envoy".into()),
            tls_fingerprint_attestation: token,
            tls_fingerprint_verified: false,
            extra: None,
        }
    }

    #[test]
    fn verifies_context_binding_and_freshness() {
        let key = "0123456789abcdef0123456789abcdef";
        let token = create_attestation(
            key.as_bytes(),
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/products",
            Some("72a589da586844d7f0818ce684948eea"),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            "envoy",
        )
        .unwrap();
        assert_eq!(
            token,
            "v1:1700000000:192976122c9fbaa4cb8c2554be66f2439e020a7d470ac838f2a622b0c5829a49"
        );
        let config = TlsFingerprintConfig {
            attestation_key: Some(key.into()),
            max_age_seconds: 60,
            ..TlsFingerprintConfig::default()
        };
        assert!(verify_request(
            &request(Some(token.clone())),
            &config,
            1_700_000_030
        ));
        let mut tampered = request(Some(token.clone()));
        tampered.path = Some("/admin".into());
        assert!(!verify_request(&tampered, &config, 1_700_000_030));
        assert!(!verify_request(
            &request(Some(token)),
            &config,
            1_700_000_061
        ));
    }

    #[test]
    fn rejects_get_root_replay_on_post_admin() {
        let key = "0123456789abcdef0123456789abcdef";
        let token = create_attestation(
            key.as_bytes(),
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/",
            Some("72a589da586844d7f0818ce684948eea"),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            "envoy",
        )
        .unwrap();
        let config = TlsFingerprintConfig {
            attestation_key: Some(key.into()),
            ..TlsFingerprintConfig::default()
        };
        let mut replay = request(Some(token));
        replay.method = Some("POST".into());
        replay.path = Some("/admin".into());
        assert!(!verify_request(&replay, &config, 1_700_000_030));
    }

    #[test]
    fn accepts_previous_key_during_rotation() {
        let previous_key = "abcdef0123456789abcdef0123456789";
        let token = create_attestation(
            previous_key.as_bytes(),
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/products",
            Some("72a589da586844d7f0818ce684948eea"),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            "envoy",
        )
        .unwrap();
        let config = TlsFingerprintConfig {
            attestation_key: Some("0123456789abcdef0123456789abcdef".into()),
            previous_attestation_key: Some(previous_key.into()),
            ..TlsFingerprintConfig::default()
        };
        assert!(verify_request(
            &request(Some(token)),
            &config,
            1_700_000_030
        ));
    }
}
