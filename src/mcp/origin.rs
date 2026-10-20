use axum::http::{header::ORIGIN, HeaderMap, StatusCode, Uri};

/// Browser Origin is a security boundary only when compared with a configured
/// trust anchor. Comparing it with Host would permit DNS rebinding when both
/// headers name an attacker-controlled domain.
pub(crate) fn check_origin(headers: &HeaderMap, allowed: &[String]) -> Result<(), StatusCode> {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        // Non-browser MCP clients commonly omit Origin; bearer authentication
        // still applies to them.
        return Ok(());
    };
    if origins.next().is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    let origin = origin.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
    if !valid_origin(origin) || !allowed.iter().any(|value| value == origin) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

pub(crate) fn valid_origin(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        || value.contains('#')
    {
        return false;
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return false;
    };
    let Some(scheme @ ("http" | "https")) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let port_ok = authority
        .as_str()
        .strip_prefix(authority.host())
        .is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.strip_prefix(':').is_some_and(|port| {
                    port.parse::<u16>().is_ok_and(|value| {
                        value != 0
                            && !(scheme == "http" && value == 80)
                            && !(scheme == "https" && value == 443)
                    })
                })
        });
    !authority.host().is_empty()
        && !authority.as_str().contains('@')
        && !authority
            .host()
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        && port_ok
        && value == format!("{scheme}://{authority}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn configured_origins_are_exact_and_structured() {
        for accepted in [
            "https://console.example",
            "https://console.example:8443",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            assert!(valid_origin(accepted), "{accepted}");
        }
        for rejected in [
            "null",
            "*",
            "file://example",
            "https://user@example.com",
            "https://console.example/path",
            "https://console.example?x=1",
            "https://console.example#fragment",
            "https://console.example,https://evil.example",
            "https://console.example:99999",
            "https://console.example:443",
            "http://console.example:80",
            "https://CONSOLE.example",
            " https://console.example",
        ] {
            assert!(!valid_origin(rejected), "{rejected}");
        }
    }

    #[test]
    fn absent_origin_is_allowed_but_unlisted_or_duplicated_origin_is_not() {
        let allowed = vec!["https://console.example".to_string()];
        assert!(check_origin(&HeaderMap::new(), &allowed).is_ok());
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://console.example"));
        assert!(check_origin(&headers, &allowed).is_ok());
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert_eq!(check_origin(&headers, &allowed), Err(StatusCode::FORBIDDEN));
        headers.append(ORIGIN, HeaderValue::from_static("https://console.example"));
        assert_eq!(check_origin(&headers, &allowed), Err(StatusCode::FORBIDDEN));
    }
}
