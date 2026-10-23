use crate::config::LimitsConfig;
use crate::mcp::origin::check_origin;
use crate::mcp::tool_registry::ToolRegistry;
use crate::mcp::transport_ws::{handle_ws_connection, process_message, SUPPORTED_PROTOCOL_VERSION};
use crate::state::AppState;
use crate::telemetry::gather_metrics;
use axum::{
    body::{to_bytes, Body},
    extract::{ws::WebSocketUpgrade, FromRequestParts, Request, State},
    http::{
        header::{
            ACCEPT, ALLOW, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, UPGRADE,
            X_CONTENT_TYPE_OPTIONS,
        },
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    middleware::map_response,
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{
    convert::Infallible,
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{watch, Notify, Semaphore};
use tower::Service;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

#[derive(Clone)]
pub struct ServerState {
    pub app: Arc<AppState>,
    pub registry: Arc<ToolRegistry>,
}

pub fn build_router(state: ServerState, max_body: usize) -> Router {
    let metrics_path = state.app.config.telemetry.metrics_path.clone();
    let utility_routes = Router::new()
        .route("/health", get(http_health_handler))
        .route(&metrics_path, get(metrics_handler))
        .route("/ready", get(readiness_handler))
        .layer(RequestBodyLimitLayer::new(max_body));
    Router::new()
        .route("/mcp", any(mcp_handler))
        .merge(utility_routes)
        .layer(map_response(add_security_headers))
        .with_state(state)
}

async fn add_security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

async fn mcp_handler(State(state): State<ServerState>, request: Request) -> Response {
    let caller_scope = match authorize(request.headers(), &state.app) {
        Ok(scope) => scope,
        Err(error) => return error_response(&error),
    };
    if let Err(status) = check_origin(request.headers(), &state.app.config.auth.allowed_origins) {
        return status.into_response();
    }
    let websocket_upgrade = request.method() == Method::GET
        && header_has_token(request.headers(), UPGRADE, "websocket")
        && header_has_token(request.headers(), CONNECTION, "upgrade");
    // WebSocket is a custom transport and does not use the Streamable HTTP
    // version header. Check every other MCP HTTP method before dispatch.
    if !websocket_upgrade && !valid_protocol_version(request.headers()) {
        return invalid_protocol_version_response();
    }

    match *request.method() {
        Method::POST => http_mcp_handler(state, request, caller_scope).await,
        Method::GET if websocket_upgrade => ws_handler(state, request, caller_scope).await,
        _ => (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "POST, GET")]).into_response(),
    }
}

async fn ws_handler(state: ServerState, request: Request, caller_scope: String) -> Response {
    let (mut parts, _) = request.into_parts();
    let mut ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };

    let Ok(connection_permit) = Arc::clone(&state.app.connection_semaphore).try_acquire_owned()
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket connection limit reached",
        )
            .into_response();
    };
    let max_message_bytes = state.app.config.limits.max_request_bytes;
    ws = ws
        .protocols(["mcp"])
        .max_message_size(max_message_bytes)
        .max_frame_size(max_message_bytes);

    ws.on_upgrade(move |socket| {
        handle_ws_connection(
            socket,
            state.app,
            state.registry,
            caller_scope,
            connection_permit,
        )
    })
}

fn header_has_token(
    headers: &HeaderMap,
    name: axum::http::header::HeaderName,
    token: &str,
) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

async fn http_mcp_handler(state: ServerState, request: Request, caller_scope: String) -> Response {
    if !json_content_type(request.headers()) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "MCP POST Content-Type must be application/json with UTF-8 charset",
        )
            .into_response();
    }
    if !accepts_json(request.headers()) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            "MCP HTTP responses require an Accept range allowing application/json",
        )
            .into_response();
    }
    if request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > state.app.config.limits.max_request_bytes as u64)
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds limit").into_response();
    }
    let body = match tokio::time::timeout(
        Duration::from_secs(state.app.config.limits.http_body_timeout_secs),
        to_bytes(
            request.into_body(),
            state.app.config.limits.max_request_bytes,
        ),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds limit").into_response()
        }
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "Request body timed out").into_response(),
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error: MCP messages must be UTF-8"}}"#,
        )
            .into_response();
    };
    // The one-way envelope check below also parses the body. Reject wide
    // structures before either parser allocates JSON Value nodes.
    if !super::transport_ws::within_json_complexity_budget(text) {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body exceeds limit").into_response();
    }
    match process_message(text, &state.app, &state.registry, &caller_scope).await {
        Some(response) => {
            // Rejected notifications and client responses need an HTTP error
            // status, not an in-band JSON-RPC response (MCP Streamable HTTP).
            if is_one_way_candidate(text) {
                StatusCode::BAD_REQUEST.into_response()
            } else {
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    response,
                )
                    .into_response()
            }
        }
        // MCP 2025-06-18 Streamable HTTP acknowledges accepted client
        // notifications and responses with 202 and no response body.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

fn is_one_way_candidate(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| {
            value.as_object().map(|object| {
                let has_method = object.contains_key("method");
                (has_method && !object.contains_key("id"))
                    || (!has_method
                        && ["id", "result", "error"]
                            .iter()
                            .any(|key| object.contains_key(*key)))
            })
        })
        .unwrap_or(false)
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        // Older direct clients can omit Content-Type; the JSON parser still
        // validates the bounded UTF-8 body.
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    let mut saw_charset = false;
    for part in parts {
        let Some((name, value)) = part.trim().split_once('=') else {
            return false;
        };
        if !name.trim().eq_ignore_ascii_case("charset") || saw_charset {
            return false;
        }
        saw_charset = true;
        let value = value.trim();
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if !value.eq_ignore_ascii_case("utf-8") {
            return false;
        }
    }
    true
}

// This endpoint has one response representation: application/json. RFC 9110
// gives an exact media range precedence over a type wildcard and a type
// wildcard precedence over */*, even when the more specific range has q=0.
fn accepts_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(ACCEPT).iter().peekable();
    if values.peek().is_none() {
        return true; // Legacy direct clients omit Accept.
    }
    let mut best: Option<(u8, u8, u16)> = None;
    for value in values {
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(ranges) = split_unquoted(value, ',') else {
            return false;
        };
        'range: for range in ranges {
            let Some(parameters) = split_unquoted(range.trim(), ';') else {
                return false;
            };
            let mut parts = parameters.into_iter();
            let media = parts.next().unwrap_or("").trim();
            let specificity = if media.eq_ignore_ascii_case("application/json") {
                2
            } else if media.eq_ignore_ascii_case("application/*") {
                1
            } else if media == "*/*" {
                0
            } else {
                continue;
            };
            let mut quality = 1000;
            let mut saw_q = false;
            let mut matched_parameters = 0;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    continue 'range;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    if saw_q {
                        return false;
                    }
                    saw_q = true;
                    let Some(parsed) = parse_quality(value.trim()) else {
                        return false;
                    };
                    quality = parsed;
                } else {
                    // A media parameter not carried by our JSON response does
                    // not match. It must not invalidate a later wildcard.
                    if !name.trim().eq_ignore_ascii_case("charset")
                        || !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
                        || specificity != 2
                    {
                        continue 'range;
                    }
                    matched_parameters = 1;
                }
            }
            if best.is_none_or(|(prior, params, _)| {
                (specificity, matched_parameters) > (prior, params)
            }) {
                best = Some((specificity, matched_parameters, quality));
            } else if let Some((prior, params, prior_quality)) = best {
                if (specificity, matched_parameters) == (prior, params) && quality > prior_quality {
                    best = Some((specificity, matched_parameters, quality));
                }
            }
        }
    }
    best.is_some_and(|(_, _, quality)| quality > 0)
}

fn split_unquoted(value: &str, separator: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == separator {
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" if fraction.is_empty() => Some(0),
        "0" => fraction
            .parse::<u16>()
            .ok()
            .map(|n| n * 10_u16.pow((3 - fraction.len()) as u32)),
        "1" if fraction.bytes().all(|c| c == b'0') => Some(1000),
        _ => None,
    }
}

fn valid_protocol_version(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all("mcp-protocol-version").iter();
    match values.next() {
        // No header is retained for older clients, which have no session state
        // from which to recover a negotiated version.
        None => true,
        Some(value) => {
            value.as_bytes() == SUPPORTED_PROTOCOL_VERSION.as_bytes() && values.next().is_none()
        }
    }
}

fn invalid_protocol_version_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "Invalid or unsupported MCP-Protocol-Version",
    )
        .into_response()
}

#[cfg(test)]
mod protocol_version_tests {
    use super::*;

    #[test]
    fn duplicate_version_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-06-18"),
        );
        headers.append(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-06-18"),
        );
        assert!(!valid_protocol_version(&headers));
    }

    #[test]
    fn duplicate_content_type_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(!json_content_type(&headers));
    }

    #[test]
    fn accept_quality_and_specificity() {
        for value in [
            "application/json",
            "application/json, text/event-stream",
            "application/*",
            "*/*",
            "application/json;q=0.001",
            "application/json;q=1.000",
            "application/json;q=0.5, text/event-stream",
            "application/json;q=0.5, application/*;q=0",
            "Application/JSON; Q=1",
            "application/json;foo=bar, */*",
            "application/json;q=1;version=1, */*",
            "multipart/form-data;boundary=\"x,application/json,y\", application/json",
            "application/*;q=0, application/json",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, HeaderValue::from_str(value).unwrap());
            assert!(accepts_json(&headers), "{value}");
        }
        for value in [
            "text/event-stream",
            "application/json;q=0",
            "application/json;q=0, */*;q=1",
            "application/*;q=0, */*;q=1",
            "*/*;q=0",
            "application/json;q=1.1",
            "application/json;q=bogus",
            "application/json;charset=utf-8;q=0, application/json",
            "application/json;q=0;charset=utf-8, application/json;q=1",
            "application/json;q=0.0001",
            "multipart/form-data;boundary=\"x,application/json,y\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, HeaderValue::from_str(value).unwrap());
            assert!(!accepts_json(&headers), "{value}");
        }
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.append(ACCEPT, HeaderValue::from_static("application/json"));
        assert!(accepts_json(&headers));
    }
}

fn authorize(headers: &HeaderMap, state: &AppState) -> Result<String, crate::error::AppError> {
    if state.config.auth.enabled {
        return crate::auth::authenticated_cache_scope_with_key(
            headers,
            &state.config.auth.tokens,
            state
                .config
                .auth
                .cache_scope_hmac_key
                .as_deref()
                .map(str::as_bytes),
        );
    }
    Ok("public".to_string())
}

fn error_response(error: &crate::error::AppError) -> Response {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, error.code()).into_response()
}

async fn http_health_handler(State(state): State<ServerState>) -> impl IntoResponse {
    let health = crate::tools::health::run(&state.app).await;
    (StatusCode::OK, axum::Json(health))
}

async fn metrics_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        gather_metrics(),
    )
}

async fn readiness_handler(State(state): State<ServerState>) -> impl IntoResponse {
    let capacity_available = state.app.semaphore.available_permits() > 0;
    let (redis_ready, postgres_ready) = tokio::join!(
        async {
            state.app.config.redis.url.is_none()
                || crate::tools::health::bounded_backend_ping(state.app.redis.ping()).await
        },
        async {
            state.app.config.postgres.url.is_none()
                || crate::tools::health::bounded_backend_ping(state.app.postgres.ping()).await
        },
    );
    let geoip_configured = state.app.config.geoip.mmdb_path.is_some()
        || state.app.config.geoip.city_mmdb_path.is_some()
        || state.app.config.geoip.asn_mmdb_path.is_some()
        || state.app.config.geoip.anonymous_ip_mmdb_path.is_some();
    let geoip_ready = !geoip_configured || state.app.geoip.is_available();
    if capacity_available && redis_ready && postgres_ready && geoip_ready {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

pub async fn run_server(app_state: AppState) -> anyhow::Result<()> {
    let registry = Arc::new(crate::mcp::tool_registry::build_registry());
    let bind_addr = app_state.config.bind_addr()?;
    let max_body = app_state.config.limits.max_request_bytes;

    info!(addr = %bind_addr, "starting MCP server");

    // Warmup
    let warmup_req = crate::models::request::WarmupRequest {
        target: Some("all".to_string()),
    };
    crate::tools::warmup::run(&app_state, warmup_req).await;

    let server_state = ServerState {
        app: Arc::new(app_state),
        registry,
    };

    let router = build_router(server_state.clone(), max_body);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "listening");

    serve_listener(listener, router, server_state.app.config.limits.clone()).await
}

#[derive(Clone, Copy, Default)]
struct Http2Activity {
    seen: bool,
    active: usize,
    requests: usize,
}

impl Http2Activity {
    fn admit(&mut self, request_cap: usize) -> bool {
        self.seen = true;
        if self.requests >= request_cap {
            return false;
        }
        self.active += 1;
        self.requests += 1;
        true
    }
}

struct Http2RequestGuard(watch::Sender<Http2Activity>);
impl Drop for Http2RequestGuard {
    fn drop(&mut self) {
        self.0.send_modify(|activity| activity.active -= 1);
    }
}

const HTTP_CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(120);
const HTTP1_MAX_REQUESTS: usize = 128;

#[derive(Debug, PartialEq, Eq)]
enum AcceptErrorAction {
    RetryImmediately,
    RetryWithBackoff,
    Fatal,
}

fn accept_error_action(error: &io::Error) -> AcceptErrorAction {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if matches!(
        error.raw_os_error(),
        // Linux accept(2) reports these pending-connection network errors as
        // accept failures; retrying permits the next peer to proceed.
        Some(1 | 64 | 71 | 92 | 95 | 100 | 101 | 112 | 113)
    ) {
        return AcceptErrorAction::RetryImmediately;
    }
    match error.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => AcceptErrorAction::RetryImmediately,
        io::ErrorKind::OutOfMemory => AcceptErrorAction::RetryWithBackoff,
        _ => {
            // These resource errors are not all represented by ErrorKind.
            // Keep this narrow: a permanently invalid listener must fail.
            let resource_error = match error.raw_os_error() {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Some(12 | 23 | 24 | 105) => true, // ENOMEM, ENFILE, EMFILE, ENOBUFS
                #[cfg(target_os = "macos")]
                Some(12 | 23 | 24 | 55) => true,
                #[cfg(windows)]
                Some(4 | 10024 | 10055) => true,
                _ => false,
            };
            if resource_error {
                AcceptErrorAction::RetryWithBackoff
            } else {
                AcceptErrorAction::Fatal
            }
        }
    }
}

async fn serve_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    limits: LimitsConfig,
) -> anyhow::Result<()> {
    serve_listener_with_http1_lifetime(listener, router, limits, HTTP_CONNECTION_MAX_LIFETIME).await
}

async fn serve_listener_with_http1_lifetime(
    listener: tokio::net::TcpListener,
    router: Router,
    limits: LimitsConfig,
    http1_max_lifetime: Duration,
) -> anyhow::Result<()> {
    let connection_limit = Arc::new(Semaphore::new(limits.max_connections));
    let mut last_accept_error_log: Option<Instant> = None;
    let mut last_accept_recovery_log: Option<Instant> = None;
    let mut accept_error_count = 0_u64;
    let mut resource_backoff = Duration::from_millis(100);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                if accept_error_count > 0 {
                    if last_accept_recovery_log
                        .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
                    {
                        info!(accept_error_count, "TCP accept recovered");
                        last_accept_recovery_log = Some(Instant::now());
                    }
                    accept_error_count = 0;
                    resource_backoff = Duration::from_millis(100);
                }
                accepted
            }
            Err(error) => {
                match accept_error_action(&error) {
                    AcceptErrorAction::RetryImmediately => continue,
                    AcceptErrorAction::Fatal => return Err(error.into()),
                    AcceptErrorAction::RetryWithBackoff => {}
                }
                accept_error_count = accept_error_count.saturating_add(1);
                if last_accept_error_log
                    .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
                {
                    warn!(%error, accept_error_count, "TCP accept failed; retrying");
                    last_accept_error_log = Some(Instant::now());
                }
                tokio::time::sleep(resource_backoff).await;
                resource_backoff = resource_backoff
                    .saturating_mul(2)
                    .min(Duration::from_secs(1));
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
            // This path is attacker-reachable; per-rejection logs would turn
            // connection shedding into unbounded log growth.
            drop(stream);
            continue;
        };
        let router = router.clone();
        let header_timeout = Duration::from_secs(limits.http_header_timeout_secs);
        let http2_idle_timeout = Duration::from_secs(limits.http2_idle_timeout_secs);
        // Bound a peer that repeatedly sends cheap unauthenticated requests
        // before each idle deadline, including rapid stream resets.
        let http2_max_lifetime = HTTP_CONNECTION_MAX_LIFETIME;
        let http2_max_requests = 128;
        let http_drain_timeout = Duration::from_secs(
            limits
                .http_body_timeout_secs
                .saturating_add(
                    limits
                        .per_tool_timeout_secs
                        .max(limits.classify_timeout_secs),
                )
                .saturating_add(2),
        );
        tokio::spawn(async move {
            // Hyper's HTTP/1 header timeout does not cover the auto-protocol
            // sniff or an HTTP/2 connection before its first request. Bound
            // both before they can retain a connection permit indefinitely.
            let first_request = Arc::new(Notify::new());
            let first_request_for_service = Arc::clone(&first_request);
            let (activity_tx, mut activity_rx) = watch::channel(Http2Activity::default());
            let http1_requests = Arc::new(AtomicUsize::new(0));
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let is_http2 = request.version() == hyper::Version::HTTP_2;
                let http1_request_number = if is_http2 {
                    0
                } else {
                    http1_requests.fetch_add(1, Ordering::Relaxed) + 1
                };
                let activity_tx = activity_tx.clone();
                let mut over_http2_request_cap = false;
                if is_http2 {
                    activity_tx.send_modify(|activity| {
                        over_http2_request_cap = !activity.admit(http2_max_requests);
                    });
                }
                let request_guard =
                    (is_http2 && !over_http2_request_cap).then(|| Http2RequestGuard(activity_tx));
                first_request_for_service.notify_one();
                let mut router = router.clone();
                async move {
                    let _request_guard = request_guard;
                    if over_http2_request_cap {
                        return Ok::<Response, Infallible>(
                            (StatusCode::SERVICE_UNAVAILABLE, "connection request limit")
                                .into_response(),
                        );
                    }
                    if http1_request_number > HTTP1_MAX_REQUESTS {
                        let mut response =
                            (StatusCode::SERVICE_UNAVAILABLE, "connection request limit")
                                .into_response();
                        response
                            .headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("close"));
                        return Ok::<Response, Infallible>(response);
                    }
                    let mut response = router.call(request.map(Body::new)).await?;
                    if http1_request_number == HTTP1_MAX_REQUESTS
                        && response.status() != StatusCode::SWITCHING_PROTOCOLS
                    {
                        response
                            .headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("close"));
                    }
                    Ok(response)
                }
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            builder.http2().max_concurrent_streams(16);
            {
                let connection =
                    builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                tokio::pin!(connection);
                // Give Hyper's HTTP/1 timer a small chance to send 408 before
                // our transport-neutral first-request deadline closes the socket.
                let first_request_deadline =
                    header_timeout.saturating_add(Duration::from_millis(250));
                let outcome = tokio::time::timeout(first_request_deadline, async {
                    tokio::select! {
                        result = &mut connection => Some(result),
                        _ = first_request.notified() => None,
                    }
                })
                .await;
                let result = match outcome {
                    Ok(Some(result)) => Some(result),
                    Ok(None) if activity_rx.borrow().seen => {
                        // An HTTP/2 connection can stay open after a complete
                        // request. Idle, age and request-count caps apply;
                        // in-flight work gets a separate bounded drain.
                        let lifetime_deadline = tokio::time::sleep(http2_max_lifetime);
                        tokio::pin!(lifetime_deadline);
                        let result = loop {
                            let activity = *activity_rx.borrow_and_update();
                            if activity.requests >= http2_max_requests {
                                break None;
                            }
                            let active = activity.active;
                            if active == 0 {
                                tokio::select! {
                                    biased;
                                    result = &mut connection => break Some(result),
                                    _ = &mut lifetime_deadline => break None,
                                    changed = activity_rx.changed() => {
                                        if changed.is_err() { break None; }
                                    }
                                    _ = tokio::time::sleep(http2_idle_timeout) => {
                                        if !activity_rx.has_changed().unwrap_or(false) {
                                            break None;
                                        }
                                    }
                                }
                            } else {
                                tokio::select! {
                                    result = &mut connection => break Some(result),
                                    _ = &mut lifetime_deadline => break None,
                                    changed = activity_rx.changed() => {
                                        if changed.is_err() { break None; }
                                    }
                                }
                            }
                        };
                        if result.is_none() {
                            connection.as_mut().graceful_shutdown();
                            let drain_deadline = tokio::time::sleep(http_drain_timeout);
                            tokio::pin!(drain_deadline);
                            // A stream already on the wire at GOAWAY may still
                            // dispatch, and the response can outlive its handler.
                            // Wait for hyper's two-phase GOAWAY to finish, with a
                            // hard cap for peers that never answer its PING.
                            // Dispatch rejects requests over the cap even if
                            // hyper accepts them during the first GOAWAY phase.
                            tokio::select! {
                                _ = &mut connection => {},
                                _ = &mut drain_deadline => {},
                            }
                        }
                        result
                    }
                    // Stop accepting work at the HTTP/1 age cap while giving
                    // an in-flight request a bounded chance to finish. A peer
                    // that stops reading still loses its permit at the drain
                    // deadline.
                    Ok(None) => match tokio::time::timeout(http1_max_lifetime, &mut connection)
                        .await
                    {
                        Ok(result) => Some(result),
                        Err(_) => {
                            connection.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(http_drain_timeout, &mut connection).await;
                            None
                        }
                    },
                    Err(_) => None, // Pre-auth timeout is attacker-reachable; do not log each one.
                };
                if let Some(Err(error)) = result {
                    tracing::debug!(%peer, %error, "HTTP connection closed");
                }
            }
            // Close the connection before freeing its permit.
            drop(permit);
        });
    }
}

#[cfg(test)]
mod slow_client_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::timeout,
    };

    #[test]
    fn accept_error_classification_preserves_fatal_errors() {
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::ConnectionAborted)),
            AcceptErrorAction::RetryImmediately
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::Interrupted)),
            AcceptErrorAction::RetryImmediately
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::OutOfMemory)),
            AcceptErrorAction::RetryWithBackoff
        );
        assert_eq!(
            accept_error_action(&io::Error::from(io::ErrorKind::InvalidInput)),
            AcceptErrorAction::Fatal
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert_eq!(
                accept_error_action(&io::Error::from_raw_os_error(24)),
                AcceptErrorAction::RetryWithBackoff
            );
            assert_eq!(
                accept_error_action(&io::Error::from_raw_os_error(100)),
                AcceptErrorAction::RetryImmediately
            );
            assert_eq!(
                accept_error_action(&io::Error::from_raw_os_error(9)),
                AcceptErrorAction::Fatal
            );
        }
    }

    #[test]
    fn http2_admission_rejects_request_129_without_dispatch() {
        let mut activity = Http2Activity::default();
        for _ in 0..128 {
            assert!(activity.admit(128));
        }
        assert_eq!(activity.requests, 128);
        assert_eq!(activity.active, 128);
        assert!(!activity.admit(128));
        assert_eq!(activity.requests, 128);
        assert_eq!(activity.active, 128);
    }

    async fn test_server_with_limits(
        max_connections: usize,
        body_timeout_secs: u64,
        http2_idle_timeout_secs: u64,
        http1_max_lifetime: Duration,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let mut config = crate::config::Config::default();
        config.auth.enabled = true;
        config.auth.tokens = vec!["test-token-with-at-least-32-characters".to_string()];
        config.limits.http_header_timeout_secs = 1;
        config.limits.http_body_timeout_secs = body_timeout_secs;
        config.limits.per_tool_timeout_secs = 1;
        config.limits.classify_timeout_secs = 1;
        config.limits.http2_idle_timeout_secs = http2_idle_timeout_secs;
        config.limits.max_connections = max_connections;
        let limits = config.limits.clone();
        let max_body = limits.max_request_bytes;
        let state = ServerState {
            app: Arc::new(AppState::new(config)),
            registry: Arc::new(crate::mcp::tool_registry::build_registry()),
        };
        let router = build_router(state, max_body);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            serve_listener_with_http1_lifetime(listener, router, limits, http1_max_lifetime)
                .await
                .unwrap();
        });
        (addr, task)
    }

    async fn test_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        test_server_with_limits(2, 1, 1, HTTP_CONNECTION_MAX_LIFETIME).await
    }

    async fn test_server_with_connections(
        max_connections: usize,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        test_server_with_limits(max_connections, 1, 1, HTTP_CONNECTION_MAX_LIFETIME).await
    }

    #[tokio::test]
    async fn partial_protocol_prefaces_release_connection_permits() {
        let (addr, task) = test_server_with_connections(3).await;
        let mut sockets = Vec::new();
        for preface in [
            b"".as_slice(),
            b"P".as_slice(),
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(preface).await.unwrap();
            sockets.push(stream);
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        for socket in &mut sockets {
            let mut response = Vec::new();
            timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
                .await
                .expect("partial preface must be closed")
                .unwrap();
            assert!(response.len() < 2048);
        }
        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 256];
        let read = timeout(Duration::from_secs(2), healthy.read(&mut response))
            .await
            .expect("pre-request timeout must release a connection permit")
            .unwrap();
        assert!(std::str::from_utf8(&response[..read])
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        task.abort();
    }

    #[tokio::test]
    async fn http1_lifetime_drains_inflight_response() {
        let router = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(600)).await;
                "completed after connection age deadline"
            }),
        );
        let limits = LimitsConfig {
            http_header_timeout_secs: 1,
            http_body_timeout_secs: 1,
            per_tool_timeout_secs: 1,
            classify_timeout_secs: 1,
            ..LimitsConfig::default()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            serve_listener_with_http1_lifetime(
                listener,
                router,
                limits,
                Duration::from_millis(200),
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("in-flight response should drain before its deadline")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response
            .windows(b"completed after connection age deadline".len())
            .any(|window| window == b"completed after connection age deadline"));
        task.abort();
    }

    #[tokio::test]
    async fn http1_slow_reader_releases_connection_permit_at_lifetime() {
        // A single response larger than a normal kernel send buffer makes the
        // non-reading peer hold the connection in the response-write path.
        let router = Router::new()
            .route(
                "/large",
                get(|| async { axum::body::Bytes::from(vec![b'x'; 16 * 1024 * 1024]) }),
            )
            .route("/health", get(|| async { "ok" }));
        let limits = LimitsConfig {
            max_connections: 1,
            http_header_timeout_secs: 1,
            http_body_timeout_secs: 1,
            per_tool_timeout_secs: 1,
            classify_timeout_secs: 1,
            ..LimitsConfig::default()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            serve_listener_with_http1_lifetime(listener, router, limits, Duration::from_secs(2))
                .await
                .unwrap();
        });
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        let mut slow_reader = socket.connect(addr).await.unwrap();
        timeout(
            Duration::from_secs(2),
            slow_reader.write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        )
        .await
        .expect("request should fit the sender buffer")
        .unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut blocked = TcpStream::connect(addr).await.unwrap();
        blocked
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = [0_u8; 256];
        let before_deadline = timeout(Duration::from_millis(500), blocked.read(&mut reply)).await;
        assert!(
            !matches!(before_deadline, Ok(Ok(n)) if reply[..n].starts_with(b"HTTP/1.1 200")),
            "a non-reading peer should still hold the only slot before its lifetime"
        );

        tokio::time::sleep(Duration::from_secs(6)).await;
        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let read = timeout(Duration::from_secs(2), healthy.read(&mut reply))
            .await
            .expect("HTTP/1 lifetime must release the connection permit")
            .unwrap();
        assert!(reply[..read].starts_with(b"HTTP/1.1 200"));
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn http1_request_budget_closes_busy_keepalive_connection() {
        let mut limits = crate::config::Config::default().limits;
        limits.max_connections = 1;
        // Longer than the read deadline: a header timeout must not make this
        // test pass if the request-budget close header is missing.
        limits.http_header_timeout_secs = 30;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/health", get(|| async { "ok" }));
        let task = tokio::spawn(async move {
            serve_listener_with_http1_lifetime(listener, router, limits, Duration::from_secs(30))
                .await
                .unwrap();
        });

        let mut busy = TcpStream::connect(addr).await.unwrap();
        let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut pipeline = Vec::with_capacity(request.len() * HTTP1_MAX_REQUESTS);
        for _ in 0..HTTP1_MAX_REQUESTS {
            pipeline.extend_from_slice(request);
        }
        busy.write_all(&pipeline).await.unwrap();
        let mut responses = Vec::new();
        timeout(Duration::from_secs(5), busy.read_to_end(&mut responses))
            .await
            .expect("HTTP/1 request budget must close the busy connection")
            .unwrap();
        assert_eq!(
            responses
                .windows(b"HTTP/1.1 200".len())
                .filter(|window| *window == b"HTTP/1.1 200")
                .count(),
            HTTP1_MAX_REQUESTS
        );
        let last_status = responses
            .windows(b"HTTP/1.1 200".len())
            .rposition(|window| window == b"HTTP/1.1 200")
            .unwrap();
        assert!(responses[last_status..]
            .windows(b"connection: close".len())
            .any(|window| window.eq_ignore_ascii_case(b"connection: close")));

        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = [0_u8; 256];
        let read = timeout(Duration::from_secs(2), healthy.read(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply[..read].starts_with(b"HTTP/1.1 200"));
        task.abort();
    }

    #[tokio::test]
    async fn first_request_does_not_limit_websocket_lifetime() {
        let (addr, task) = test_server_with_limits(2, 1, 1, Duration::from_secs(2)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token-with-at-least-32-characters\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
        let mut response = [0_u8; 512];
        let read = timeout(Duration::from_secs(2), stream.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&response[..read])
            .unwrap()
            .starts_with("HTTP/1.1 101"));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        stream.write_all(b"\x89\x80\x00\x00\x00\x00").await.unwrap();
        let mut pong = [0_u8; 2];
        timeout(Duration::from_secs(2), stream.read_exact(&mut pong))
            .await
            .expect("WebSocket must outlive the first-request deadline")
            .unwrap();
        assert_eq!(pong, [0x8a, 0x00]);
        task.abort();
    }

    #[tokio::test]
    async fn idle_http2_after_valid_request_releases_connection_permit() {
        let (addr, task) = test_server_with_connections(1).await;
        let mut h2 = TcpStream::connect(addr).await.unwrap();
        // HTTP/2 client preface, empty SETTINGS, and a static HPACK-encoded
        // GET /health stream. These bytes are independent of a test client SDK.
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        h2.write_all(b"\0\0\x11\x01\x05\0\0\0\x01\x82\x44\x85\x62\x72\x8e\x84\xcf\x86\x41\x86\xa0\xe4\x1d\x13\x9d\x09")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), async {
            loop {
                let mut chunk = [0_u8; 1024];
                let read = h2.read(&mut chunk).await.unwrap();
                assert!(read > 0, "HTTP/2 health response must arrive");
                response.extend_from_slice(&chunk[..read]);
                if response
                    .windows(b"healthy".len())
                    .any(|part| part == b"healthy")
                {
                    break;
                }
            }
        })
        .await
        .expect("HTTP/2 health request must complete");
        timeout(Duration::from_secs(10), h2.read_to_end(&mut response))
            .await
            .expect("idle HTTP/2 connection must close")
            .unwrap();
        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = [0_u8; 256];
        let read = timeout(Duration::from_secs(2), healthy.read(&mut reply))
            .await
            .expect("idle HTTP/2 must release the connection permit")
            .unwrap();
        assert!(std::str::from_utf8(&reply[..read])
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        task.abort();
    }

    #[tokio::test]
    async fn repeated_http2_health_requests_reach_connection_request_cap() {
        let (addr, task) = test_server_with_limits(1, 1, 30, HTTP_CONNECTION_MAX_LIFETIME).await;
        let mut h2 = TcpStream::connect(addr).await.unwrap();
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        let headers = b"\x82\x44\x85\x62\x72\x8e\x84\xcf\x86\x41\x86\xa0\xe4\x1d\x13\x9d\x09";
        timeout(Duration::from_secs(15), async {
            for stream_number in 0..127_u32 {
                let stream_id = stream_number * 2 + 1;
                let mut frame = [0_u8, 0, 17, 1, 5, 0, 0, 0, 0];
                frame[5..9].copy_from_slice(&stream_id.to_be_bytes());
                h2.write_all(&frame).await.unwrap();
                h2.write_all(headers).await.unwrap();
                let mut response = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = h2.read(&mut chunk).await.unwrap();
                    assert!(read > 0, "HTTP/2 connection closed before request cap");
                    response.extend_from_slice(&chunk[..read]);
                    if response.windows(7).any(|part| part == b"healthy") {
                        break;
                    }
                }
            }
        })
        .await
        .expect("bounded health requests must complete");
        // Send the 128th and 129th streams before reading GOAWAY. Only the
        // former may reach the health handler even if hyper accepts both.
        for stream_id in [255_u32, 257_u32] {
            let mut frame = [0_u8, 0, 17, 1, 5, 0, 0, 0, 0];
            frame[5..9].copy_from_slice(&stream_id.to_be_bytes());
            h2.write_all(&frame).await.unwrap();
            h2.write_all(headers).await.unwrap();
        }
        let mut response = Vec::new();
        timeout(Duration::from_secs(10), h2.read_to_end(&mut response))
            .await
            .expect("request cap must close the HTTP/2 connection")
            .unwrap();
        assert!(
            response
                .windows(b"\"version\":".len())
                .filter(|part| *part == b"\"version\":")
                .count()
                == 1,
            "request 129 must not reach the health handler"
        );
        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = [0_u8; 256];
        let read = timeout(Duration::from_secs(2), healthy.read(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&reply[..read])
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        task.abort();
    }

    #[tokio::test]
    async fn reset_http2_stream_does_not_leak_active_request_count() {
        let (addr, task) = test_server_with_limits(1, 3, 1, HTTP_CONNECTION_MAX_LIFETIME).await;
        let mut h2 = TcpStream::connect(addr).await.unwrap();
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        // HPACK headers for an authenticated POST /mcp stream with a declared
        // 100-byte body that never arrives. RST_STREAM cancels the service.
        let headers = "000042010400000001834483629257864186a0e41d139d091f089fba51d85b14495095927ea5a96f064ceb0d2b5051a12b32258938ec19125b115f8b1d75d0620d263d4c7441ea5c820801";
        let headers: Vec<u8> = (0..headers.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&headers[index..index + 2], 16).unwrap())
            .collect();
        h2.write_all(&headers).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1300)).await;
        let mut response = Vec::new();
        assert!(
            timeout(Duration::from_millis(100), h2.read_to_end(&mut response))
                .await
                .is_err(),
            "an in-flight body must outlive the idle deadline"
        );
        h2.write_all(b"\0\0\x04\x03\0\0\0\0\x01\0\0\0\0")
            .await
            .unwrap();
        timeout(Duration::from_secs(10), h2.read_to_end(&mut response))
            .await
            .expect("reset stream must not disable the HTTP/2 idle deadline")
            .unwrap();
        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = [0_u8; 256];
        let read = timeout(Duration::from_secs(2), healthy.read(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&reply[..read])
            .unwrap()
            .starts_with("HTTP/1.1 200"));
        task.abort();
    }

    #[tokio::test]
    async fn incomplete_headers_cannot_hold_socket_indefinitely() {
        let (addr, task) = test_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 128];
        let read = timeout(Duration::from_secs(3), stream.read(&mut response))
            .await
            .expect("partial headers must time out");
        assert!(
            read.is_ok(),
            "connection should close or receive an HTTP timeout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn incomplete_authorized_body_returns_timeout() {
        let (addr, task) = test_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token-with-at-least-32-characters\r\nContent-Length: 100\r\n\r\nx").await.unwrap();
        let mut response = [0_u8; 256];
        let read = timeout(Duration::from_secs(3), stream.read(&mut response))
            .await
            .expect("partial body must time out")
            .unwrap();
        assert!(std::str::from_utf8(&response[..read])
            .unwrap()
            .starts_with("HTTP/1.1 408"));
        task.abort();
    }
}
