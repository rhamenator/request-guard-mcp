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
        header::{ALLOW, CONNECTION, UPGRADE, X_CONTENT_TYPE_OPTIONS},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware::map_response,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tower::Service;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

#[derive(Clone)]
pub struct ServerState {
    pub app: Arc<AppState>,
    pub registry: Arc<ToolRegistry>,
}

pub fn build_router(state: ServerState, max_body: usize) -> Router {
    let metrics_path = state.app.config.telemetry.metrics_path.clone();
    Router::new()
        .route("/mcp", get(ws_handler).post(http_mcp_handler))
        .route("/health", get(http_health_handler))
        .route(&metrics_path, get(metrics_handler))
        .route("/ready", get(readiness_handler))
        .layer(map_response(add_security_headers))
        .layer(RequestBodyLimitLayer::new(max_body))
        .with_state(state)
}

async fn add_security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

async fn ws_handler(State(state): State<ServerState>, request: Request) -> Response {
    let caller_scope = match authorize(request.headers(), &state.app) {
        Ok(scope) => scope,
        Err(error) => return error_response(&error),
    };
    if let Err(status) = check_origin(request.headers(), &state.app.config.auth.allowed_origins) {
        return status.into_response();
    }
    if !valid_protocol_version(request.headers()) {
        return invalid_protocol_version_response();
    }

    // The custom WebSocket transport shares this path with Streamable HTTP.
    // This server does not offer a server-initiated SSE GET stream.
    if !header_has_token(request.headers(), UPGRADE, "websocket")
        || !header_has_token(request.headers(), CONNECTION, "upgrade")
    {
        return (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "POST, GET")]).into_response();
    }
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

async fn http_mcp_handler(State(state): State<ServerState>, request: Request) -> Response {
    let caller_scope = match authorize(request.headers(), &state.app) {
        Ok(scope) => scope,
        Err(error) => return error_response(&error),
    };
    if let Err(status) = check_origin(request.headers(), &state.app.config.auth.allowed_origins) {
        return status.into_response();
    }
    if !valid_protocol_version(request.headers()) {
        return invalid_protocol_version_response();
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
    match process_message(text, &state.app, &state.registry, &caller_scope).await {
        Some(response) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            response,
        )
            .into_response(),
        // MCP 2025-06-18 Streamable HTTP acknowledges accepted client
        // notifications and responses with 202 and no response body.
        None => StatusCode::ACCEPTED.into_response(),
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
    let redis_ready = state.app.config.redis.url.is_none() || state.app.redis.ping().await;
    let postgres_ready = state.app.config.postgres.url.is_none() || state.app.postgres.ping().await;
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

async fn serve_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    limits: LimitsConfig,
) -> anyhow::Result<()> {
    let connection_limit = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
            // This path is attacker-reachable; per-rejection logs would turn
            // connection shedding into unbounded log growth.
            drop(stream);
            continue;
        };
        let router = router.clone();
        let header_timeout = Duration::from_secs(limits.http_header_timeout_secs);
        tokio::spawn(async move {
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let mut router = router.clone();
                async move { router.call(request.map(Body::new)).await }
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            builder
                .http2()
                .enable_connect_protocol()
                .max_concurrent_streams(16);
            if let Err(error) = builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%peer, %error, "HTTP connection closed");
            }
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

    async fn test_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let mut config = crate::config::Config::default();
        config.auth.enabled = true;
        config.auth.tokens = vec!["test-token-with-at-least-32-characters".to_string()];
        config.limits.http_header_timeout_secs = 1;
        config.limits.http_body_timeout_secs = 1;
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
            serve_listener(listener, router, limits).await.unwrap();
        });
        (addr, task)
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
