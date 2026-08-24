use crate::mcp::tool_registry::ToolRegistry;
use crate::mcp::transport_ws::{handle_ws_connection, process_message};
use crate::state::AppState;
use crate::telemetry::gather_metrics;
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
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
        .layer(RequestBodyLimitLayer::new(max_body))
        .with_state(state)
}

async fn ws_handler(
    mut ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<ServerState>,
) -> Response {
    let caller_scope = match authorize(&headers, &state.app) {
        Ok(scope) => scope,
        Err(error) => return error_response(&error),
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

async fn http_mcp_handler(
    headers: HeaderMap,
    State(state): State<ServerState>,
    body: axum::body::Bytes,
) -> Response {
    let caller_scope = match authorize(&headers, &state.app) {
        Ok(scope) => scope,
        Err(error) => return error_response(&error),
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
        None => StatusCode::NO_CONTENT.into_response(),
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

    let router = build_router(server_state, max_body);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "listening");

    axum::serve(listener, router).await?;
    Ok(())
}
