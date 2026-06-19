use crate::mcp::tool_registry::ToolRegistry;
use crate::mcp::transport_ws::handle_ws_connection;
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
    Router::new()
        .route("/mcp", get(ws_handler))
        .route("/health", get(http_health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ready", get(readiness_handler))
        .layer(RequestBodyLimitLayer::new(max_body))
        .with_state(state)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<ServerState>,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    ws.on_upgrade(move |socket| handle_ws_connection(socket, state.app, state.registry, auth))
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
    // Simple readiness: semaphore available + no critical failures
    let available = state.app.semaphore.available_permits() > 0;
    if available {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

pub async fn run_server(app_state: AppState) -> anyhow::Result<()> {
    let registry = Arc::new(crate::mcp::tool_registry::build_registry());
    let bind_addr = app_state.config.bind_addr();
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
