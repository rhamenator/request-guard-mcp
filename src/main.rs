use anyhow::Result;
use request_guard_mcp::{config, mcp, state, telemetry};

#[tokio::main]
async fn main() -> Result<()> {
    // Load config (reads .env and env vars)
    let config = config::Config::load()?;

    // Initialize tracing
    let tracer_provider = telemetry::init_tracing(
        &config.log_level,
        &config.telemetry.service_name,
        config.telemetry.otlp_endpoint.as_deref(),
    )?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %config.host,
        port = config.port,
        "request-guard-mcp starting"
    );

    // Build application state
    let app_state = state::AppState::initialize(config).await?;

    // Run the MCP server (blocks until shutdown)
    let result = mcp::server::run_server(app_state).await;
    if let Some(provider) = tracer_provider {
        provider
            .shutdown()
            .map_err(|error| anyhow::anyhow!("failed to flush OTLP traces: {error}"))?;
    }
    result
}
