use anyhow::Result;
use request_guard_mcp::{config, mcp, state, telemetry};

#[tokio::main]
async fn main() -> Result<()> {
    // Load config (reads .env and env vars)
    let config = config::Config::load()?;

    // Initialize tracing
    telemetry::init_tracing(&config.log_level);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %config.host,
        port = config.port,
        "request-guard-mcp starting"
    );

    // Build application state
    let app_state = state::AppState::new(config);

    // Run the MCP server (blocks until shutdown)
    mcp::server::run_server(app_state).await
}
