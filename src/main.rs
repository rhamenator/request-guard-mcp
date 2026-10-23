use anyhow::Result;
use request_guard_mcp::{config, mcp, state, telemetry};

#[cfg(unix)]
async fn wait_for_network_signal(terminate: &mut tokio::signal::unix::Signal) {
    let mut term_available = true;
    let mut interrupt_available = true;
    loop {
        tokio::select! {
            result = terminate.recv(), if term_available => match result {
                Some(()) => return,
                None => term_available = false,
            },
            result = tokio::signal::ctrl_c(), if interrupt_available => match result {
                Ok(()) => return,
                Err(error) => {
                    tracing::warn!(%error, "cannot listen for Ctrl-C; retaining SIGTERM handler");
                    interrupt_available = false;
                }
            },
            else => std::future::pending::<()>().await,
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_network_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "cannot listen for Ctrl-C");
        std::future::pending::<()>().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let stdio = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [mode] if mode == "--stdio" => true,
        _ => anyhow::bail!("usage: request-guard-mcp [--stdio]"),
    };
    // Load config (reads .env and env vars)
    let config = if stdio {
        config::Config::load_stdio()?
    } else {
        config::Config::load()?
    };

    // Initialize tracing
    let tracer_provider = telemetry::init_tracing(
        &config.log_level,
        &config.telemetry.service_name,
        config.telemetry.otlp_endpoint.as_deref(),
        stdio,
    )?;

    if stdio {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            "request-guard-mcp starting on stdio"
        );
    } else {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            host = %config.host,
            port = config.port,
            "request-guard-mcp starting"
        );
    }

    // Build application state
    let app_state = state::AppState::initialize(config).await?;

    if stdio {
        let result = mcp::transport_stdio::run_stdio(app_state).await;
        if let Some(provider) = tracer_provider {
            if let Err(error) = provider.shutdown() {
                eprintln!("failed to flush OTLP traces: {error}");
                std::process::exit(1);
            }
        }
        if let Err(error) = result {
            eprintln!("stdio transport failed: {error:#}");
            std::process::exit(1);
        }
        // tokio::io::stdin uses a blocking reader. Terminate the process
        // explicitly so a peer that closed stdout but left stdin open cannot
        // keep the runtime waiting on that reader during teardown.
        std::process::exit(0);
    }

    // Register SIGTERM before entering the accept loop. The first signal
    // starts a bounded drain; a second signal forces immediate termination.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let signal_monitor = tokio::spawn(async move {
        #[cfg(unix)]
        wait_for_network_signal(&mut terminate).await;
        #[cfg(not(unix))]
        wait_for_network_signal().await;
        let _ = shutdown_tx.send(());
        #[cfg(unix)]
        wait_for_network_signal(&mut terminate).await;
        #[cfg(not(unix))]
        wait_for_network_signal().await;
        std::process::exit(1);
    });
    let result = mcp::server::run_server(app_state, async {
        let _ = shutdown_rx.await;
    })
    .await;
    signal_monitor.abort();
    if let Some(provider) = tracer_provider {
        provider
            .shutdown()
            .map_err(|error| anyhow::anyhow!("failed to flush OTLP traces: {error}"))?;
    }
    result
}
