use anyhow::Result;
use request_guard_mcp::{config, mcp, state, telemetry};
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_started = Arc::new(AtomicBool::new(false));
    if std::env::var_os("REQUEST_GUARD_NPM_PARENT_PIPE").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        let parent_pipe_tx = shutdown_tx.clone();
        let parent_pipe_started = shutdown_started.clone();
        // The npm launcher gives HTTP mode a private stdin pipe. EOF means
        // the launcher is gone, even when it was killed with SIGKILL. A
        // standard thread avoids keeping the Tokio runtime waiting on stdin.
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut byte = [0u8; 1];
            loop {
                match stdin.read(&mut byte) {
                    Ok(0) => {
                        if !parent_pipe_started.swap(true, Ordering::SeqCst) {
                            let _ = parent_pipe_tx.send(());
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => {
                        if !parent_pipe_started.swap(true, Ordering::SeqCst) {
                            let _ = parent_pipe_tx.send(());
                        }
                        break;
                    }
                    Ok(_) => {}
                }
            }
        });
    }
    let signal_tx = shutdown_tx.clone();
    let signal_started = shutdown_started.clone();
    let signal_monitor = tokio::spawn(async move {
        #[cfg(unix)]
        wait_for_network_signal(&mut terminate).await;
        #[cfg(not(unix))]
        wait_for_network_signal().await;
        if signal_started.swap(true, Ordering::SeqCst) {
            std::process::exit(1);
        }
        let _ = signal_tx.send(());
        #[cfg(unix)]
        wait_for_network_signal(&mut terminate).await;
        #[cfg(not(unix))]
        wait_for_network_signal().await;
        std::process::exit(1);
    });
    let result = mcp::server::run_server(app_state, async {
        let _ = shutdown_rx.recv().await;
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
