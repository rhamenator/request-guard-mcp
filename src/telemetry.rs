use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing subscriber.
pub fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "tracing initialized");
}

/// Gather Prometheus metrics as a text response body.
pub fn gather_metrics() -> String {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}
