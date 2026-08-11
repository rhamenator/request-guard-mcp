use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing subscriber.
pub fn init_tracing(
    log_level: &str,
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> Result<Option<SdkTracerProvider>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let provider = if let Some(endpoint) = otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .context("failed to build configured OTLP trace exporter")?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_service_name(service_name.to_string())
                    .build(),
            )
            .build();
        let tracer = provider.tracer(service_name.to_string());
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("failed to initialize tracing subscriber")?;
        Some(provider)
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .try_init()
            .context("failed to initialize tracing subscriber")?;
        None
    };

    info!(version = env!("CARGO_PKG_VERSION"), "tracing initialized");
    Ok(provider)
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
