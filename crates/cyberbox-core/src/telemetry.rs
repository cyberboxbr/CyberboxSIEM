use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialise the global tracing subscriber.
///
/// When `otlp_endpoint` is non-empty, spans are exported to the OTLP gRPC
/// endpoint (e.g. Jaeger / Grafana Tempo) in addition to stdout JSON logs.
/// If the OTLP exporter fails to initialise, the function falls back to
/// stdout-only logging and prints the error to stderr.
pub fn init(service_name: &str, otlp_endpoint: Option<&str>) {
    if let Some(endpoint) = otlp_endpoint.filter(|e| !e.is_empty()) {
        match init_with_otel(service_name, endpoint) {
            Ok(()) => return,
            Err(err) => {
                eprintln!("OTel exporter init failed ({err}); falling back to stdout-only logging");
            }
        }
    }
    init_stdout_only(service_name);
}

fn init_stdout_only(service_name: &str) {
    let filter = make_filter(service_name);
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .try_init();
}

fn init_with_otel(service_name: &str, endpoint: &str) -> anyhow::Result<()> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint),
        )
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                "service.name",
                service_name.to_owned(),
            )]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    // `install_batch` returns a `TracerProvider`; obtain the actual `Tracer` from it.
    let tracer = provider.tracer(service_name.to_owned());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(make_filter(service_name))
        .with(fmt::layer().with_target(true).json())
        .with(otel_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("subscriber init failed: {e}"))?;

    Ok(())
}

fn make_filter(service_name: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("{service_name}=info,tower_http=info,axum=info"))
    })
}
