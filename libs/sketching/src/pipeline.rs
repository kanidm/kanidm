use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::{
    tonic_types::metadata::MetadataMap, Protocol, WithExportConfig, WithTonicConfig,
};
use opentelemetry_sdk::{
    trace::{Sampler, SdkTracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions::{
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use std::str::FromStr;
use std::time::Duration;
use tracing::Subscriber;
use tracing_core::Level;
use tracing_subscriber::{filter::Directive, prelude::*, EnvFilter, Registry};

const MAX_EVENTS_PER_SPAN: u32 = 64 * 1024;
const MAX_ATTRIBUTES_PER_SPAN: u32 = 128;

/// This does all the startup things for the logging pipeline
pub fn start_logging_pipeline(
    otlp_endpoint: &Option<String>,
    log_filter: crate::LogLevel,
) -> Result<(Option<SdkTracerProvider>, Box<dyn Subscriber + Send + Sync>), String> {
    // Always force the event span to be generated at the correct level, regardless
    // of what the user set.
    let kanidmd_core_directives = [
        Directive::from_str("kanidmd_core::https::trace=info")
            .map_err(|err| format!("Invalid directive during log setup: {}", err))?,
        Directive::from_str("kanidmd_core::https::middleware=info")
            .map_err(|err| format!("Invalid directive during log setup: {}", err))?,
    ];

    let mut logging_filter = EnvFilter::builder()
        .with_default_directive(log_filter.into())
        .parse("")
        .map_err(|err| format!("Failed to create OTEL logging filter: {}", err))?;
    for directive in kanidmd_core_directives.iter() {
        logging_filter = logging_filter.add_directive(directive.clone());
    }
    logging_filter = logging_filter
        // tell the tonic/grpc/h2 layers to trace at warn, so we can see connectivity issues
        .add_directive(
            Directive::from_str("tonic=warn")
                .map_err(|err| format!("Failed to set tonic logging to warn: {}", err))?,
        )
        .add_directive(
            Directive::from_str("hyper=warn")
                .map_err(|err| format!("Failed to set hyper logging to warn: {}", err))?,
        )
        .add_directive(
            Directive::from_str("h2=warn")
                .map_err(|err| format!("Failed to set h2 logging to warn: {}", err))?,
        )
        .add_directive(
            Directive::from_str("h2::proto::streams::prioritize=warn").map_err(|err| {
                format!(
                    "Failed to set h2::proto::streams::prioritize logging to warn: {}",
                    err
                )
            })?,
        );

    eprintln!(
        "Logging filter initialized: {:?}",
        logging_filter.to_string()
    );

    // TODO: work out how to do metrics things
    if let Some(endpoint) = otlp_endpoint {
        eprintln!("Starting OTLP logging pipeline endpoint={}", endpoint);

        // setup metadata so we can auth to third-party services
        let mut tonic_metadata = MetadataMap::new();

        if let Some(headers) = std::env::var_os("OTEL_EXPORTER_OTLP_HEADERS") {
            let headers = headers.to_string_lossy();
            for header in headers.split(',') {
                if let Some((key, value)) = header.split_once('=') {
                    if !key.is_empty() && key.eq_ignore_ascii_case("authorization") {
                        if let Ok(header_value) = tonic::metadata::MetadataValue::from_str(value) {
                            tonic_metadata.insert("authorization", header_value);
                        } else {
                            eprintln!(
                            "Warning: could not parse OTEL_EXPORTER_OTLP_HEADERS environment variable, skipping this: {}", header
                        );
                        };
                    }
                }
            }
        }
        let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_metadata(tonic_metadata)
            .with_protocol(Protocol::HttpBinary)
            .with_timeout(Duration::from_secs(5))
            .build()
            .map_err(|err| err.to_string())?;

        // this env var gets set at build time, if we can pull it, add it to the metadata
        let git_rev = match option_env!("KANIDM_PKG_COMMIT_REV") {
            Some(rev) => format!("-{rev}"),
            None => "".to_string(),
        };

        let version = format!("{}{}", env!("CARGO_PKG_VERSION"), git_rev);
        let hostname = gethostname::gethostname();
        let hostname = hostname.to_string_lossy();
        let hostname = hostname.to_lowercase();

        let mut resource = Resource::builder().with_schema_url(
            [
                // TODO: it'd be really nice to be able to set the instance ID here, from the server UUID so we know *which* instance on this host is logging
                KeyValue::new(SERVICE_VERSION, version),
                KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, hostname),
            ],
            SCHEMA_URL,
        );

        // only set the service name if it's not already set in the environment because the SDK defaults to "unknown_service"
        if std::env::var("OTEL_SERVICE_NAME").is_err() {
            resource = resource.with_service_name("kanidmd");
        }
        let resource = resource.build();

        let provider = opentelemetry_sdk::trace::TracerProviderBuilder::default()
            .with_batch_exporter(otlp_exporter)
            // we want *everything!*
            .with_sampler(Sampler::AlwaysOn)
            .with_max_events_per_span(MAX_EVENTS_PER_SPAN)
            .with_max_attributes_per_span(MAX_ATTRIBUTES_PER_SPAN)
            .with_resource(resource)
            .build();

        let provider_handle = provider.clone();

        global::set_tracer_provider(provider.clone());
        provider.tracer("tracing-otel-subscriber");
        use tracing_opentelemetry::OpenTelemetryLayer;

        let registry = tracing_subscriber::registry()
            .with(
                tracing_subscriber::filter::LevelFilter::from_level(Level::INFO)
                    .with_filter(logging_filter.clone()),
            )
            .with(
                OpenTelemetryLayer::new(provider.tracer("tracing-otel-subscriber"))
                    .with_filter(logging_filter),
            );

        Ok((Some(provider_handle), Box::new(registry)))
    } else {
        let forest_layer = tracing_forest::ForestLayer::default().with_filter(logging_filter);
        Ok((None, Box::new(Registry::default().with(forest_layer))))
    }
}

/// This helps with cleanly shutting down the tracing/logging providers when done,
/// so we don't lose traces.
pub struct TracingPipelineGuard(pub Option<SdkTracerProvider>);

impl Drop for TracingPipelineGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take() {
            if let Err(err) = provider.shutdown() {
                eprintln!("Error shutting down logging pipeline: {}", err);
            } else {
                eprintln!("Logging pipeline completed shutdown");
            }
        }
    }
}
