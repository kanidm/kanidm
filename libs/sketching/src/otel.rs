use std::{str::FromStr, time::Duration};

use opentelemetry_otlp::{Protocol, WithExportConfig};

use opentelemetry::{global, trace::TracerProvider as _, KeyValue};

use opentelemetry_sdk::{
    trace::{Sampler, SdkTracerProvider},
    Resource,
};
use tracing::Subscriber;
use tracing_core::Level;

use tracing_subscriber::{filter::Directive, prelude::*, EnvFilter, Registry};

pub const MAX_EVENTS_PER_SPAN: u32 = 64 * 1024;
pub const MAX_ATTRIBUTES_PER_SPAN: u32 = 128;

use opentelemetry_semantic_conventions::{
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};

// TODO: this is coming back later
// #[allow(dead_code)]
// pub fn init_metrics() -> metrics::Result<MeterProvider> {
//     let export_config = opentelemetry_otlp::ExportConfig {
//         endpoint: "http://localhost:4318/v1/metrics".to_string(),
//         ..opentelemetry_otlp::ExportConfig::default()
//     };
//     opentelemetry_otlp::new_pipeline()
//         .metrics(opentelemetry_sdk::runtime::Tokio)
//         .with_exporter(
//             opentelemetry_otlp::new_exporter()
//                 .http()
//                 .with_export_config(export_config),
//         )
//         .build()
// }

/// This does all the startup things for the logging pipeline
pub fn start_logging_pipeline(
    otlp_endpoint: &Option<String>,
    log_filter: crate::LogLevel,
    service_name: &'static str,
) -> Result<(Option<SdkTracerProvider>, Box<dyn Subscriber + Send + Sync>), String> {
    let forest_filter: EnvFilter = EnvFilter::builder()
        .with_default_directive(log_filter.into())
        .from_env_lossy();

    // TODO: work out how to do metrics things
    match otlp_endpoint {
        Some(endpoint) => {
            // adding these filters because when you close out the process the OTLP comms layer is NOISY
            let forest_filter = forest_filter
                .add_directive(
                    Directive::from_str("tonic=info").expect("Failed to set tonic logging to info"),
                )
                .add_directive(
                    Directive::from_str("h2=info").expect("Failed to set h2 logging to info"),
                )
                .add_directive(
                    Directive::from_str("hyper=info").expect("Failed to set hyper logging to info"),
                );
            let forest_layer = tracing_forest::ForestLayer::default().with_filter(forest_filter);
            let t_filter: EnvFilter = EnvFilter::builder()
                .with_default_directive(log_filter.into())
                .from_env_lossy();

            let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
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

            let resource = Resource::builder()
                .with_schema_url(
                    [
                        // TODO: it'd be really nice to be able to set the instance ID here, from the server UUID so we know *which* instance on this host is logging
                        KeyValue::new(SERVICE_NAME, service_name),
                        KeyValue::new(SERVICE_VERSION, version),
                        KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, hostname),
                    ],
                    SCHEMA_URL,
                )
                .build();

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
                        .with_filter(t_filter),
                )
                // .with(MetricsLayer::new(meter_provider.clone()))
                .with(forest_layer)
                .with(OpenTelemetryLayer::new(
                    provider.tracer("tracing-otel-subscriber"),
                ));

            Ok((Some(provider_handle), Box::new(registry)))
        }
        None => {
            let forest_layer = tracing_forest::ForestLayer::default().with_filter(forest_filter);
            Ok((None, Box::new(Registry::default().with(forest_layer))))
        }
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
