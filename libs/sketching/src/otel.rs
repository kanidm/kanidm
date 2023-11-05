use gethostname::gethostname;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::trace::{self, Sampler};
use opentelemetry_sdk::Resource;
use std::time::Duration;
use tracing::Subscriber;
use tracing_subscriber::Registry;
use tracing_subscriber::{prelude::*, EnvFilter};

pub const MAX_EVENTS_PER_SPAN: u32 = 64 * 1024;
pub const MAX_ATTRIBUTES_PER_SPAN: u32 = 128;

/// if you set the KANIDM_OTEL_GRPC_ENDPOINT env var you'll start the OpenTelemetry pipeline.
pub fn get_otlp_endpoint() -> Option<String> {
    std::env::var("KANIDM_OTEL_GRPC_ENDPOINT").ok()
}

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
    otlp_endpoint: Option<String>,
    log_filter: crate::LogLevel,
    service_name: String,
) -> Result<Box<dyn Subscriber + Send + Sync>, String> {
    let forest_filter: EnvFilter = log_filter.into();

    // adding these filters because when you close out the process the OTLP comms layer is NOISY
    let forest_filter = forest_filter
        .add_directive(
            "tonic=info"
                .parse()
                .expect("Failed to set tonic logging to info"),
        )
        .add_directive("h2=info".parse().expect("Failed to set h2 logging to info"))
        .add_directive(
            "hyper=info"
                .parse()
                .expect("Failed to set hyper logging to info"),
        );
    let forest_layer = tracing_forest::ForestLayer::default().with_filter(forest_filter);

    // TODO: work out how to do metrics things
    // let meter_provider = init_metrics()
    //     .map_err(|err| eprintln!("failed to start metrics provider: {:?}", err))?;

    match otlp_endpoint {
        Some(endpoint) => {
            let t_filter: EnvFilter = log_filter.into();

            let tracer = opentelemetry_otlp::new_pipeline().tracing().with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint)
                    .with_timeout(Duration::from_secs(5))
                    .with_protocol(Protocol::HttpBinary),
            );

            // this env var gets set at build time, if we can pull it, add it to the metadata
            let git_rev = match option_env!("KANIDM_KANIDM_PKG_COMMIT_REV") {
                Some(rev) => format!("-{}", rev),
                None => "".to_string(),
            };

            let version = format!("{}{}", env!("CARGO_PKG_VERSION"), git_rev);
            let hostname = gethostname();
            let hostname = hostname.to_string_lossy();
            let hostname = hostname.to_lowercase();

            let tracer = tracer
                .with_trace_config(
                    trace::config()
                        // we want *everything!*
                        .with_sampler(Sampler::AlwaysOn)
                        .with_max_events_per_span(MAX_EVENTS_PER_SPAN)
                        .with_max_attributes_per_span(MAX_ATTRIBUTES_PER_SPAN)
                        .with_resource(Resource::new(vec![
                            KeyValue::new("service.name", service_name),
                            KeyValue::new("service.version", version),
                            KeyValue::new("host.name", hostname),
                            // TODO: it'd be really nice to be able to set the instance ID here, from the server UUID so we know *which* instance on this host is logging
                        ])),
                )
                .install_batch(opentelemetry::runtime::Tokio)
                .map_err(|err| {
                    let err = format!("Failed to start OTLP pipeline: {:?}", err);
                    eprintln!("{}", err);
                    err
                })?;
            // Create a tracing layer with the configured tracer;
            let telemetry = tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_threads(true)
                .with_filter(t_filter);

            Ok(Box::new(
                Registry::default().with(forest_layer).with(telemetry),
            ))
        }
        None => Ok(Box::new(Registry::default().with(forest_layer))),
    }
}

/// This helps with cleanly shutting down the tracing/logging providers when done,
/// so we don't lose traces.
pub struct TracingPipelineGuard {}

impl Drop for TracingPipelineGuard {
    fn drop(&mut self) {
        opentelemetry::global::shutdown_tracer_provider();
        opentelemetry::global::shutdown_logger_provider();
        println!("Logging pipeline completed shutdown");
    }
}
