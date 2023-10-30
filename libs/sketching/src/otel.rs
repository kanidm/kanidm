use opentelemetry::trace::{SpanId, TraceId};
use opentelemetry::{metrics, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::MeterProvider;
use opentelemetry_sdk::trace::{self, IdGenerator, Sampler};
use opentelemetry_sdk::Resource;
use rand::Rng;
use std::cell::RefCell;
use std::time::Duration;
use tracing_subscriber::Registry;
use tracing_subscriber::{prelude::*, EnvFilter};

pub const MAX_EVENTS_PER_SPAN: u32 = 64;
pub const MAX_ATTRIBUTES_PER_SPAN: u32 = 32;

/// if you set the OTLP_ENDPOINT env var you can send this elsewhere
pub fn get_otlp_endpoint() -> Option<String> {
    std::env::var("OTLP_ENDPOINT").ok()
    //.unwrap_or_else(|_| "http://localhost:4317".to_string())
}

#[allow(dead_code)]
pub fn init_metrics() -> metrics::Result<MeterProvider> {
    let export_config = opentelemetry_otlp::ExportConfig {
        endpoint: "http://localhost:4318/v1/metrics".to_string(),
        ..opentelemetry_otlp::ExportConfig::default()
    };
    opentelemetry_otlp::new_pipeline()
        .metrics(opentelemetry_sdk::runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .http()
                .with_export_config(export_config),
        )
        .build()
}

/// This does all the bootup things
pub fn startup_opentelemetry(
    otlp_endpoint: Option<String>,
    log_filter: crate::LogLevel,
) -> Result<(), String> {
    // if let Some(endpoint) = otlp_endpoint {
    // let tracer = opentelemetry_otlp::new_pipeline().tracing().with_exporter(
    //     opentelemetry_otlp::new_exporter()
    //         .tonic()
    //         .with_endpoint(&endpoint)
    //         .with_timeout(Duration::from_secs(5))
    //         .with_protocol(Protocol::HttpBinary),
    // );

    // let tracer = tracer
    //     .with_trace_config(
    //         trace::config()
    //             // we want *everything!*
    //             .with_sampler(Sampler::AlwaysOn)
    //             .with_id_generator(TraceIdGenerator::default()) // TODO: this should be a uuidvr
    //             .with_max_events_per_span(MAX_EVENTS_PER_SPAN)
    //             .with_max_attributes_per_span(MAX_ATTRIBUTES_PER_SPAN)
    //             .with_resource(Resource::new(vec![KeyValue::new(
    //                 "service.name",
    //                 "kanidmd",
    //             )])),
    //     )
    //     .install_batch(opentelemetry::runtime::Tokio)
    //     .map_err(|err| eprintln!("Failed to start OTLP pipeline: {:?}", err))?;
    // Create a tracing layer with the configured tracer;
    // }

    let forest_filter: EnvFilter = log_filter.into();
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

            let tracer = tracer
                .with_trace_config(
                    trace::config()
                        // we want *everything!*
                        .with_sampler(Sampler::AlwaysOn)
                        .with_id_generator(TraceIdGenerator::default()) // TODO: this should be a uuidvr
                        .with_max_events_per_span(MAX_EVENTS_PER_SPAN)
                        .with_max_attributes_per_span(MAX_ATTRIBUTES_PER_SPAN)
                        .with_resource(Resource::new(vec![KeyValue::new(
                            "service.name",
                            "kanidmd",
                        )])),
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

            let subscriber = Registry::default().with(forest_layer).with(telemetry);
            tracing::subscriber::set_global_default(subscriber).unwrap();
        }
        None => {
            let subscriber = Registry::default().with(forest_layer);
            tracing::subscriber::set_global_default(subscriber).unwrap();
        }
    };

    Ok(())
}

#[derive(Clone, Debug, Default)]
/// This generates trace IDs for traces/spans
struct TraceIdGenerator {
    _private: (),
}

impl IdGenerator for TraceIdGenerator {
    fn new_trace_id(&self) -> TraceId {
        uuid::Uuid::new_v4().as_u128().into()
        // CURRENT_RNG.with(|rng| TraceId::from(rng.borrow_mut().gen::<u128>()))
    }

    fn new_span_id(&self) -> SpanId {
        CURRENT_RNG.with(|rng| SpanId::from(rng.borrow_mut().gen::<u64>()))
    }
}

thread_local! {
    /// Store random number generator for each thread
    static CURRENT_RNG: RefCell<rand::rngs::ThreadRng> = RefCell::new(rand::rngs::ThreadRng::default());
}
