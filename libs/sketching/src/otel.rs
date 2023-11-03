use opentelemetry::{metrics, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::MeterProvider;
use opentelemetry_sdk::trace::{self, Sampler};
use opentelemetry_sdk::Resource;
use std::time::Duration;
use tracing::Subscriber;
use tracing_subscriber::Registry;
use tracing_subscriber::{prelude::*, EnvFilter};

pub const MAX_EVENTS_PER_SPAN: u32 = 64 * 1024;
pub const MAX_ATTRIBUTES_PER_SPAN: u32 = 128;

// TODO: for some reason this doesn't show the response data at the end of the trace?

/// if you set the KANIDM_OTEL_GRPC_ENDPOINT env var you'll start the OpenTelemetry pipeline.
pub fn get_otlp_endpoint() -> Option<String> {
    std::env::var("KANIDM_OTEL_GRPC_ENDPOINT").ok()
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
) -> Result<Box<dyn Subscriber + Send + Sync>, String> {
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
                        // .with_id_generator(TraceIdGenerator::default()) // TODO: this should be a uuidv4
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

            Ok(Box::new(
                Registry::default().with(forest_layer).with(telemetry),
            ))
            // tracing::subscriber::set_global_default(subscriber).unwrap();
        }
        None => {
            Ok(Box::new(Registry::default().with(forest_layer)))
            // tracing::subscriber::set_global_default(subscriber).unwrap();
        }
    }
}

// pub async fn on<F: Future>(self, f: F) -> F::Output {
//     let (shutdown_tx, mut shutdown_rx) = tokio::mponeshot::channel();
//     let processor = self.worker_processor.0;
//     let mut receiver = self.receiver;

//     // this does the processor bit
//     let handle = tokio::spawn(async move {
//         loop {
//             tokio::select! {
//                 Some(tree) = receiver.recv() => processor.process(tree).expect(fail::PROCESSING_ERROR),
//                 Ok(()) = &mut shutdown_rx => break,
//                 else => break,
//             }
//         }

//         receiver.close();

//         // Drain any remaining logs in the channel buffer.
//         while let Ok(tree) = receiver.try_recv() {
//             processor.process(tree).expect(fail::PROCESSING_ERROR);
//         }
//     });

//     // this waits for the function
//     let output = {
//         let _guard = if self.is_global {
//             tracing::subscriber::set_global_default(self.subscriber)
//                 .expect("global default already set");
//             None
//         } else {
//             Some(tracing::subscriber::set_default(self.subscriber))
//         };

//         f.await
//     };

//     shutdown_tx
//         .send(())
//         .expect("Shutdown signal couldn't send, this is a bug");

//     handle
//         .await
//         .expect("Failed to join the writing task, this is a bug");

//     output
// }
