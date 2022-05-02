use kanidm::tracing_tree::TreeMiddleware;
use tide::Redirect;
use kanidm::be::Backend;

// TODO: look at the "push" functionality for prometheus
#[derive(Clone)]
struct MetricState {
    be: kanidm::be::Backend,
}

impl MetricState{
    pub fn new(be: Backend) -> Self {
        MetricState {
            be: be,
        }
    }
}

/// Starts the metrics server - but this won't block the entire platform if it fails.
pub fn create_metrics_server(
    be: Backend,
    address: String) -> Result<(), ()> {
    debug!(
        "Attempting to start the metrics listener on address: {}",
        &address
    );

    let mut metrics_server = tide::with_state(
        MetricState::new(be));
    metrics_server.with(TreeMiddleware::with_stdout());
    // because it's just nice, y'know
    metrics_server.at("/").get(Redirect::permanent("/metrics"));
    metrics_server.at("/metrics")
        .get(|req: tide::Request<MetricState>| async move {
            let encoded: Vec<u8> = req.state().be.get_metrics_encoded();
            let response = tide::Response::builder(200)
                .body(encoded)
                .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
                .build();
            Ok(response)
        });
    tokio::spawn(async move {
        if let Err(e) = metrics_server.listen(&address).await {
            error!(
                "Failed to start metrics listener on address {:?} -> {:?}",
                &address, e,
            );
        }
    });

    Ok(())
}
