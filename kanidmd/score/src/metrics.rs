use tide::Redirect;
use kanidm::tracing_tree::TreeMiddleware;


/// Starts the metrics server - but this won't block the entire platform if it fails.
pub fn create_metrics_server(
    address: String,
) -> Result<(), ()> {
    debug!("Attempting to start the metrics listener on address: {}", &address);

    let mut metrics_server = tide::new();
    metrics_server.with(TreeMiddleware::with_stdout());
    // because it's just nice, y'know
    metrics_server.at("/").get(Redirect::temporary("/metrics"));
    metrics_server.at("/metrics").get(tide_prometheus::metrics_endpoint);

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