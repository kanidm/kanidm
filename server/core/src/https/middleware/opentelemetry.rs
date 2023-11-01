use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry_api::trace::get_active_span;
use opentelemetry_api::KeyValue;

#[instrument(skip_all, fields(http.status_code))]
pub async fn opentelemetry_layer<B>(request: Request<B>, next: Next<B>) -> Response {
    // wait for the middleware to come back
    let response = next.run(request).await;

    let status_code = response.status();

    get_active_span(|span| {
        span.set_attribute(KeyValue::new(
            "http.status_code",
            status_code.as_u16() as i64,
        ));
    });

    response
}
