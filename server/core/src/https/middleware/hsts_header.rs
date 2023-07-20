use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::HeaderValue;

const HSTS_HEADER: &str = "max-age=86400";

pub async fn strict_transport_security_layer<B>(request: Request<B>, next: Next<B>) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the header
    let headers = response.headers_mut();
    let hsts_header = HeaderValue::from_static(HSTS_HEADER);

    headers.insert("Strict-Transport-Security", hsts_header);

    response
}
