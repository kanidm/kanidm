use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

const HSTS_HEADER: &str = "max-age=86400";

pub async fn strict_transport_security_layer(request: Request<Body>, next: Next) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the header
    response.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static(HSTS_HEADER),
    );

    response
}
