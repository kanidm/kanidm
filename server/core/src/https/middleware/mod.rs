use axum::{
    http::{self, Request},
    response::Response,
    middleware::Next,
};
use http::HeaderValue;


pub mod compression;

// TODO: version middleware
// the version middleware injects

const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");


pub async fn version_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // do something with `request`...

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-KANIDM-VERSION", HeaderValue::from_str(KANIDM_VERSION).unwrap());

    response
}
