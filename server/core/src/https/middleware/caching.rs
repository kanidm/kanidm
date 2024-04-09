use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use axum_extra::headers::{CacheControl, HeaderMapExt};

/// Adds `no-cache max-age=0` to the response headers.
pub async fn dont_cache_me(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store no-cache max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    response
}

/// Adds a cache control header of 300 seconds to the response headers.
pub async fn cache_me(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let cache_header = CacheControl::new()
        .with_max_age(std::time::Duration::from_secs(300))
        .with_private();

    response.headers_mut().typed_insert(cache_header);
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    response
}
