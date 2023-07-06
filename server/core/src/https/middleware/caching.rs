use axum::{
    http::{self, Request},
    middleware::Next,
    response::Response,
};

/// Adds `no-cache max-age=0` to the response headers.
pub async fn dont_cache_me<B>(request: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store no-cache max-age=0"),
    );
    response.headers_mut().insert(
        http::header::PRAGMA,
        http::HeaderValue::from_static("no-cache"),
    );

    response
}
