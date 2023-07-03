use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum_csp::*;

pub async fn cspheaders_layer<B>(request: Request<B>, next: Next<B>) -> Response {
    let directive: CspDirective = CspDirective {
        directive_type: CspDirectiveType::ImgSrc,
        values: vec![
            CspValue::SelfSite,
            CspValue::SchemeHttps,
            CspValue::SchemeData,
        ],
    };

    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the header
    let headers = response.headers_mut();
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_str(&directive.to_string()).unwrap(),
    );

    response
}

/// Removes the CSP headers from the response
pub async fn strip_csp_headers<B>(request: Request<B>, next: Next<B>) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the header
    let headers = response.headers_mut();
    headers.remove("Content-Security-Policy");

    response
}
