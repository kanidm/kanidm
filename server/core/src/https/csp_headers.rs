use axum::extract::State;
use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum_csp::*;

use super::ServerState;

// #[axum_macros::debug_handler]
pub async fn cspheaders_layer<B>(
    State(_state): State<ServerState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
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
