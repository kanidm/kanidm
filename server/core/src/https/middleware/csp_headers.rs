use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::https::ServerState;

pub async fn cspheaders_layer<B>(
    State(state): State<ServerState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the header
    let headers = response.headers_mut();
    headers.insert("Content-Security-Policy", state.csp_header);

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
