use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::header::X_CONTENT_TYPE_OPTIONS;
use http::HeaderValue;

use crate::https::ServerState;

const PERMISSIONS_POLICY_VALUE: &str = "fullscreen=(), geolocation=()";
const X_CONTENT_TYPE_OPTIONS_VALUE: &str = "nosniff";

pub async fn security_headers_layer<B>(
    State(state): State<ServerState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    // add the Content-Security-Policy header, which defines how contact will be accessed/run based on the source URL
    let headers = response.headers_mut();
    headers.insert(http::header::CONTENT_SECURITY_POLICY, state.csp_header);

    // X-Content-Type-Options tells the browser if it's OK to "sniff" or guess the content type of a response
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
    // https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options
    #[allow(clippy::expect_used)]
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_str(X_CONTENT_TYPE_OPTIONS_VALUE)
            .expect("Failed to generate security header X-Content-Type-Options"),
    );

    // Permissions policy defines access to platform services like geolocation, fullscreen etc.
    //
    // https://www.w3.org/TR/permissions-policy-1/
    #[allow(clippy::expect_used)]
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_str(PERMISSIONS_POLICY_VALUE)
            .expect("Failed to generate security header Permissions-Policy"),
    );

    // Don't send a referrer header when the user is navigating to a non-HTTPS URL
    // Ref:
    // https://scotthelme.co.uk/a-new-security-header-referrer-policy/
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
    #[allow(clippy::expect_used)]
    headers.insert(
        http::header::REFERRER_POLICY,
        HeaderValue::from_str("no-referrer-when-downgrade")
            .expect("Failed to generate Referer-Policy header"),
    );

    response
}
