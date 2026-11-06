use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

use crate::https::ServerState;

// once the http crate has them built in, those can be used instead
const COEP_NAME: &str = "cross-origin-embedder-policy";
const COOP_NAME: &str = "cross-origin-opener-policy";
const CORP_NAME: &str = "cross-origin-resource-policy";

const COEP_VALUE: &str = "require-corp";
const COOP_VALUE: &str = "same-origin";
const CORP_VALUE: &str = "same-origin";
const HSTS_VALUE: &str = "max-age=63072001"; // 2 years + 1 second
const PERMISSIONS_POLICY_VALUE: &str = "fullscreen=(), geolocation=()";
const X_CONTENT_TYPE_OPTIONS_VALUE: &str = "nosniff";

pub async fn security_headers_layer(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // wait for the middleware to come back
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // add the Content-Security-Policy header, which defines how contact will be accessed/run based on the source URL
    // Only update the CSP if none is present. This allows some routes to opt into defining their own CSP
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(header::CONTENT_SECURITY_POLICY, state.csp_header);
    }

    // X-Content-Type-Options tells the browser if it's OK to "sniff" or guess the content type of a response
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
    // https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static(X_CONTENT_TYPE_OPTIONS_VALUE),
    );

    // Permissions policy defines access to platform services like geolocation, fullscreen etc.
    //
    // https://www.w3.org/TR/permissions-policy-1/
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(PERMISSIONS_POLICY_VALUE),
    );

    // Don't send a referrer header when the user is navigating to a non-HTTPS URL
    // Ref:
    // https://scotthelme.co.uk/a-new-security-header-referrer-policy/
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("origin"));

    // Request the browser to only load this site via HTTPS in the future
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security
    response.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static(HSTS_VALUE),
    );

    // Restrict loading of external resources to ones having properly set CORP and/or CORS
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy
    response.headers_mut().insert(
        HeaderName::from_static(COEP_NAME),
        HeaderValue::from_static(COEP_VALUE),
    );

    // Isolate windows opened with JavaScript from other sites
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy
    response.headers_mut().insert(
        HeaderName::from_static(COOP_NAME),
        HeaderValue::from_static(COOP_VALUE),
    );

    // Require browsers loading our resources to use CORS
    //
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy
    response.headers_mut().insert(
        HeaderName::from_static(CORP_NAME),
        HeaderValue::from_static(CORP_VALUE),
    );

    response
}

pub async fn csp_header_no_form_action_layer(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        state.csp_header_no_form_action,
    );

    response
}
