use axum::{
    headers::{authorization::Bearer, Authorization},
    http::{self, Request},
    middleware::Next,
    response::Response,
    TypedHeader,
};
#[cfg(debug_assertions)]
use http::header::CONTENT_TYPE;
use http::HeaderValue;
use uuid::Uuid;

pub(crate) mod caching;
pub(crate) mod compression;
pub(crate) mod hsts_header;
pub(crate) mod security_headers;

// the version middleware injects
const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Injects a header into the response with "X-KANIDM-VERSION" matching the version of the package.
pub async fn version_middleware<B>(request: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("X-KANIDM-VERSION", HeaderValue::from_static(KANIDM_VERSION));
    response
}

#[derive(Clone, Debug)]
/// For holding onto the event ID and other handy request-based things
pub struct KOpId {
    pub eventid: Uuid,
    pub uat: Option<String>,
}

/// Ensure the status code is 200..=299
#[cfg(debug_assertions)]
fn from_200_to_299(status: http::StatusCode) -> bool {
    status.as_u16() >= 200 && status.as_u16() <= 299
}

#[test]
fn test_from_200_to_299() {
    assert!(from_200_to_299(http::StatusCode::OK));
    assert!(from_200_to_299(http::StatusCode::IM_USED));
    assert!(!from_200_to_299(http::StatusCode::BAD_REQUEST));
    assert!(!from_200_to_299(http::StatusCode::INTERNAL_SERVER_ERROR));
}

#[cfg(debug_assertions)]
/// This is a debug middleware to ensure that /v1/ endpoints only return JSON
#[instrument(name = "are_we_json_yet", skip_all)]
pub async fn are_we_json_yet<B>(request: Request<B>, next: Next<B>) -> Response {
    let uri = request.uri().path().to_string();

    let response = next.run(request).await;

    if uri.starts_with("/v1") && from_200_to_299(response.status()) {
        let headers = response.headers();
        assert!(headers.contains_key(CONTENT_TYPE));
        dbg!(headers.get(CONTENT_TYPE));
        assert!(
            headers.get(CONTENT_TYPE)
                == Some(&HeaderValue::from_static(crate::https::APPLICATION_JSON))
        );
    }

    response
}

/// This runs at the start of the request, adding an extension with `KOpId` which has useful things inside it.
#[instrument(name = "request", skip_all)]
pub async fn kopid_middleware<B>(
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    let eventid = sketching::tracing_forest::id();

    // get the bearer token from the headers if present.
    let uat = auth.map(|bearer| bearer.token().to_string());

    // insert the extension so we can pull it out later
    request.extensions_mut().insert(KOpId { eventid, uat });
    let mut response = next.run(request).await;

    #[allow(clippy::unwrap_used)]
    response.headers_mut().insert(
        "X-KANIDM-OPID",
        HeaderValue::from_str(&eventid.as_hyphenated().to_string()).unwrap(),
    );

    response
}
