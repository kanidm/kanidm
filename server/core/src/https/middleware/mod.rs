use axum::{
    http::{self, Request},
    middleware::Next,
    response::Response,
    Extension,
};
use http::{HeaderMap, HeaderValue};
use uuid::Uuid;

pub mod compression;

// the version middleware injects
const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Injects a header into the response with "X-KANIDM-VERSION" matching the version of the package.
pub async fn version_middleware<B>(request: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-KANIDM-VERSION",
        HeaderValue::from_str(KANIDM_VERSION).unwrap(),
    );

    response
}

#[derive(Clone)]
/// For holding onto the event ID
pub struct KOpId {
    pub eventid: Uuid,
    pub value: String,
    pub uat: Option<String>,
}

/// This runs at the start of the request, adding an extension with the OperationID
pub async fn kopid_start<B>(
    headers: HeaderMap,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    let eventid = sketching::tracing_forest::id();
    let value = eventid.as_hyphenated().to_string();

    let uat = headers
        .get("Authorization")
        .and_then(|hv| {
            // Get the first header value.
            hv.to_str().ok()
        })
        .and_then(|h| {
            // Turn it to a &str, and then check the prefix
            h.strip_prefix("Bearer ")
        })
        .map(|s| s.to_string());

    // insert the extension so we can pull it out later
    request.extensions_mut().insert(KOpId {
        eventid,
        value,
        uat,
    });
    next.run(request).await
}

/// This runs at the start of the request, adding an extension with the OperationID
pub async fn kopid_end<B>(
    // State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    // insert the extension so we can pull it out later
    let mut response = next.run(request).await;

    response.headers_mut().insert(
        "X-KANIDM-OPID",
        HeaderValue::from_str(&kopid.value).unwrap(),
    );

    response
}
