use axum::{
    extract::State,
    http::{self, Request},
    middleware::Next,
    response::Response,
    Extension,
};
use http::{HeaderMap, HeaderValue};
use uuid::Uuid;

use super::ServerState;

pub mod compression;

// TODO: version middleware
// the version middleware injects

const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn version_middleware<B>(request: Request<B>, next: Next<B>) -> Response {
    // do something with `request`...

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
    State(state): State<ServerState>,
    headers: HeaderMap,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    let (eventid, value) = state.new_eventid();
    // insert the extension so we can pull it out later
    request.extensions_mut().insert(KOpId {
        eventid,
        value,
        uat: state.get_current_uat(headers),
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
