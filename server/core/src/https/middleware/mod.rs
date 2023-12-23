use axum::{
    headers::{authorization::Bearer, Authorization},
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
    TypedHeader,
};
use kanidm_proto::constants::{KOPID, KVERSION};
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
        .insert(KVERSION, HeaderValue::from_static(KANIDM_VERSION));
    response
}

#[derive(Clone, Debug)]
/// For holding onto the event ID and other handy request-based things
pub struct KOpId {
    /// The event correlation ID
    pub eventid: Uuid,
    /// The User Access Token, if present
    pub uat: Option<String>,
}

#[cfg(any(test, debug_assertions))]
/// This is a debug middleware to ensure that /v1/ endpoints only return JSON
#[instrument(level = "debug", name = "are_we_json_yet", skip_all)]
pub async fn are_we_json_yet<B>(request: Request<B>, next: Next<B>) -> Response {
    let uri = request.uri().path().to_string();

    let response = next.run(request).await;

    if uri.starts_with("/v1") && response.status().is_success() {
        let headers = response.headers();
        assert!(headers.contains_key(axum::http::header::CONTENT_TYPE));
        assert!(
            headers.get(axum::http::header::CONTENT_TYPE)
                == Some(&HeaderValue::from_static(
                    kanidm_proto::constants::APPLICATION_JSON
                ))
        );
    }

    response
}

/// This runs at the start of the request, adding an extension with `KOpId` which has useful things inside it.
#[instrument(level = "debug", name = "kopid_middleware", skip_all)]
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

    // This conversion *should never* fail. If it does, rather than panic, we warn and
    // just don't put the id in the response.
    let _ = HeaderValue::from_str(&eventid.as_hyphenated().to_string())
        .map(|hv| response.headers_mut().insert(KOPID, hv))
        .map_err(|err| {
            warn!(?err, "An invalid operation id was encountered");
        });

    response
}
