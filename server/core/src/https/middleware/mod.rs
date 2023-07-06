use axum::{
    headers::{authorization::Bearer, Authorization},
    http::{self, Request},
    middleware::Next,
    response::Response,
    TypedHeader,
};
use axum_sessions::SessionHandle;
use http::HeaderValue;
use uuid::Uuid;

pub(crate) mod caching;
pub(crate) mod compression;
pub(crate) mod csp_headers;

// the version middleware injects
const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Injects a header into the response with "X-KANIDM-VERSION" matching the version of the package.
pub async fn version_middleware<B>(request: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-KANIDM-VERSION", HeaderValue::from_static(KANIDM_VERSION));
    response
}

#[derive(Clone, Debug)]
/// For holding onto the event ID and other handy request-based things
pub struct KOpId {
    pub eventid: Uuid,
    pub uat: Option<String>,
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

    // get the bearer token from the headers or the session
    let uat = match auth {
        Some(bearer) => Some(bearer.token().to_string()),
        None => {
            // no headers, let's try the cookies
            match request.extensions().get::<SessionHandle>() {
                Some(sess) => {
                    // we have a session!
                    sess.read().await.get::<String>("bearer")
                }
                None => None,
            }
        }
    };

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
