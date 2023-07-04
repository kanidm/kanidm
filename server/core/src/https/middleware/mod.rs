use axum::{
    http::{self, Request},
    middleware::Next,
    response::Response,
    Extension,
};
use axum_sessions::SessionHandle;
use http::{HeaderMap, HeaderValue};
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
    #[allow(clippy::unwrap_used)]
    headers.insert(
        "X-KANIDM-VERSION",
        HeaderValue::from_str(KANIDM_VERSION).unwrap(),
    );

    response
}

#[derive(Clone, Debug)]
/// For holding onto the event ID and other handy request-based things
pub struct KOpId {
    pub eventid: Uuid,
    pub uat: Option<String>,
}

impl KOpId {
    /// Return the event ID as a string
    pub fn eventid_value(&self) -> String {
        let res = self.eventid;
        res.as_hyphenated().to_string()
    }
}

/// This runs at the start of the request, adding an extension with `KOpId` which has useful things inside it.
pub async fn kopid_start<B>(
    // TODO: try and make this into a TypedHeader - can't make it optional until at least axum 0.7.x - <https://github.com/tokio-rs/axum/issues/1781>
    // TODO: #1787: try this https://github.com/cuberoot74088/kanidm/commit/583d7634e8d38db3ba8e980f9d4d5b64c85df849
    headers: HeaderMap,
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    let eventid = sketching::tracing_forest::id();

    // get the bearer token from the headers or the session
    let uat = match headers
        .get("Authorization")
        .and_then(|hv| {
            // Get the first header value.
            hv.to_str().ok()
        })
        .and_then(|h| {
            // Turn it to a &str, and then check the prefix
            h.strip_prefix("Bearer ")
        })
        .map(|s| s.to_string())
    {
        Some(val) => Some(val),
        None => {
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
    request.extensions_mut().insert(KOpId {
        eventid,
        // eventid_value: value,
        uat,
    });
    next.run(request).await
}

/// This runs at the start of the request, adding an extension with the OperationID
pub async fn kopid_end<B>(
    Extension(kopid): Extension<KOpId>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // generate the event ID
    // insert the extension so we can pull it out later
    let mut response = next.run(request).await;

    #[allow(clippy::unwrap_used)]
    response.headers_mut().insert(
        "X-KANIDM-OPID",
        HeaderValue::from_str(&kopid.eventid_value()).unwrap(),
    );

    response
}
