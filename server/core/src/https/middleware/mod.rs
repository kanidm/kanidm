use crate::https::extractors::ClientConnInfo;
use crate::https::ServerState;
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, State},
    http::{header::HeaderName, StatusCode},
    http::{HeaderValue, Request},
    middleware::Next,
    response::Response,
    RequestExt,
};
use kanidm_proto::constants::{KOPID, KVERSION, X_FORWARDED_FOR};
use std::net::IpAddr;
use uuid::Uuid;

#[allow(clippy::declare_interior_mutable_const)]
const X_FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static(X_FORWARDED_FOR);

pub(crate) mod caching;
pub(crate) mod compression;
pub(crate) mod hsts_header;
pub(crate) mod security_headers;

// the version middleware injects
const KANIDM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Injects a header into the response with "X-KANIDM-VERSION" matching the version of the package.
pub async fn version_middleware(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(KVERSION, HeaderValue::from_static(KANIDM_VERSION));
    response
}

#[cfg(any(test, debug_assertions))]
/// This is a debug middleware to ensure that /v1/ endpoints only return JSON
#[instrument(level = "trace", name = "are_we_json_yet", skip_all)]
pub async fn are_we_json_yet(request: Request<Body>, next: Next) -> Response {
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

#[derive(Clone, Debug)]
/// For holding onto the event ID and other handy request-based things
pub struct KOpId {
    /// The event correlation ID
    pub eventid: Uuid,
}

/// This runs at the start of the request, adding an extension with `KOpId` which has useful things inside it.
#[instrument(level = "trace", name = "kopid_middleware", skip_all)]
pub async fn kopid_middleware(mut request: Request<Body>, next: Next) -> Response {
    // generate the event ID
    let eventid = sketching::tracing_forest::id();

    // insert the extension so we can pull it out later
    request.extensions_mut().insert(KOpId { eventid });
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

// This middleware extracts the ip_address and client information, and stores it
// in the request extensions for future layers to use it.
pub async fn ip_address_middleware(
    State(state): State<ServerState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match ip_address_middleware_inner(&state, &mut request).await {
        Ok(trusted_client_ip) => {
            request.extensions_mut().insert(trusted_client_ip);
            next.run(request).await
        }
        Err((status_code, reason)) => {
            // Worst case, return.
            let mut response = Response::new(Body::from(reason));
            *response.status_mut() = status_code;
            response
        }
    }
}

async fn ip_address_middleware_inner(
    state: &ServerState,
    request: &mut Request<Body>,
) -> Result<ClientConnInfo, (StatusCode, &'static str)> {
    // Extract the IP and insert it to the request.
    let ConnectInfo(ClientConnInfo {
        connection_addr,
        client_ip_addr,
        client_cert,
    }) = request
        .extract_parts::<ConnectInfo<ClientConnInfo>>()
        .await
        .map_err(|_| {
            error!("Connect info contains invalid data");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "connect info contains invalid data",
            )
        })?;

    let connection_ip_addr = connection_addr.ip();

    let trust_x_forward_for = state
        .trust_x_forward_for_ips
        .as_ref()
        .map(|range| range.contains(&connection_ip_addr))
        .unwrap_or_default();

    let client_ip_addr = if trust_x_forward_for {
        if let Some(x_forward_for) = request.headers().get(X_FORWARDED_FOR_HEADER) {
            // X forward for may be comma separated.
            let first = x_forward_for
                .to_str()
                .map(|s|
                    // Split on an optional comma, return the first result.
                    s.split(',').next().unwrap_or(s))
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "X-Forwarded-For contains invalid data",
                    )
                })?;

            first.parse::<IpAddr>().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "X-Forwarded-For contains invalid ip addr",
                )
            })?
        } else {
            client_ip_addr
        }
    } else {
        // This can either be the client_addr == connection_addr if there are
        // no ip address trust sources, or this is the value as reported by
        // proxy protocol header. If the proxy protocol header is used, then
        // trust_x_forward_for can never have been true so we catch here.
        client_ip_addr
    };

    Ok(ClientConnInfo {
        connection_addr,
        client_ip_addr,
        client_cert,
    })
}
