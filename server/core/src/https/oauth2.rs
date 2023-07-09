use super::middleware::KOpId;
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::{to_axum_response, ServerState};
use axum::extract::{Path, Query, State};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, LOCATION,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper::Body;
use kanidm_proto::oauth2::AuthorisationResponse;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenRequest, AuthorisationRequest, AuthorisePermitSuccess,
    AuthoriseResponse, ErrorResponse, Oauth2Error, TokenRevokeRequest,
};
use kanidmd_lib::prelude::f_eq;
use kanidmd_lib::prelude::*;
use kanidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};

// == Oauth2 Configuration Endpoints ==

/// List all the OAuth2 Resource Servers
pub async fn oauth2_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(
        "class",
        PartialValue::new_class("oauth2_resource_server")
    ));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn oauth2_basic_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "oauth2_resource_server".to_string(),
        "oauth2_resource_server_basic".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn oauth2_public_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "oauth2_resource_server".to_string(),
        "oauth2_resource_server_public".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

fn oauth2_id(rs_name: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("oauth2_resource_server")),
        f_eq("oauth2_rs_name", PartialValue::new_iname(rs_name))
    ]))
}

pub async fn oauth2_id_get(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

#[instrument(level = "info", skip(state))]
pub async fn oauth2_id_get_basic_secret(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_r_ref
        .handle_oauth2_basic_secret_read(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_patch(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);

    let res = state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_scopemap_update(kopid.uat, group, scopes, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_scopemap_delete(kopid.uat, group, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_sup_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_update(kopid.uat, group, scopes, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_sup_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_delete(kopid.uat, group, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn oauth2_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
) -> impl IntoResponse {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_internaldelete(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

// == OAUTH2 PROTOCOL FLOW HANDLERS ==
//
// oauth2 (partial)
// https://tools.ietf.org/html/rfc6749
// oauth2 pkce
// https://tools.ietf.org/html/rfc7636
//
// TODO
// oauth2 token introspection
// https://tools.ietf.org/html/rfc7662
// oauth2 bearer token
// https://tools.ietf.org/html/rfc6750
//
// From https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
//
//       +----------+
//       | Resource |
//       |   Owner  |
//       |          |
//       +----------+
//            ^
//            |
//           (B)
//       +----|-----+          Client Identifier      +---------------+
//       |         -+----(A)-- & Redirection URI ---->|               |
//       |  User-   |                                 | Authorization |
//       |  Agent  -+----(B)-- User authenticates --->|     Server    |
//       |          |                                 |               |
//       |         -+----(C)-- Authorization Code ---<|               |
//       +-|----|---+                                 +---------------+
//         |    |                                         ^      v
//        (A)  (C)                                        |      |
//         |    |                                         |      |
//         ^    v                                         |      |
//       +---------+                                      |      |
//       |         |>---(D)-- Authorization Code ---------'      |
//       |  Client |          & Redirection URI                  |
//       |         |                                             |
//       |         |<---(E)----- Access Token -------------------'
//       +---------+       (w/ Optional Refresh Token)
//
//     Note: The lines illustrating steps (A), (B), and (C) are broken into
//     two parts as they pass through the user-agent.
//
//  In this diagram, kanidm is the authorisation server. Each step is handled by:
//
//  * Client Identifier  A)  oauth2_authorise_get
//  * User authenticates B)  normal kanidm auth flow
//  * Authorization Code C)  oauth2_authorise_permit_get
//                           oauth2_authorise_reject_get
//  * Authorization Code / Access Token
//                     D/E)  oauth2_token_post
//
//  These functions appear stateless, but the state is managed through encrypted
//  tokens transmitted in the responses of this flow. This is because in a HA setup
//  we can not guarantee that the User-Agent or the Resource Server (client) will
//  access the same Kanidm instance, and we can not rely on replication in these
//  cases. As a result, we must have our state in localised tokens so that any
//  valid Kanidm instance in the topology can handle these request.
//

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(auth_req): Json<AuthorisationRequest>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise(state, auth_req, kopid)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Query(auth_req): Query<AuthorisationRequest>,
) -> impl IntoResponse {
    // Start the oauth2 authorisation flow to present to the user.
    oauth2_authorise(state, auth_req, kopid).await
}

async fn oauth2_authorise(
    state: ServerState,
    auth_req: AuthorisationRequest,
    kopid: KOpId,
) -> impl IntoResponse {
    let res: Result<AuthoriseResponse, Oauth2Error> = state
        .qe_r_ref
        .handle_oauth2_authorise(kopid.uat.clone(), auth_req, kopid.eventid)
        .await;

    match res {
        Ok(AuthoriseResponse::ConsentRequested {
            client_name,
            scopes,
            pii_scopes,
            consent_token,
        }) => {
            // Render a redirect to the consent page for the user to interact with
            // to authorise this session-id
            // This is json so later we can expand it with better detail.
            #[allow(clippy::unwrap_used)]
            let body = serde_json::to_string(&AuthorisationResponse::ConsentRequested {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            })
            .unwrap();
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .body(body.into())
                .unwrap()
        }
        Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        })) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            #[allow(clippy::unwrap_used)]
            let body =
                Body::from(serde_json::to_string(&AuthorisationResponse::Permitted).unwrap());

            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    LOCATION,
                    HeaderValue::from_str(redirect_uri.as_str()).unwrap(),
                )
                // I think the client server needs this
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_str(&redirect_uri.origin().ascii_serialization()).unwrap(),
                )
                .body(body)
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", HeaderValue::from_str("Bearer").unwrap())
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        /*
        RFC - If the request fails due to a missing, invalid, or mismatching
              redirection URI, or if the client identifier is missing or invalid,
              the authorization server SHOULD inform the resource owner of the
              error and MUST NOT automatically redirect the user-agent to the
              invalid redirection URI.
        */
        // To further this, it appears that a malicious client configuration can set a phishing
        // site as the redirect URL, and then use that to trigger certain types of attacks. Instead
        // we do NOT redirect in an error condition, and just render the error ourselves.
        Err(e) => {
            admin_error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &e.to_string()
            );
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
    }
}

pub async fn oauth2_authorise_permit_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(consent_req): Json<String>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise_permit(state, consent_req, kopid)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConsentRequestData {
    token: String,
}

pub async fn oauth2_authorise_permit_get(
    State(state): State<ServerState>,
    Query(token): Query<ConsentRequestData>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // When this is called, this indicates consent to proceed from the user.
    oauth2_authorise_permit(state, token.token, kopid).await
}

async fn oauth2_authorise_permit(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_oauth2_authorise_permit(kopid.uat, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        }) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", redirect_uri.as_str())
                .header(
                    "Access-Control-Allow-Origin",
                    redirect_uri.origin().ascii_serialization(),
                )
                .body(Body::empty())
                .unwrap()
        }
        Err(_e) => {
            // If an error happens in our consent flow, I think
            // that we should NOT redirect to the calling application
            // and we need to handle that locally somehow.
            // This needs to be better!
            //
            // Turns out this instinct was correct:
            //  https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection
            // Possible to use this with a malicious client configuration to phish / spam.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
    }
}

// When this is called, this indicates the user has REJECTED the intent to proceed.
pub async fn oauth2_authorise_reject_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Form(consent_req): Form<ConsentRequestData>,
) -> impl IntoResponse {
    oauth2_authorise_reject(state, consent_req.token, kopid).await
}

pub async fn oauth2_authorise_reject_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Query(consent_req): Query<ConsentRequestData>,
) -> impl IntoResponse {
    oauth2_authorise_reject(state, consent_req.token, kopid).await
}

// // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
// // If the user willingly rejects the authorisation, we must redirect
// // with an error.
async fn oauth2_authorise_reject(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
) -> impl IntoResponse {
    // Need to go back to the redir_uri
    // For this, we'll need to lookup where to go.

    let res = state
        .qe_r_ref
        .handle_oauth2_authorise_reject(kopid.uat, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(mut redirect_uri) => {
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("error", "access_denied")
                .append_pair("error_description", "authorisation rejected");
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(LOCATION, redirect_uri.as_str())
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    redirect_uri.origin().ascii_serialization(),
                )
                .body(Body::empty())
                .unwrap()
            // I think the client server needs this
        }
        Err(_e) => {
            // If an error happens in our reject flow, I think
            // that we should NOT redirect to the calling application
            // and we need to handle that locally somehow.
            // This needs to be better!
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
    }
}

pub async fn oauth2_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap, // TODO: make this a typed basic auth header
    Form(tok_req): Form<AccessTokenRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then issue
    // the token to the caller.

    // Get the authz header (if present). Not all exchange types require this.
    let client_authz = headers
        .get("authorization")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|h| h.split(' ').last())
        .map(str::to_string);

    // Do we change the method/path we take here based on the type of requested
    // grant? Should we cease the delayed/async session update here and just opt
    // for a wr txn?

    let res = state
        .qe_w_ref
        .handle_oauth2_token_exchange(client_authz, tok_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) =>
        {
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(serde_json::to_string(&atr).unwrap()))
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) =>
        {
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let body = match serde_json::to_string(&err) {
                Ok(val) => val,
                Err(e) => {
                    admin_warn!("Failed to serialize error response: original_error=\"{:?}\" serialization_error=\"{:?}\"", err, e);
                    format!("{:?}", err)
                }
            };

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
    }
}

// // For future openid integration
pub async fn oauth2_openid_discovery_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // let client_id = req.get_url_param("client_id")?;

    let res = state
        .qe_r_ref
        .handle_oauth2_openid_discovery(client_id, kopid.eventid)
        .await;

    match res {
        Ok(dsc) => {
            // Humans may look at this so we pretty it.
            #[allow(clippy::unwrap_used)]
            let body = serde_json::to_string_pretty(&dsc).unwrap();
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            let body = match serde_json::to_string(&e) {
                Ok(val) => val,
                Err(e) => {
                    format!("{:?}", e)
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
    }
}

pub async fn oauth2_openid_userinfo_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Response<Body> {
    // The token we want to inspect is in the authorisation header.
    let client_token = match kopid.uat {
        Some(val) => val,
        None => {
            error!("Bearer Authentication Not Provided");
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from("Invalid Bearer Authorisation"))
                .unwrap();
        }
    };

    let res = state
        .qe_r_ref
        .handle_oauth2_openid_userinfo(client_id, client_token, kopid.eventid)
        .await;

    match res {
        Ok(uir) => {
            #[allow(clippy::unwrap_used)]
            let body = serde_json::to_string(&uir).unwrap();
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };
            let body = match serde_json::to_string(&err) {
                Ok(val) => val,
                Err(e) => {
                    format!("{:?}", e)
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
            // https://datatracker.ietf.org/doc/html/rfc6750#section-6.2
        }
    }
}

pub async fn oauth2_openid_publickey_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_publickey(client_id, kopid.eventid)
        .await;
    to_axum_response(res)
}

/// This is called directly by the resource server, where we then issue
/// information about this token to the caller.
pub async fn oauth2_token_introspect_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap,
    Form(intr_req): Form<AccessTokenIntrospectRequest>,
) -> impl IntoResponse {
    let client_authz = match kopid.uat {
        Some(val) => val,
        None => {
            error!("Bearer Authentication Not Provided, trying basic");
            match headers.get(AUTHORIZATION) {
                Some(val) => {
                    // LOL THIS IS HILARIOUSLY TERRIBLE BUT WE PARSE THE RAW OK
                    #[allow(clippy::unwrap_used)]
                    val.to_str()
                        .unwrap()
                        .strip_prefix("Basic ")
                        .unwrap()
                        .to_string()
                }
                None => {
                    #[allow(clippy::unwrap_used)]
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(Body::from("Invalid Bearer Authorisation"))
                        .unwrap();
                }
            }
        }
    };
    request_trace!("Introspect Request - {:?}", intr_req);

    let res = state
        .qe_r_ref
        .handle_oauth2_token_introspect(client_authz, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) => {
            let body = match serde_json::to_string(&atr) {
                Ok(val) => val,
                Err(e) => {
                    admin_warn!("Failed to serialize introspect response: original_data=\"{:?}\" serialization_error=\"{:?}\"", atr, e);
                    format!("{:?}", atr)
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let body = match serde_json::to_string(&err) {
                Ok(val) => val,
                Err(e) => {
                    format!("{:?}", e)
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// This is called directly by the resource server, where we then revoke
/// the token identified by this request.
pub async fn oauth2_token_revoke_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Form(intr_req): Form<TokenRevokeRequest>,
) -> impl IntoResponse {
    // TODO: we should handle the session-based auth bit here I think maybe possibly there's no tests
    let client_authz = match kopid.uat {
        Some(val) => val,
        None =>
        {
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
    };

    request_trace!("Revoke Request - {:?}", intr_req);

    let res = state
        .qe_w_ref
        .handle_oauth2_token_revoke(client_authz, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(()) =>
        {
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(serde_json::to_string(&err).unwrap()))
                .unwrap()
        }
    }
}

// Some requests from browsers require preflight so that CORS works.
pub async fn oauth2_preflight_options() -> impl IntoResponse {
    #[allow(clippy::unwrap_used)]
    Response::builder()
        .status(StatusCode::OK)
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "Authorization")
        .body(Body::empty())
        .unwrap()
}

pub fn oauth2_route_setup(state: ServerState) -> Router<ServerState> {
    // this has all the openid-related routes
    let openid_router = Router::new()
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/:client_id/.well-known/openid-configuration",
            get(oauth2_openid_discovery_get).options(oauth2_preflight_options),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/:client_id/userinfo",
            get(oauth2_openid_userinfo_get).options(oauth2_preflight_options),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/:client_id/public_key.jwk",
            get(oauth2_openid_publickey_get),
        )
        .with_state(state.clone());

    Router::new()
        .route("/oauth2", get(oauth2_get))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/authorise",
            post(oauth2_authorise_post).get(oauth2_authorise_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/authorise/permit",
            post(oauth2_authorise_permit_post).get(oauth2_authorise_permit_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/authorise/reject",
            post(oauth2_authorise_reject_post).get(oauth2_authorise_reject_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route("/oauth2/token", post(oauth2_token_post))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/token/introspect",
            post(oauth2_token_introspect_post),
        )
        .route("/oauth2/token/revoke", post(oauth2_token_revoke_post))
        .merge(openid_router)
        .with_state(state)
        .layer(from_fn(super::middleware::caching::dont_cache_me))
}
