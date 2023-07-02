use super::middleware::KOpId;
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::{to_axum_response, ServerState};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
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
// use serde::{Deserialize, Serialize};

// // == Oauth2 Configuration Endpoints ==
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
    // Get a specific config

    let filter = oauth2_id(&rs_name);

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

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

// // == OAUTH2 PROTOCOL FLOW HANDLERS ==

// // oauth2 (partial)
// // https://tools.ietf.org/html/rfc6749
// // oauth2 pkce
// // https://tools.ietf.org/html/rfc7636

// // TODO
// // oauth2 token introspection
// // https://tools.ietf.org/html/rfc7662
// // oauth2 bearer token
// // https://tools.ietf.org/html/rfc6750

// // From https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// //
// //       +----------+
// //       | Resource |
// //       |   Owner  |
// //       |          |
// //       +----------+
// //            ^
// //            |
// //           (B)
// //       +----|-----+          Client Identifier      +---------------+
// //       |         -+----(A)-- & Redirection URI ---->|               |
// //       |  User-   |                                 | Authorization |
// //       |  Agent  -+----(B)-- User authenticates --->|     Server    |
// //       |          |                                 |               |
// //       |         -+----(C)-- Authorization Code ---<|               |
// //       +-|----|---+                                 +---------------+
// //         |    |                                         ^      v
// //        (A)  (C)                                        |      |
// //         |    |                                         |      |
// //         ^    v                                         |      |
// //       +---------+                                      |      |
// //       |         |>---(D)-- Authorization Code ---------'      |
// //       |  Client |          & Redirection URI                  |
// //       |         |                                             |
// //       |         |<---(E)----- Access Token -------------------'
// //       +---------+       (w/ Optional Refresh Token)
// //
// //     Note: The lines illustrating steps (A), (B), and (C) are broken into
// //     two parts as they pass through the user-agent.
// //
// //  In this diagram, kanidm is the authorisation server. Each step is handled by:
// //
// //  * Client Identifier  A)  oauth2_authorise_get
// //  * User authenticates B)  normal kanidm auth flow
// //  * Authorization Code C)  oauth2_authorise_permit_get
// //                           oauth2_authorise_reject_get
// //  * Authorization Code / Access Token
// //                     D/E)  oauth2_token_post
// //
// //  These functions appear stateless, but the state is managed through encrypted
// //  tokens transmitted in the responses of this flow. This is because in a HA setup
// //  we can not guarantee that the User-Agent or the Resource Server (client) will
// //  access the same Kanidm instance, and we can not rely on replication in these
// //  cases. As a result, we must have our state in localised tokens so that any
// //  valid Kanidm instance in the topology can handle these request.
// //

pub async fn oauth2_authorise_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(auth_req): Json<AuthorisationRequest>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise(state, auth_req, kopid)
        .await
        .into_response();
    if res.status() == 302 {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

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
        .handle_oauth2_authorise(kopid.uat, auth_req, kopid.eventid)
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
            let body = serde_json::to_string(&AuthorisationResponse::ConsentRequested {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            })
            .unwrap();
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
            // let mut res = tide::Response::new(302);
            let body =
                Body::from(serde_json::to_string(&AuthorisationResponse::Permitted).unwrap());

            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
            Response::builder()
                .status(302)
                .header(
                    "Location",
                    HeaderValue::from_str(redirect_uri.as_str()).unwrap(),
                )
                // // I think the client server needs this
                .header(
                    "Access-Control-Allow-Origin",
                    HeaderValue::from_str(&redirect_uri.origin().ascii_serialization()).unwrap(),
                )
                .body(body)
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", HeaderValue::from_str("Bearer").unwrap())
                .body(Body::empty())
                .unwrap()
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            Response::builder()
                .status(StatusCode::FORBIDDEN)
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
                "Unable to authorise - Error ID: {} error: {}",
                &kopid.value,
                &e.to_string()
            );
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
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
    if res.status() == 302 {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct ConsentRequestData {
//     token: String,
// }

pub async fn oauth2_authorise_permit_get(
    State(state): State<ServerState>,
    Query(token): Query<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // When this is called, this indicates consent to proceed from the user.

    // let consent_req: ConsentRequestData = req.query().map_err(|e| {
    //     error!("{:?}", e);
    //     tide::Error::from_str(
    //         tide::StatusCode::BadRequest,
    //         "Invalid Oauth2 Consent Permit",
    //     )
    // })?;

    oauth2_authorise_permit(state, token, kopid).await
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
            // let mut res = tide::Response::new(302);
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
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
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        }
    }
}

// // When this is called, this indicates the user has REJECTED the intent to proceed.
// pub async fn oauth2_authorise_reject_post(State(state): State<ServerState>) -> impl IntoResponse {
//     let consent_req: String = req.body_json().await?;
//     oauth2_authorise_reject(req, consent_req).await
// }

// pub async fn oauth2_authorise_reject_get(State(state): State<ServerState>) -> impl IntoResponse {
//     debug!("Request Query - {:?}", req.url().query());

//     let consent_req: ConsentRequestData = req.query().map_err(|e| {
//         error!("{:?}", e);
//         tide::Error::from_str(
//             tide::StatusCode::BadRequest,
//             "Invalid Oauth2 Consent Reject",
//         )
//     })?;

//     oauth2_authorise_reject(req, consent_req.token).await
// }

// // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
// // If the user willingly rejects the authorisation, we must redirect
// // with an error.
// async fn oauth2_authorise_reject(
//     State(state): State<ServerState>,headers: HeaderMap,
//     consent_req: String,
// ) -> impl IntoResponse {
//     // Need to go back to the redir_uri
//     // For this, we'll need to lookup where to go.

//     let res = state
//         .qe_r_ref
//         .handle_oauth2_authorise_reject(uat, consent_req, eventid)
//         .await;

//     let mut res = match res {
//         Ok(mut redirect_uri) => {
//             let mut res = tide::Response::new(302);
//             redirect_uri
//                 .query_pairs_mut()
//                 .clear()
//                 .append_pair("error", "access_denied")
//                 .append_pair("error_description", "authorisation rejected");
//             res.insert_header("Location", redirect_uri.as_str());
//             // I think the client server needs this
//             // res.insert_header("Access-Control-Allow-Origin", redirect_uri.origin().ascii_serialization());
//             res
//         }
//         Err(_e) => {
//             // If an error happens in our reject flow, I think
//             // that we should NOT redirect to the calling application
//             // and we need to handle that locally somehow.
//             // This needs to be better!
//             tide::Response::new(500)
//         }
//     };
//     res.insert_header("X-KANIDM-OPID", hvalue);
//     res
// }

pub async fn oauth2_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap, // TOOD: make this a typed basic auth header
    Form(tok_req): Form<AccessTokenRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then issue
    // the token to the caller.

    // Get the authz header (if present). In the future depending on the
    // type of exchanges we support, this could become an Option type.
    let client_authz = match headers
        .get("authorization")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|h| h.split(' ').last())
        .map(str::to_string)
    {
        Some(val) => val,
        None => {
            error!("Basic Authentication Not Provided");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Invalid Basic Authorisation"))
                .unwrap();
        }
    };

    // Get the accessToken Request
    // let tok_req: AccessTokenRequest = req.body_form().await.map_err(|e| {
    //     error!("atr parse error - {:?}", e);
    //     tide::Error::from_str(
    //         tide::StatusCode::BadRequest,
    //         "Invalid Oauth2 AccessTokenRequest",
    //     )
    // })?;

    // Do we change the method/path we take here based on the type of requested
    // grant? Should we cease the delayed/async session update here and just opt
    // for a wr txn?

    let res = state
        .qe_w_ref
        .handle_oauth2_token_exchange(Some(client_authz), tok_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) => {
            let body = serde_json::to_string(&atr).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let body = serde_json::to_string(&err).unwrap();
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
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
    to_axum_response(res)
}

pub async fn oauth2_openid_userinfo_get(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Response<Body> {
    // The token we want to inspect is in the authorisation header.
    let client_authz = match headers
        .get("authorization")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string)
    {
        Some(val) => val,
        None => {
            error!("Bearer Authentication Not Provided");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Invalid Bearer Authorisation"))
                .unwrap();
        }
    };

    let res = state
        .qe_r_ref
        .handle_oauth2_openid_userinfo(client_id, client_authz, kopid.eventid)
        .await;

    match res {
        Ok(uir) => {
            let body = serde_json::to_string(&uir).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };
            let err: String = serde_json::to_string(&err).unwrap();
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(err))
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

pub async fn oauth2_token_introspect_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap, // TODO: turn this into an auth/bearer header?
    Form(intr_req): Form<AccessTokenIntrospectRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then issue
    // information about this token to the caller.

    let client_authz = match headers
        .get("authorization")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string)
    {
        Some(val) => val,
        None => {
            error!("Bearer Authentication Not Provided");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Invalid Bearer Authorisation"))
                .unwrap();
        }
    };

    // Get the introspection request, could we accept json or form? Prob needs content type here.
    // let intr_req: AccessTokenIntrospectRequest = req.body_form().await.map_err(|e| {
    //     // TODO: #1787 test this
    //     request_error!("{:?}", e);
    //     tide::Error::from_str(
    //         tide::StatusCode::BadRequest,
    //         "Invalid Oauth2 AccessTokenIntrospectRequest",
    //     )
    // })?;

    request_trace!("Introspect Request - {:?}", intr_req);

    let res = state
        .qe_r_ref
        .handle_oauth2_token_introspect(client_authz, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) => {
            let body = serde_json::to_string(&atr).unwrap();
            Response::new(Body::from(body))
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            Response::builder()
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

            let body = serde_json::to_string(&err).unwrap();
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(body))
                .unwrap()
        }
    }
}

pub async fn oauth2_token_revoke_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap,
    Form(intr_req): Form<TokenRevokeRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then revoke
    // the token identified by this request.

    let client_authz = match headers
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
        Some(val) => val,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap()
        }
    };

    // TODO: #1787 test this to support token auth
    // Get the introspection request, could we accept json or form? Prob needs content type here.
    // let intr_req: TokenRevokeRequest = req.body_form().await.map_err(|e| {
    //     request_error!("{:?}", e);
    //     tide::Error::from_str(
    //         tide::StatusCode::BadRequest,
    //         "Invalid Oauth2 TokenRevokeRequest",
    //     )
    // })?;

    request_trace!("Revoke Request - {:?}", intr_req);

    let res = state
        .qe_w_ref
        .handle_oauth2_token_revoke(client_authz, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(()) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            Response::builder()
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
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(serde_json::to_string(&err).unwrap()))
                .unwrap()
        }
    }
}

pub fn oauth2_route_setup(state: ServerState) -> Router<ServerState> {
    // this has all the openid-related routes
    let openid_router = Router::new() // appserver.at("/oauth2/openid");
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/:client_id/.well-known/openid-configuration",
            get(oauth2_openid_discovery_get),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route("/:client_id/userinfo", get(oauth2_openid_userinfo_get))
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/:client_id/public_key.jwk",
            get(oauth2_openid_publickey_get),
        )
        .with_state(state.clone());

    Router::new() //= appserver.at("/oauth2");
        .route("/", get(oauth2_get))
        .route("/_basic", post(oauth2_basic_post))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/authorise",
            post(oauth2_authorise_post).get(oauth2_authorise_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/authorise/permit",
            post(oauth2_authorise_permit_post).get(oauth2_authorise_permit_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        // .route("/authorise/reject", post(oauth2_authorise_reject_post).get(oauth2_authorise_reject_get))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route("/token", post(oauth2_token_post))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route("/token/introspect", post(oauth2_token_introspect_post))
        .route("/token/revoke", post(oauth2_token_revoke_post))
        .nest("/openid", openid_router)
        .route(
            "/:rs_name",
            get(oauth2_id_get)
                .patch(oauth2_id_patch)
                .delete(oauth2_id_delete),
        )
        .route("/:rs_name/_basic_secret", get(oauth2_id_get_basic_secret))
        .route(
            "/:rs_name/_scopemap/:group",
            post(oauth2_id_scopemap_post).delete(oauth2_id_scopemap_delete),
        )
        .route(
            "/:rs_name/_sup_scopemap/:group",
            post(oauth2_id_sup_scopemap_post).delete(oauth2_id_sup_scopemap_delete),
        )
        .with_state(state)
}
