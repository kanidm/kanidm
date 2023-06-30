use kanidm_proto::oauth2::AuthorisationResponse;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenRequest, AuthorisationRequest, AuthorisePermitSuccess,
    AuthoriseResponse, ErrorResponse, Oauth2Error, TokenRevokeRequest,
};
use kanidmd_lib::prelude::*;
use serde::{Deserialize, Serialize};

use super::routemaps::{RouteMap, RouteMaps};
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::{to_tide_response, AppState, RequestExtensions};

// == Oauth2 Configuration Endpoints ==

pub async fn oauth2_get(State(state): State<ServerState>) -> tide::Result {
    let filter = filter_all!(f_eq(
        "class",
        PartialValue::new_class("oauth2_resource_server")
    ));
    json_rest_event_get(req, filter, None).await
}

pub async fn oauth2_basic_post(State(state): State<ServerState>) -> tide::Result {
    let classes = vec![
        "oauth2_resource_server".to_string(),
        "oauth2_resource_server_basic".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(req, classes).await
}

fn oauth2_id(id: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("oauth2_resource_server")),
        f_eq("oauth2_rs_name", PartialValue::new_iname(id))
    ]))
}

pub async fn oauth2_id_get(State(state): State<ServerState>) -> tide::Result {
    // Get a specific config
    let uat = req.get_current_uat();
    let id = req.get_url_param("rs_name")?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, None, eventid)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_get_basic_secret(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();

    let id = req.get_url_param("rs_name")?;
    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_basic_secret_read(uat, filter, eventid)
        .await;

    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_patch(State(state): State<ServerState>) -> tide::Result {
    // Update a value / attrs
    let uat = req.get_current_uat();
    let id = req.get_url_param("rs_name")?;

    let obj: ProtoEntry = req.body_json().await?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_internalpatch(uat, filter, obj, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_scopemap_post(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let group = req.get_url_param("group")?;

    let scopes: Vec<String> = req.body_json().await?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_scopemap_update(uat, group, scopes, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_scopemap_delete(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let group = req.get_url_param("group")?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_scopemap_delete(uat, group, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_sup_scopemap_post(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let group = req.get_url_param("group")?;

    let scopes: Vec<String> = req.body_json().await?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_sup_scopemap_update(uat, group, scopes, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_sup_scopemap_delete(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let group = req.get_url_param("group")?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_sup_scopemap_delete(uat, group, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_id_delete(State(state): State<ServerState>) -> tide::Result {
    // Delete this
    let uat = req.get_current_uat();
    let id = req.get_url_param("rs_name")?;

    let filter = oauth2_id(&id);

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_internaldelete(uat, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// == OAUTH2 PROTOCOL FLOW HANDLERS ==

// oauth2 (partial)
// https://tools.ietf.org/html/rfc6749
// oauth2 pkce
// https://tools.ietf.org/html/rfc7636

// TODO
// oauth2 token introspection
// https://tools.ietf.org/html/rfc7662
// oauth2 bearer token
// https://tools.ietf.org/html/rfc6750

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

pub async fn oauth2_authorise_post(State(state): State<ServerState>) -> tide::Result {
    let auth_req: AuthorisationRequest = req.body_json().await?;
    oauth2_authorise(req, auth_req).await.map(|mut res| {
        if res.status() == 302 {
            // in post, we need the redirect not to be issued, so we mask 302 to 200
            res.set_status(200);
        }
        res
    })
}

pub async fn oauth2_authorise_get(State(state): State<ServerState>) -> tide::Result {
    // Start the oauth2 authorisation flow to present to the user.
    debug!("Request Query - {:?}", req.url().query());
    // Get the authorisation request.
    let auth_req: AuthorisationRequest = req.query().map_err(|e| {
        error!("{:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 AuthorisationRequest",
        )
    })?;

    oauth2_authorise(req, auth_req).await
}

async fn oauth2_authorise(
    State(state): State<ServerState>,
    auth_req: AuthorisationRequest,
) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

    // let mut redir_url = auth_req.redirect_uri.clone();

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_authorise(uat, auth_req, eventid)
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
            let mut res = tide::Response::new(200);
            // This is json so later we can expand it with better detail.
            tide::Body::from_json(&AuthorisationResponse::ConsentRequested {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            })
            .map(|b| {
                res.set_body(b);
                res
            })
        }
        Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        })) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            let mut res = tide::Response::new(302);

            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
            res.insert_header("Location", redirect_uri.as_str());
            // I think the client server needs this
            res.insert_header(
                "Access-Control-Allow-Origin",
                redirect_uri.origin().ascii_serialization(),
            );
            tide::Body::from_json(&AuthorisationResponse::Permitted).map(|b| {
                res.set_body(b);
                res
            })
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            let mut res = tide::Response::new(tide::StatusCode::Unauthorized);
            res.insert_header("WWW-Authenticate", "Bearer");
            Ok(res)
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            let res = tide::Response::new(tide::StatusCode::Forbidden);
            Ok(res)
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
                &hvalue,
                &e.to_string()
            );
            Ok(tide::Response::new(tide::StatusCode::BadRequest))
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

pub async fn oauth2_authorise_permit_post(State(state): State<ServerState>) -> tide::Result {
    let consent_req: String = req.body_json().await?;
    oauth2_authorise_permit(req, consent_req)
        .await
        .map(|mut res| {
            if res.status() == 302 {
                // in post, we need the redirect not to be issued, so we mask 302 to 200
                res.set_status(200);
            }
            res
        })
}

#[derive(Serialize, Deserialize, Debug)]
struct ConsentRequestData {
    token: String,
}

pub async fn oauth2_authorise_permit_get(State(state): State<ServerState>) -> tide::Result {
    // When this is called, this indicates consent to proceed from the user.
    debug!("Request Query - {:?}", req.url().query());

    let consent_req: ConsentRequestData = req.query().map_err(|e| {
        error!("{:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 Consent Permit",
        )
    })?;

    oauth2_authorise_permit(req, consent_req.token).await
}

async fn oauth2_authorise_permit(
    State(state): State<ServerState>,
    consent_req: String,
) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_authorise_permit(uat, consent_req, eventid)
        .await;

    let mut res = match res {
        Ok(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        }) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            let mut res = tide::Response::new(302);
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);
            res.insert_header("Location", redirect_uri.as_str());
            // I think the client server needs this
            res.insert_header(
                "Access-Control-Allow-Origin",
                redirect_uri.origin().ascii_serialization(),
            );
            res
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
            tide::Response::new(tide::StatusCode::InternalServerError)
        }
    };
    res.insert_header("X-KANIDM-OPID", hvalue);
    Ok(res)
}

// When this is called, this indicates the user has REJECTED the intent to proceed.
pub async fn oauth2_authorise_reject_post(State(state): State<ServerState>) -> tide::Result {
    let consent_req: String = req.body_json().await?;
    oauth2_authorise_reject(req, consent_req).await
}

pub async fn oauth2_authorise_reject_get(State(state): State<ServerState>) -> tide::Result {
    debug!("Request Query - {:?}", req.url().query());

    let consent_req: ConsentRequestData = req.query().map_err(|e| {
        error!("{:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 Consent Reject",
        )
    })?;

    oauth2_authorise_reject(req, consent_req.token).await
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
// If the user willingly rejects the authorisation, we must redirect
// with an error.
async fn oauth2_authorise_reject(
    State(state): State<ServerState>,
    consent_req: String,
) -> tide::Result {
    // Need to go back to the redir_uri
    // For this, we'll need to lookup where to go.
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_authorise_reject(uat, consent_req, eventid)
        .await;

    let mut res = match res {
        Ok(mut redirect_uri) => {
            let mut res = tide::Response::new(302);
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("error", "access_denied")
                .append_pair("error_description", "authorisation rejected");
            res.insert_header("Location", redirect_uri.as_str());
            // I think the client server needs this
            // res.insert_header("Access-Control-Allow-Origin", redirect_uri.origin().ascii_serialization());
            res
        }
        Err(_e) => {
            // If an error happens in our reject flow, I think
            // that we should NOT redirect to the calling application
            // and we need to handle that locally somehow.
            // This needs to be better!
            tide::Response::new(500)
        }
    };
    res.insert_header("X-KANIDM-OPID", hvalue);
    Ok(res)
}

pub async fn oauth2_token_post(State(state): State<ServerState>) -> tide::Result {
    // This is called directly by the resource server, where we then issue
    // the token to the caller.
    let (eventid, hvalue) = req.new_eventid();

    // Get the authz header (if present). In the future depending on the
    // type of exchanges we support, this could become an Option type.
    let client_authz = req
        .header("authorization")
        .and_then(|hv| hv.get(0))
        .and_then(|h| h.as_str().strip_prefix("Basic "))
        .map(str::to_string);

    // Get the accessToken Request
    let tok_req: AccessTokenRequest = req.body_form().await.map_err(|e| {
        error!("atr parse error - {:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 AccessTokenRequest",
        )
    })?;

    // Do we change the method/path we take here based on the type of requested
    // grant? Should we cease the delayed/async session update here and just opt
    // for a wr txn?

    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_token_exchange(client_authz, tok_req, eventid)
        .await;

    match res {
        Ok(atr) => {
            let mut res = tide::Response::new(200);
            tide::Body::from_json(&atr).map(|b| {
                res.set_body(b);
                res
            })
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            Ok(tide::Response::new(tide::StatusCode::Unauthorized))
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let mut res = tide::Response::new(400);
            tide::Body::from_json(&err).map(|b| {
                res.set_body(b);
                res
            })
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

// For future openid integration
pub async fn oauth2_openid_discovery_get(State(state): State<ServerState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let client_id = req.get_url_param("client_id")?;

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_openid_discovery(client_id, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_openid_userinfo_get(State(state): State<ServerState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let client_id = req.get_url_param("client_id")?;

    // The token we want to inspect is in the authorisation header.
    let client_authz = req
        .header("authorization")
        .and_then(|hv| hv.get(0))
        .and_then(|h| h.as_str().strip_prefix("Bearer "))
        .map(str::to_string)
        .ok_or_else(|| {
            // TODO #1787 test bearer auth
            error!("Bearer Authentication Not Provided");
            tide::Error::from_str(
                tide::StatusCode::Unauthorized,
                "Invalid Bearer Authorisation",
            )
        })?;

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_openid_userinfo(client_id, client_authz, eventid)
        .await;

    match res {
        Ok(uir) => {
            let mut res = tide::Response::new(200);
            tide::Body::from_json(&uir).map(|b| {
                res.set_body(b);
                res
            })
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6750#section-6.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let mut res = tide::Response::new(400);
            tide::Body::from_json(&err).map(|b| {
                res.set_body(b);
                res
            })
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

pub async fn oauth2_openid_publickey_get(State(state): State<ServerState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let client_id = req.get_url_param("client_id")?;

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_openid_publickey(client_id, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn oauth2_token_introspect_post(State(state): State<ServerState>) -> tide::Result {
    // This is called directly by the resource server, where we then issue
    // information about this token to the caller.
    let (eventid, hvalue) = req.new_eventid();

    let client_authz = req
        .header("authorization")
        .and_then(|hv| hv.get(0))
        .and_then(|h| h.as_str().strip_prefix("Basic "))
        .map(str::to_string)
        .ok_or_else(|| {
            error!("Basic Authentication Not Provided");
            tide::Error::from_str(
                tide::StatusCode::Unauthorized,
                "Invalid Basic Authorisation",
            )
        })?;

    // Get the introspection request, could we accept json or form? Prob needs content type here.
    let intr_req: AccessTokenIntrospectRequest = req.body_form().await.map_err(|e| {
        // TODO: #1787 test this
        request_error!("{:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 AccessTokenIntrospectRequest",
        )
    })?;

    request_trace!("Introspect Request - {:?}", intr_req);

    let res = req
        .state()
        .qe_r_ref
        .handle_oauth2_token_introspect(client_authz, intr_req, eventid)
        .await;

    match res {
        Ok(atr) => {
            let mut res = tide::Response::new(200);
            tide::Body::from_json(&atr).map(|b| {
                res.set_body(b);
                res
            })
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            Ok(tide::Response::new(tide::StatusCode::Unauthorized))
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let mut res = tide::Response::new(400);
            tide::Body::from_json(&err).map(|b| {
                res.set_body(b);
                res
            })
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

pub async fn oauth2_token_revoke_post(State(state): State<ServerState>) -> tide::Result {
    // This is called directly by the resource server, where we then revoke
    // the token identified by this request.
    let (eventid, hvalue) = req.new_eventid();

    let client_authz = req
        .header("authorization")
        .and_then(|hv| hv.get(0))
        .and_then(|h| h.as_str().strip_prefix("Basic "))
        .map(str::to_string)
        .ok_or_else(|| {
            error!("Basic Authentication Not Provided");
            tide::Error::from_str(
                tide::StatusCode::Unauthorized,
                "Invalid Basic Authorisation",
            )
        })?;

    // TODO: #1787 test this to support token auth
    // Get the introspection request, could we accept json or form? Prob needs content type here.
    let intr_req: TokenRevokeRequest = req.body_form().await.map_err(|e| {
        request_error!("{:?}", e);
        tide::Error::from_str(
            tide::StatusCode::BadRequest,
            "Invalid Oauth2 TokenRevokeRequest",
        )
    })?;

    request_trace!("Revoke Request - {:?}", intr_req);

    let res = req
        .state()
        .qe_w_ref
        .handle_oauth2_token_revoke(client_authz, intr_req, eventid)
        .await;

    match res {
        Ok(()) => Ok(tide::Response::new(200)),
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            Ok(tide::Response::new(tide::StatusCode::Unauthorized))
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                error_description: None,
                error_uri: None,
            };

            let mut res = tide::Response::new(400);
            tide::Body::from_json(&err).map(|b| {
                res.set_body(b);
                res
            })
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

pub fn oauth2_route_setup(appserver: &mut tide::Route<'_, AppState>, routemap: &mut RouteMap) {
    let mut oauth2_process = appserver.at("/oauth2");
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise")
        .mapped_post(routemap, oauth2_authorise_post)
        .mapped_get(routemap, oauth2_authorise_get);

    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise/permit")
        .mapped_post(routemap, oauth2_authorise_permit_post)
        .mapped_get(routemap, oauth2_authorise_permit_get);

    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise/reject")
        .mapped_post(routemap, oauth2_authorise_reject_post)
        .mapped_get(routemap, oauth2_authorise_reject_get);

    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/token")
        .mapped_post(routemap, oauth2_token_post);

    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/token/introspect")
        .mapped_post(routemap, oauth2_token_introspect_post);
    oauth2_process
        .at("/token/revoke")
        .mapped_post(routemap, oauth2_token_revoke_post);

    let mut openid_process = appserver.at("/oauth2/openid");
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS

    openid_process
        .at("/:client_id/.well-known/openid-configuration")
        .mapped_get(routemap, oauth2_openid_discovery_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS

    openid_process
        .at("/:client_id/userinfo")
        .mapped_get(routemap, oauth2_openid_userinfo_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS

    openid_process
        .at("/:client_id/public_key.jwk")
        .mapped_get(routemap, oauth2_openid_publickey_get);
}
