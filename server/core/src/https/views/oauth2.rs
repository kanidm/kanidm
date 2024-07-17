use kanidmd_lib::prelude::*;
use kanidmd_lib::idm::oauth2::{
    AuthorisationRequest,
    Oauth2Error,
    AuthorisePermitSuccess,
    AuthoriseResponse,
};
use compact_jwt::{Jws, JwsSigner};

use crate::https::{extractors::VerifiedClientInformation, middleware::KOpId, ServerState};

use kanidm_proto::internal::COOKIE_OAUTH2_REQ;

use std::collections::BTreeSet;

use askama::Template;

use axum::{
    extract::{Query, State},
    response::{
        IntoResponse,
        Redirect,
        Response
    },
    http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
    routing::{get, post},
    Extension,
    Router,
    Form,
};
use axum_extra::extract::cookie::{
    Cookie,
    CookieJar,
    SameSite
};
use axum_htmx::HX_REDIRECT;
use serde::Deserialize;

use super::{HtmlTemplate, UnrecoverableErrorView};

#[derive(Template)]
#[template(path = "oauth2_consent_request.html")]
struct ConsentRequestView {
    client_name: String,
    // scopes: BTreeSet<String>,
    pii_scopes: BTreeSet<String>,
    consent_token: String,
}

#[derive(Template)]
#[template(path = "oauth2_access_denied.html")]
struct AccessDeniedView {
    operation_id: Uuid,
}

pub async fn view_index_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Query(auth_req): Query<AuthorisationRequest>,
) -> Response {
    oauth2_auth_req(
        state, kopid, client_auth_info, jar, auth_req
    ).await
}

pub async fn view_resume_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> Response {
    let maybe_auth_req = jar
        .get(COOKIE_OAUTH2_REQ)
        .map(|c| c.value())
        .and_then(|s| {
            state.deserialise_from_str::<AuthorisationRequest>(s)
        });

    if let Some(auth_req) = maybe_auth_req {
        oauth2_auth_req(
            state, kopid, client_auth_info, jar, auth_req
        ).await
    } else {
        error!("unable to resume session, no auth_req was found in the cookie");
        HtmlTemplate(UnrecoverableErrorView {
            err_code: OperationError::InvalidState,
            operation_id: kopid.eventid,
        })
        .into_response()
    }
}

async fn oauth2_auth_req(
    state: ServerState,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
    jar: CookieJar,
    auth_req: AuthorisationRequest,
) -> Response {
    let res: Result<AuthoriseResponse, Oauth2Error> = state
        .qe_r_ref
        .handle_oauth2_authorise(client_auth_info, auth_req.clone(), kopid.eventid)
        .await;

    match res {
        Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        })) => {
            let jar = if let Some(authreq_cookie) = jar.get(COOKIE_OAUTH2_REQ) {
                let mut authreq_cookie = authreq_cookie.clone();
                authreq_cookie.make_removal();
                authreq_cookie.set_path("/ui");
                jar.add(authreq_cookie)
            } else {
                jar
            };

            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);

            (
                jar,
                [(
                    HX_REDIRECT,
                    redirect_uri.as_str().to_string(),
                ),
                (
                    ACCESS_CONTROL_ALLOW_ORIGIN.as_str(),
                    redirect_uri.origin().ascii_serialization(),
                )],
                Redirect::to(redirect_uri.as_str()),
            ).into_response()
        }
        Ok(AuthoriseResponse::ConsentRequested {
            client_name,
            scopes: _,
            pii_scopes,
            consent_token,
        }) => {
            // We can just render the form now, the consent token has everything we need.
            HtmlTemplate(ConsentRequestView {
                client_name,
                // scopes,
                pii_scopes,
                consent_token,
            })
                .into_response()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // We store the auth_req into the cookie.
            let kref = &state.jws_signer;

            let token = match Jws::into_json(&auth_req)
                .map_err(|err| {
                    error!(?err, "Failed to serialise AuthorisationRequest");
                    OperationError::InvalidSessionState
                })
                .and_then(|jws|
                    kref.sign(&jws)
                    .map_err(|err| {
                        error!(?err, "Failed to sign AuthorisationRequest");
                        OperationError::InvalidSessionState
                    })
                )
                .map(|jwss| jwss.to_string())
            {
                Ok(jws) => jws,
                Err(err_code) => {
                    return HtmlTemplate(UnrecoverableErrorView {
                        err_code,
                        operation_id: kopid.eventid,
                    })
                    .into_response();
                }
            };

            let mut authreq_cookie =
                Cookie::new(COOKIE_OAUTH2_REQ, token);
            authreq_cookie.set_secure(state.secure_cookies);
            authreq_cookie.set_same_site(SameSite::Strict);
            authreq_cookie.set_http_only(true);
            authreq_cookie.set_domain(state.domain.clone());
            authreq_cookie.set_path("/ui");
            let jar = jar.add(authreq_cookie);

            (jar, Redirect::to("/ui/login")).into_response()
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            HtmlTemplate(AccessDeniedView {
                operation_id: kopid.eventid,
            })
                .into_response()
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
        Err(err_code) => {
            error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &err_code.to_string()
            );

            HtmlTemplate(UnrecoverableErrorView {
                err_code: OperationError::InvalidState,
                operation_id: kopid.eventid,
            })
            .into_response()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentForm {
    consent_token: String,
}

pub async fn view_consent_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(consent_form): Form<ConsentForm>,
) -> Response {
    let res = state
        .qe_w_ref
        .handle_oauth2_authorise_permit(client_auth_info, consent_form.consent_token, kopid.eventid)
        .await;

    match res {
        Ok(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        }) => {
            let jar = if let Some(authreq_cookie) = jar.get(COOKIE_OAUTH2_REQ) {
                let mut authreq_cookie = authreq_cookie.clone();
                authreq_cookie.make_removal();
                authreq_cookie.set_path("/ui");
                jar.add(authreq_cookie)
            } else {
                jar
            };

            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);

            (
                jar,
                [(
                    HX_REDIRECT,
                    redirect_uri.as_str().to_string(),
                ),
                (
                    ACCESS_CONTROL_ALLOW_ORIGIN.as_str(),
                    redirect_uri.origin().ascii_serialization(),
                )],
                Redirect::to(redirect_uri.as_str()),
            ).into_response()
        }
        Err(err_code) => {
            error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &err_code.to_string()
            );

            HtmlTemplate(UnrecoverableErrorView {
                err_code: OperationError::InvalidState,
                operation_id: kopid.eventid,
            })
            .into_response()
        }
    }
}

pub fn view_router() -> Router<ServerState> {
    Router::new()
        .route("/", get(view_index_get))
        .route("/resume", get(view_resume_get))
        .route("/consent", post(view_consent_post))
}
