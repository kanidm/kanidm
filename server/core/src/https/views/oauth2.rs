use crate::https::{
    extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation},
    middleware::KOpId,
    ServerState,
};
use kanidmd_lib::idm::oauth2::{
    AuthorisationRequest, AuthorisePermitSuccess, AuthoriseResponse, Oauth2Error,
};
use kanidmd_lib::prelude::*;

use kanidm_proto::internal::COOKIE_OAUTH2_REQ;

use std::collections::BTreeSet;

use askama::Template;

#[cfg(feature = "dev-oauth2-device-flow")]
use axum::http::StatusCode;
use axum::{
    extract::{Query, State},
    http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use axum_extra::extract::cookie::{CookieJar, SameSite};
use axum_htmx::HX_REDIRECT;
use serde::Deserialize;

use super::constants::Urls;
use super::login::{LoginDisplayCtx, Oauth2Ctx};
use super::{cookies, UnrecoverableErrorView};

#[derive(Template)]
#[template(path = "oauth2_consent_request.html")]
struct ConsentRequestView {
    client_name: String,
    // scopes: BTreeSet<String>,
    pii_scopes: BTreeSet<String>,
    consent_token: String,
    redirect: Option<String>,
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
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Query(auth_req): Query<AuthorisationRequest>,
) -> Response {
    oauth2_auth_req(state, kopid, client_auth_info, domain_info, jar, auth_req).await
}

pub async fn view_resume_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> Result<Response, UnrecoverableErrorView> {
    let maybe_auth_req =
        cookies::get_signed::<AuthorisationRequest>(&state, &jar, COOKIE_OAUTH2_REQ);

    if let Some(auth_req) = maybe_auth_req {
        Ok(oauth2_auth_req(state, kopid, client_auth_info, domain_info, jar, auth_req).await)
    } else {
        error!("unable to resume session, no auth_req was found in the cookie");
        Err(UnrecoverableErrorView {
            err_code: OperationError::InvalidState,
            operation_id: kopid.eventid,
        })
    }
}

async fn oauth2_auth_req(
    state: ServerState,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
    jar: CookieJar,
    auth_req: AuthorisationRequest,
) -> Response {
    let res: Result<AuthoriseResponse, Oauth2Error> = state
        .qe_r_ref
        .handle_oauth2_authorise(client_auth_info, auth_req.clone(), kopid.eventid)
        .await;

    // No matter what, we always clear the stored oauth2 cookie to prevent
    // ui loops
    let jar = if let Some(authreq_cookie) = jar.get(COOKIE_OAUTH2_REQ) {
        let mut authreq_cookie = authreq_cookie.clone();
        authreq_cookie.make_removal();
        authreq_cookie.set_path(Urls::Ui.as_ref());
        jar.add(authreq_cookie)
    } else {
        jar
    };

    match res {
        Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
            mut redirect_uri,
            state,
            code,
        })) => {
            redirect_uri
                .query_pairs_mut()
                .clear()
                .append_pair("state", &state)
                .append_pair("code", &code);

            (
                jar,
                [
                    (HX_REDIRECT, redirect_uri.as_str().to_string()),
                    (
                        ACCESS_CONTROL_ALLOW_ORIGIN.as_str(),
                        redirect_uri.origin().ascii_serialization(),
                    ),
                ],
                Redirect::to(redirect_uri.as_str()),
            )
                .into_response()
        }
        Ok(AuthoriseResponse::ConsentRequested {
            client_name,
            scopes: _,
            pii_scopes,
            consent_token,
        }) => {
            // We can just render the form now, the consent token has everything we need.
            ConsentRequestView {
                client_name,
                // scopes,
                pii_scopes,
                consent_token,
                redirect: None,
            }
            .into_response()
        }

        Ok(AuthoriseResponse::AuthenticationRequired {
            client_name,
            login_hint,
        }) => {
            // Sign the auth req and hide it in our cookie - we'll come back for
            // you later.
            let maybe_jar =
                cookies::make_signed(&state, COOKIE_OAUTH2_REQ, &auth_req, Urls::Ui.as_ref())
                    .map(|mut cookie| {
                        cookie.set_same_site(SameSite::Strict);
                        jar.add(cookie)
                    })
                    .ok_or(OperationError::InvalidSessionState);

            match maybe_jar {
                Ok(jar) => {
                    let display_ctx = LoginDisplayCtx {
                        domain_info,
                        oauth2: Some(Oauth2Ctx { client_name }),
                        reauth: None,
                        error: None,
                    };

                    super::login::view_oauth2_get(jar, display_ctx, login_hint)
                }
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                }
                .into_response(),
            }
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            AccessDeniedView {
                operation_id: kopid.eventid,
            }
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

            UnrecoverableErrorView {
                err_code: OperationError::InvalidState,
                operation_id: kopid.eventid,
            }
            .into_response()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentForm {
    consent_token: String,
    #[serde(default)]
    #[allow(dead_code)] // TODO: do smoething with this
    redirect: Option<String>,
}

pub async fn view_consent_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(consent_form): Form<ConsentForm>,
) -> Result<Response, UnrecoverableErrorView> {
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
            let jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ);

            if let Some(redirect) = consent_form.redirect {
                Ok((
                    jar,
                    [
                        (HX_REDIRECT, redirect_uri.as_str().to_string()),
                        (
                            ACCESS_CONTROL_ALLOW_ORIGIN.as_str(),
                            redirect_uri.origin().ascii_serialization(),
                        ),
                    ],
                    Redirect::to(&redirect),
                )
                    .into_response())
            } else {
                redirect_uri
                    .query_pairs_mut()
                    .clear()
                    .append_pair("state", &state)
                    .append_pair("code", &code);
                Ok((
                    jar,
                    [
                        (HX_REDIRECT, redirect_uri.as_str().to_string()),
                        (
                            ACCESS_CONTROL_ALLOW_ORIGIN.as_str(),
                            redirect_uri.origin().ascii_serialization(),
                        ),
                    ],
                    Redirect::to(redirect_uri.as_str()),
                )
                    .into_response())
            }
        }
        Err(err_code) => {
            error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &err_code.to_string()
            );

            Err(UnrecoverableErrorView {
                err_code: OperationError::InvalidState,
                operation_id: kopid.eventid,
            })
        }
    }
}

#[derive(Template, Debug, Clone)]
#[cfg(feature = "dev-oauth2-device-flow")]
#[template(path = "oauth2_device_login.html")]
pub struct Oauth2DeviceLoginView {
    domain_custom_image: bool,
    title: String,
    user_code: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg(feature = "dev-oauth2-device-flow")]
pub(crate) struct QueryUserCode {
    pub user_code: Option<String>,
}

#[axum::debug_handler]
#[cfg(feature = "dev-oauth2-device-flow")]
pub async fn view_device_get(
    State(state): State<ServerState>,
    Extension(_kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Query(user_code): Query<QueryUserCode>,
) -> Result<Oauth2DeviceLoginView, (StatusCode, String)> {
    // TODO: if we have a valid auth session and the user code is valid, prompt the user to allow the session to start
    Ok(Oauth2DeviceLoginView {
        domain_custom_image: state.qe_r_ref.domain_info_read().has_custom_image(),
        title: "Device Login".to_string(),
        user_code: user_code.user_code.unwrap_or("".to_string()),
    })
}

#[derive(Deserialize)]
#[cfg(feature = "dev-oauth2-device-flow")]
pub struct Oauth2DeviceLoginForm {
    user_code: String,
    confirm_login: bool,
}

#[cfg(feature = "dev-oauth2-device-flow")]
#[axum::debug_handler]
pub async fn view_device_post(
    State(_state): State<ServerState>,
    Extension(_kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Form(form): Form<Oauth2DeviceLoginForm>,
) -> Result<String, (StatusCode, &'static str)> {
    debug!("User code: {}", form.user_code);
    debug!("User confirmed: {}", form.confirm_login);

    // TODO: when the user POST's this form we need to check the user code and see if it's valid
    // then start a login flow which ends up authorizing the token at the end.
    Err((StatusCode::NOT_IMPLEMENTED, "Not implemented yet"))
}
