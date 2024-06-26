use askama::Template;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

// use axum_htmx::HxRequestGuardLayer;

use compact_jwt::{Jws, JwsSigner};

use kanidmd_lib::prelude::{OperationError, Uuid};

use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthRequest, AuthStep};

use kanidmd_lib::prelude::*;

use kanidm_proto::internal::{COOKIE_AUTH_SESSION_ID, COOKIE_BEARER_TOKEN};

use kanidmd_lib::idm::AuthState;

use kanidmd_lib::idm::event::AuthResult;

use serde::Deserialize;

use crate::https::{
    extractors::VerifiedClientInformation, middleware::KOpId, v1::SessionId, ServerState,
};

#[derive(Template)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginView<'a> {
    username: &'a str,
    remember_me: bool,
}

#[derive(Template)]
#[template(path = "login_totp_partial.html")]
struct LoginTotpPartialView {}

pub(crate) async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    _jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            Redirect::temporary("/ui/apps").into_response()
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.

            HtmlTemplate(LoginView {
                username: "",
                remember_me: false,
            })
            .into_response()
        }
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct LoginBeginForm {
    username: String,
    #[serde(default)]
    remember_me: Option<u8>,
}

async fn partial_view_login_begin_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_begin_form): Form<LoginBeginForm>,
) -> Response {
    trace!(?login_begin_form);

    let LoginBeginForm {
        username,
        remember_me,
    } = login_begin_form;

    trace!(?remember_me);

    // Init the login.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            None,
            AuthRequest {
                step: AuthStep::Init2 {
                    username,
                    issue: AuthIssueSession::Cookie,
                    privileged: false,
                },
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match partial_view_login_step(state, kopid.clone(), jar, ar, client_auth_info).await {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                })
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

async fn partial_view_login_step(
    state: ServerState,
    kopid: KOpId,
    mut jar: CookieJar,
    auth_result: AuthResult,
    client_auth_info: ClientAuthInfo,
) -> Result<Response, OperationError> {
    trace!(?auth_result);

    let AuthResult {
        state: mut auth_state,
        sessionid,
    } = auth_result;

    let mut safety = 3;

    // Unlike the api version, only set the cookie.
    let response = loop {
        if safety == 0 {
            error!("loop safety triggered - auth state was unable to resolve. This should NEVER HAPPEN.");
            debug_assert!(false);
            return Err(OperationError::InvalidSessionState);
        }
        // The slow march to the heat death of the loop.
        safety -= 1;

        match auth_state {
            AuthState::Choose(allowed) => {
                debug!("🧩 -> AuthState::Choose");
                let kref = &state.jws_signer;
                let jws = Jws::into_json(&SessionId { sessionid }).map_err(|e| {
                    error!(?e);
                    OperationError::InvalidSessionState
                })?;

                // Get the header token ready.
                let token = kref.sign(&jws).map(|jwss| jwss.to_string()).map_err(|e| {
                    error!(?e);
                    OperationError::InvalidSessionState
                })?;

                let mut token_cookie = Cookie::new(COOKIE_AUTH_SESSION_ID, token);
                token_cookie.set_secure(state.secure_cookies);
                token_cookie.set_same_site(SameSite::Strict);
                token_cookie.set_http_only(true);
                // Not setting domains limits the cookie to precisely this
                // url that was used.
                // token_cookie.set_domain(state.domain.clone());
                jar = jar.add(token_cookie);

                let res = match allowed.len() {
                    // Should never happen.
                    0 => {
                        error!("auth state choose allowed mechs is empty");
                        HtmlTemplate(UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                        })
                        .into_response()
                    }
                    1 => {
                        let mech = allowed[0].clone();
                        // submit the choice and then loop updating our auth_state.
                        let inter = state // This may change in the future ...
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthRequest {
                                    step: AuthStep::Begin(mech),
                                },
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;

                        // Set the state now for the next loop.
                        auth_state = inter.state;

                        // Autoselect was hit.
                        continue;
                    }
                    // Render the list of options.
                    _ => todo!(),
                };
                // break acts as return in a loop.
                break res;
            }
            AuthState::Continue(allowed) => {
                let res = match allowed.len() {
                    // Shouldn't be possible.
                    0 => {
                        error!("auth state continued allowed mechs is empty");
                        HtmlTemplate(UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                        })
                        .into_response()
                    }
                    1 => {
                        let auth_allowed = allowed[0].clone();

                        match auth_allowed {
                            AuthAllowed::Totp => {
                                HtmlTemplate(LoginTotpPartialView {}).into_response()
                            }
                            _ => todo!(),
                        }
                    }
                    _ => {
                        todo!();
                    }
                };

                // break acts as return in a loop.
                break res;
            }
            AuthState::Success(token, issue) => {
                debug!("🧩 -> AuthState::Success");

                match issue {
                    AuthIssueSession::Token => {
                        error!(
                            "Impossible state, should not recieve token in a htmx view auth flow"
                        );
                        return Err(OperationError::InvalidState);
                    }
                    AuthIssueSession::Cookie => {
                        // Update jar
                        let token_str = token.to_string();
                        let mut bearer_cookie = Cookie::new(COOKIE_BEARER_TOKEN, token_str.clone());
                        bearer_cookie.set_secure(state.secure_cookies);
                        bearer_cookie.set_same_site(SameSite::Lax);
                        bearer_cookie.set_http_only(true);
                        // We set a domain here because it allows subdomains
                        // of the idm to share the cookie. If domain was incorrect
                        // then webauthn won't work anyway!
                        bearer_cookie.set_domain(state.domain.clone());
                        bearer_cookie.set_path("/");
                        jar = jar
                            .add(bearer_cookie)
                            .remove(Cookie::from(COOKIE_AUTH_SESSION_ID));

                        // Send the redirect.
                        break Redirect::temporary("/ui/apps").into_response();
                    }
                }
            }
            AuthState::Denied(_reason) => {
                debug!("🧩 -> AuthState::Denied");
                jar = jar.remove(Cookie::from(COOKIE_AUTH_SESSION_ID));

                // Render a denial.
                break Redirect::temporary("/ui/getrekt").into_response();
            }
        }
    };

    Ok((jar, response).into_response())
}

pub fn view_router() -> Router<ServerState> {
    Router::new()
        .route("/", get(view_index_get))
        // Anything that is a partial only works if triggered from htmx
        // .layer(HxRequestGuardLayer::default())
        .route("/api/login_begin", post(partial_view_login_begin_post))
}

struct HtmlTemplate<T>(T);

/// Allows us to convert Askama HTML templates into valid HTML for axum to serve in the response.
impl<T> IntoResponse for HtmlTemplate<T>
where
    T: askama::Template,
{
    fn into_response(self) -> Response {
        // Attempt to render the template with askama
        match self.0.render() {
            // If we're able to successfully parse and aggregate the template, serve it
            Ok(html) => Html(html).into_response(),
            // If we're not, return an error or some bit of fallback HTML
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}

/*
/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;
    use std::str::FromStr;

    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s)
            .map_err(serde::de::Error::custom)
            .map(Some),
    }
}

*/
