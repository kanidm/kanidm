use askama::Template;

use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use compact_jwt::{Jws, JwsSigner};

use kanidmd_lib::prelude::OperationError;

use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthStep,
};

use kanidmd_lib::prelude::*;

use kanidm_proto::internal::{COOKIE_AUTH_SESSION_ID, COOKIE_BEARER_TOKEN, COOKIE_USERNAME};

use kanidmd_lib::idm::AuthState;

use kanidmd_lib::idm::event::AuthResult;

use crate::https::{extractors::VerifiedClientInformation, middleware::KOpId, ServerState};

use webauthn_rs::prelude::PublicKeyCredential;

use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::{empty_string_as_none, HtmlTemplate, UnrecoverableErrorView};

#[derive(Default, Serialize, Deserialize)]
struct SessionContext {
    #[serde(rename = "u")]
    username: String,

    #[serde(rename = "r")]
    remember_me: bool,

    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginView {
    username: String,
    remember_me: bool,
}

pub struct Mech<'a> {
    name: AuthMech,
    value: &'a str,
}

#[derive(Template)]
#[template(path = "login_mech_choose.html")]
struct LoginMechView<'a> {
    mechs: Vec<Mech<'a>>,
}

#[derive(Default)]
enum LoginTotpError {
    #[default]
    None,
    Syntax,
}

#[derive(Template, Default)]
#[template(path = "login_totp.html")]
struct LoginTotpView {
    totp: String,
    errors: LoginTotpError,
}

#[derive(Template)]
#[template(path = "login_password.html")]
struct LoginPasswordView {
    password: String,
}

#[derive(Template)]
#[template(path = "login_backupcode.html")]
struct LoginBackupCodeView {}

#[derive(Template)]
#[template(path = "login_webauthn.html")]
struct LoginWebauthnView {
    // Control if we are rendering in security key or passkey mode.
    passkey: bool,
    // chal: RequestChallengeResponse,
    chal: String,
}

pub async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            Redirect::to("/ui/apps").into_response()
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.
            let username = jar
                .get(COOKIE_USERNAME)
                .map(|c| c.value().to_string())
                .unwrap_or_default();

            let remember_me = !username.is_empty();

            HtmlTemplate(LoginView {
                username,
                remember_me,
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
pub struct LoginBeginForm {
    username: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    password: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    totp: Option<String>,
    #[serde(default)]
    remember_me: Option<u8>,
}

pub async fn view_login_begin_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_begin_form): Form<LoginBeginForm>,
) -> Response {
    let LoginBeginForm {
        username,
        password,
        totp,
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
                    username: username.clone(),
                    issue: AuthIssueSession::Cookie,
                    privileged: false,
                },
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    let remember_me = remember_me.is_some();

    let session_context = SessionContext {
        id: None,
        username,
        password,
        totp,
        remember_me,
    };

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
            )
            .await
            {
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

#[derive(Debug, Clone, Deserialize)]
pub struct LoginMechForm {
    mech: AuthMech,
}

pub async fn view_login_mech_choose_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_mech_form): Form<LoginMechForm>,
) -> Response {
    let session_context = jar
        .get(COOKIE_AUTH_SESSION_ID)
        .map(|c| c.value())
        .and_then(|s| {
            trace!(id_jws = %s);
            state.deserialise_from_str::<SessionContext>(s)
        })
        .unwrap_or_default();

    debug!("Session ID: {:?}", session_context.id);

    let LoginMechForm { mech } = login_mech_form;

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            session_context.id,
            AuthRequest {
                step: AuthStep::Begin(mech),
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
            )
            .await
            {
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

#[derive(Debug, Clone, Deserialize)]
pub struct LoginTotpForm {
    totp: String,
}

pub async fn view_login_totp_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_totp_form): Form<LoginTotpForm>,
) -> Response {
    // trim leading and trailing white space.
    let Ok(totp) = u32::from_str(&login_totp_form.totp.trim()) else {
        // If not an int, we need to re-render with an error
        return HtmlTemplate(LoginTotpView {
            totp: String::default(),
            errors: LoginTotpError::Syntax,
        })
        .into_response();
    };

    let auth_cred = AuthCredential::Totp(totp);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginPwForm {
    password: String,
}

pub async fn view_login_pw_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_pw_form): Form<LoginPwForm>,
) -> Response {
    let auth_cred = AuthCredential::Password(login_pw_form.password);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBackupCodeForm {
    backupcode: String,
}

pub async fn view_login_backupcode_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_bc_form): Form<LoginBackupCodeForm>,
) -> Response {
    // People (like me) may copy-paste the bc with whitespace that causes issues. Trim it now.
    let trimmed = login_bc_form.backupcode.trim().to_string();
    let auth_cred = AuthCredential::BackupCode(trimmed);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

pub async fn view_login_passkey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::Passkey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

pub async fn view_login_seckey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::SecurityKey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

async fn credential_step(
    state: ServerState,
    kopid: KOpId,
    jar: CookieJar,
    client_auth_info: ClientAuthInfo,
    auth_cred: AuthCredential,
) -> Response {
    let session_context = jar
        .get(COOKIE_AUTH_SESSION_ID)
        .map(|c| c.value())
        .and_then(|s| {
            trace!(id_jws = %s);
            state.deserialise_from_str::<SessionContext>(s)
        })
        .unwrap_or_default();

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            session_context.id,
            AuthRequest {
                step: AuthStep::Cred(auth_cred),
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
            )
            .await
            {
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

async fn view_login_step(
    state: ServerState,
    kopid: KOpId,
    mut jar: CookieJar,
    auth_result: AuthResult,
    client_auth_info: ClientAuthInfo,
    mut session_context: SessionContext,
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
                // Set the sessionid.
                session_context.id = Some(sessionid);
                let jws = Jws::into_json(&session_context).map_err(|e| {
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
                    _ => {
                        let mechs = allowed
                            .into_iter()
                            .map(|m| Mech {
                                value: m.to_value(),
                                name: m,
                            })
                            .collect();
                        HtmlTemplate(LoginMechView { mechs }).into_response()
                    }
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
                            AuthAllowed::Totp => HtmlTemplate(LoginTotpView {
                                totp: session_context.totp.clone().unwrap_or_default(),
                                ..Default::default()
                            })
                            .into_response(),
                            AuthAllowed::Password => HtmlTemplate(LoginPasswordView {
                                password: session_context.password.clone().unwrap_or_default(),
                            })
                            .into_response(),
                            AuthAllowed::BackupCode => {
                                HtmlTemplate(LoginBackupCodeView {}).into_response()
                            }
                            AuthAllowed::SecurityKey(chal) => {
                                let chal_json = serde_json::to_string(&chal).unwrap();
                                HtmlTemplate(LoginWebauthnView {
                                    passkey: false,
                                    chal: chal_json,
                                })
                                .into_response()
                            }
                            AuthAllowed::Passkey(chal) => {
                                let chal_json = serde_json::to_string(&chal).unwrap();
                                HtmlTemplate(LoginWebauthnView {
                                    passkey: true,
                                    chal: chal_json,
                                })
                                .into_response()
                            }
                            _ => return Err(OperationError::InvalidState),
                        }
                    }
                    _ => {
                        // We have changed auth session to only ever return one possibility, and
                        // that one option encodes the possible challenges.
                        return Err(OperationError::InvalidState);
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

                        jar = if session_context.remember_me {
                            let mut username_cookie =
                                Cookie::new(COOKIE_USERNAME, session_context.username.clone());
                            username_cookie.set_secure(state.secure_cookies);
                            username_cookie.set_same_site(SameSite::Strict);
                            username_cookie.set_http_only(true);
                            username_cookie.set_domain(state.domain.clone());
                            username_cookie.set_path("/");
                            jar.add(username_cookie)
                        } else {
                            jar
                        };

                        jar = jar
                            .add(bearer_cookie)
                            .remove(Cookie::from(COOKIE_AUTH_SESSION_ID));

                        let res = Redirect::to("/ui/apps").into_response();

                        break res;
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
