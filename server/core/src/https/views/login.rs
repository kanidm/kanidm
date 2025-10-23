use super::constants::Urls;
use super::{cookies, empty_string_as_none, UnrecoverableErrorView};
use crate::https::views::errors::HtmxError;
use crate::https::{
    extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation},
    middleware::KOpId,
    ServerState,
};
use askama::Template;
use askama_web::WebTemplate;

use axum::http::HeaderMap;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};
use axum_extra::extract::cookie::{CookieJar, SameSite};
use hyper::Uri;
use kanidm_proto::internal::{
    UserAuthToken, COOKIE_AUTH_SESSION_ID, COOKIE_BEARER_TOKEN, COOKIE_CU_SESSION_TOKEN,
    COOKIE_OAUTH2_REQ, COOKIE_USERNAME,
};
use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthStep,
};
use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::OperationError;
use kanidmd_lib::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use webauthn_rs::prelude::PublicKeyCredential;

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

    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    after_auth_loc: Option<String>,
}

#[derive(Clone)]
pub enum ReauthPurpose {
    ProfileSettings,
}

impl fmt::Display for ReauthPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileSettings => write!(f, "Profile and Settings"),
        }
    }
}
#[derive(Clone)]
pub enum LoginError {
    InvalidUsername,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUsername => write!(f, "Invalid username"),
        }
    }
}
#[derive(Clone)]
pub struct Reauth {
    pub username: String,
    pub purpose: ReauthPurpose,
}
#[derive(Clone)]
pub struct Oauth2Ctx {
    pub client_name: String,
}

#[derive(Clone)]
pub struct LoginDisplayCtx {
    pub domain_info: DomainInfoRead,
    // We only need this on the first re-auth screen to indicate what we are doing
    pub reauth: Option<Reauth>,
    pub oauth2: Option<Oauth2Ctx>,
    pub error: Option<LoginError>,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginView {
    display_ctx: LoginDisplayCtx,
    username: String,
    remember_me: bool,
}

pub struct Mech<'a> {
    name: AuthMech,
    value: &'a str,
    autofocus: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_mech_choose.html")]
struct LoginMechView<'a> {
    display_ctx: LoginDisplayCtx,
    mechs: Vec<Mech<'a>>,
}

#[derive(Default)]
enum LoginTotpError {
    #[default]
    None,
    Syntax,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_totp.html")]
struct LoginTotpView {
    display_ctx: LoginDisplayCtx,
    totp: String,
    errors: LoginTotpError,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_password.html")]
struct LoginPasswordView {
    display_ctx: LoginDisplayCtx,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_backupcode.html")]
struct LoginBackupCodeView {
    display_ctx: LoginDisplayCtx,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_webauthn.html")]
struct LoginWebauthnView {
    display_ctx: LoginDisplayCtx,
    // Control if we are rendering in security key or passkey mode.
    passkey: bool,
    // chal: RequestChallengeResponse,
    chal: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_denied.html")]
struct LoginDeniedView {
    display_ctx: LoginDisplayCtx,
    reason: String,
    operation_id: Uuid,
}

pub async fn view_logout_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
) -> Response {
    let response = if let Err(err_code) = state
        .qe_w_ref
        .handle_logout(client_auth_info, kopid.eventid)
        .await
    {
        UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response()
    } else {
        Redirect::to(Urls::Login.as_ref()).into_response()
    };

    // Always clear cookies even on an error.
    jar = cookies::destroy(jar, COOKIE_BEARER_TOKEN, &state);
    jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);
    jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);
    jar = cookies::destroy(jar, COOKIE_CU_SESSION_TOKEN, &state);

    (jar, response).into_response()
}

pub async fn view_reauth_to_referer_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, HtmxError> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let referer = headers.get("Referer").and_then(|hv| hv.to_str().ok());

    let redirect = referer.and_then(|some_referer| Uri::from_str(some_referer).ok());
    let redirect = redirect
        .as_ref()
        .map(|uri| uri.path())
        .unwrap_or(Urls::Apps.as_ref());

    let display_ctx = LoginDisplayCtx {
        domain_info,
        oauth2: None,
        reauth: Some(Reauth {
            username: uat.spn.clone(),
            purpose: ReauthPurpose::ProfileSettings,
        }),
        error: None,
    };

    Ok(view_reauth_get(state, client_auth_info, kopid, jar, redirect, display_ctx).await)
}

pub async fn view_reauth_get(
    state: ServerState,
    client_auth_info: ClientAuthInfo,
    kopid: KOpId,
    jar: CookieJar,
    return_location: &str,
    display_ctx: LoginDisplayCtx,
) -> Response {
    // No matter what, we always clear the stored oauth2 cookie to prevent
    // ui loops
    let jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);

    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info.clone(), kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            let inter = state
                .qe_r_ref
                .handle_reauth(
                    client_auth_info.clone(),
                    AuthIssueSession::Cookie,
                    kopid.eventid,
                )
                .await;

            // Now process the response if ok.
            match inter {
                Ok(ar) => {
                    let session_context = SessionContext {
                        id: Some(ar.sessionid),
                        username: "".to_string(),
                        password: None,
                        totp: None,
                        remember_me: false,
                        after_auth_loc: Some(return_location.to_string()),
                    };

                    match view_login_step(
                        state,
                        kopid.clone(),
                        jar,
                        ar,
                        client_auth_info,
                        session_context,
                        display_ctx.clone(),
                    )
                    .await
                    {
                        Ok(r) => r,
                        // Okay, these errors are actually REALLY bad.
                        Err(err_code) => UnrecoverableErrorView {
                            err_code,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.clone().domain_info,
                        }
                        .into_response(),
                    }
                }
                // Probably needs to be way nicer on login, especially something like no matching users ...
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info: display_ctx.domain_info,
                }
                .into_response(),
            }
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.

            let username = cookies::get_unsigned(&jar, COOKIE_USERNAME)
                .map(String::from)
                .unwrap_or_default();

            let remember_me = !username.is_empty();

            (
                jar,
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                },
            )
                .into_response()
        }
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info: display_ctx.domain_info,
        }
        .into_response(),
    }
}

pub fn view_oauth2_get(
    jar: CookieJar,
    display_ctx: LoginDisplayCtx,
    login_hint: Option<String>,
) -> Response {
    let (username, remember_me) = if let Some(login_hint) = login_hint {
        (login_hint, false)
    } else if let Some(cookie_username) =
        // cookie jar with remember me.
        jar.get(COOKIE_USERNAME).map(|c| c.value().to_string())
    {
        (cookie_username, true)
    } else {
        (String::default(), false)
    };

    (
        jar,
        LoginView {
            display_ctx,
            username,
            remember_me,
        },
    )
        .into_response()
}

pub async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Extension(kopid): Extension<KOpId>,
    jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    // No matter what, we always clear the stored oauth2 cookie to prevent
    // ui loops
    let jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            (jar, Redirect::to(Urls::Apps.as_ref())).into_response()
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.
            let username = jar
                .get(COOKIE_USERNAME)
                .map(|c| c.value().to_string())
                .unwrap_or_default();

            let remember_me = !username.is_empty();

            let display_ctx = LoginDisplayCtx {
                domain_info,
                oauth2: None,
                reauth: None,
                error: None,
            };

            (
                jar,
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                },
            )
                .into_response()
        }
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
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
    DomainInfo(domain_info): DomainInfo,
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
        username: username.clone(),
        password,
        totp,
        remember_me,
        after_auth_loc: None,
    };

    let mut display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
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
                display_ctx,
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => match err_code {
            OperationError::NoMatchingEntries => {
                display_ctx.error = Some(LoginError::InvalidUsername);
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                }
                .into_response()
            }
            _ => UnrecoverableErrorView {
                err_code,
                operation_id: kopid.eventid,
                domain_info,
            }
            .into_response(),
        },
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
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_mech_form): Form<LoginMechForm>,
) -> Response {
    let session_context =
        cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
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

    let display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
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
                display_ctx,
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginTotpForm {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    password: Option<String>,
    totp: String,
}

pub async fn view_login_totp_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
    Form(login_totp_form): Form<LoginTotpForm>,
) -> Response {
    // trim leading and trailing white space.
    let totp = match u32::from_str(login_totp_form.totp.trim()) {
        Ok(val) => val,
        Err(_) => {
            let display_ctx = LoginDisplayCtx {
                domain_info,
                oauth2: None,
                reauth: None,
                error: None,
            };
            // If not an int, we need to re-render with an error
            return LoginTotpView {
                display_ctx,
                totp: String::default(),
                errors: LoginTotpError::Syntax,
            }
            .into_response();
        }
    };

    // In some flows the PW manager may not have autocompleted the pw until
    // this point. This could be due to a re-auth flow which skips the username
    // prompt, the use of remember-me+return which then skips the autocomplete.
    //
    // In the case the pw *is* bg filled, we need to add it to the session context
    // here.
    //
    // It's probably not "optimal" to be getting the context out and signing it
    // here to re-add it, but it also helps keep the flow neater in general.

    if let Some(password_autofill) = login_totp_form.password {
        let mut session_context =
            cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
                .unwrap_or_default();

        session_context.password = Some(password_autofill);

        // If we can't write this back to the jar, we warn and move on.
        if let Ok(update_jar) = add_session_cookie(&state, jar.clone(), &session_context) {
            jar = update_jar;
        } else {
            warn!("Unable to update session_context, ignoring...");
        }
    }

    let auth_cred = AuthCredential::Totp(totp);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginPwForm {
    password: String,
}

pub async fn view_login_pw_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_pw_form): Form<LoginPwForm>,
) -> Response {
    let auth_cred = AuthCredential::Password(login_pw_form.password);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBackupCodeForm {
    backupcode: String,
}

pub async fn view_login_backupcode_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_bc_form): Form<LoginBackupCodeForm>,
) -> Response {
    // People (like me) may copy-paste the bc with whitespace that causes issues. Trim it now.
    let trimmed = login_bc_form.backupcode.trim().to_string();
    let auth_cred = AuthCredential::BackupCode(trimmed);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonedPublicKeyCredential {
    cred: String,
}

pub async fn view_login_passkey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(assertion): Form<JsonedPublicKeyCredential>,
) -> Response {
    let result = serde_json::from_str::<Box<PublicKeyCredential>>(assertion.cred.as_str());
    match result {
        Ok(pkc) => {
            let auth_cred = AuthCredential::Passkey(pkc);
            credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
        }
        Err(e) => {
            error!(err = ?e, "Unable to deserialize credential submission");
            HtmxError::new(&kopid, OperationError::SerdeJsonError, domain_info).into_response()
        }
    }
}

pub async fn view_login_seckey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::SecurityKey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

async fn credential_step(
    state: ServerState,
    kopid: KOpId,
    jar: CookieJar,
    client_auth_info: ClientAuthInfo,
    auth_cred: AuthCredential,
    domain_info: DomainInfoRead,
) -> Response {
    let session_context =
        cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
            .unwrap_or_default();

    let display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
    };

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
                display_ctx.clone(),
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info: display_ctx.domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
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
    display_ctx: LoginDisplayCtx,
) -> Result<Response, OperationError> {
    trace!(?auth_result);

    let AuthResult {
        state: mut auth_state,
        sessionid,
    } = auth_result;
    session_context.id = Some(sessionid);

    // This lets us break out the loop in case of a fault. Take that halting problem!
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
            AuthState::Choose(mut allowed) => {
                debug!("🧩 -> AuthState::Choose");

                jar = add_session_cookie(&state, jar, &session_context)?;

                let res = match allowed.len() {
                    // Should never happen.
                    0 => {
                        error!("auth state choose allowed mechs is empty");
                        UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.domain_info,
                        }
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
                        allowed.sort_unstable();
                        // Put strongest first.
                        allowed.reverse();

                        let mechs: Vec<_> = allowed
                            .into_iter()
                            .enumerate()
                            .map(|(i, m)| Mech {
                                value: m.to_value(),
                                name: m,
                                // Auto focus the first item, it's the strongest
                                // mechanism and the one we should optimise for.
                                autofocus: i == 0,
                            })
                            .collect();

                        LoginMechView { display_ctx, mechs }.into_response()
                    }
                };
                // break acts as return in a loop.
                break res;
            }
            AuthState::Continue(allowed) => {
                // Reauth inits its session here so we need to be able to add it's cookie here.
                jar = add_session_cookie(&state, jar, &session_context)?;

                let res = match allowed.len() {
                    // Shouldn't be possible.
                    0 => {
                        error!("auth state continued allowed mechs is empty");
                        UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.domain_info,
                        }
                        .into_response()
                    }
                    1 => {
                        let auth_allowed = allowed[0].clone();

                        match auth_allowed {
                            AuthAllowed::Totp => LoginTotpView {
                                display_ctx,
                                totp: session_context.totp.clone().unwrap_or_default(),
                                errors: LoginTotpError::default(),
                            }
                            .into_response(),
                            AuthAllowed::Password => LoginPasswordView {
                                display_ctx,
                                password: session_context.password.clone().unwrap_or_default(),
                            }
                            .into_response(),
                            AuthAllowed::BackupCode => {
                                LoginBackupCodeView { display_ctx }.into_response()
                            }
                            AuthAllowed::SecurityKey(chal) => {
                                let chal_json = serde_json::to_string(&chal)
                                    .map_err(|_| OperationError::SerdeJsonError)?;
                                LoginWebauthnView {
                                    display_ctx,
                                    passkey: false,
                                    chal: chal_json,
                                }
                                .into_response()
                            }
                            AuthAllowed::Passkey(chal) => {
                                let chal_json = serde_json::to_string(&chal)
                                    .map_err(|_| OperationError::SerdeJsonError)?;
                                LoginWebauthnView {
                                    display_ctx,
                                    passkey: true,
                                    chal: chal_json,
                                }
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
                            "Impossible state, should not receive token in a htmx view auth flow"
                        );
                        return Err(OperationError::InvalidState);
                    }
                    AuthIssueSession::Cookie => {
                        // Update jar
                        let token_str = token.to_string();

                        // Important - this can be make unsigned as token_str has its own
                        // signatures.
                        let mut bearer_cookie =
                            cookies::make_unsigned(&state, COOKIE_BEARER_TOKEN, token_str.clone());
                        // Important - can be permanent as the token has its own expiration time internally
                        bearer_cookie.make_permanent();

                        jar = if session_context.remember_me {
                            // Important - can be unsigned as username is just for remember
                            // me and no other purpose.
                            let mut username_cookie = cookies::make_unsigned(
                                &state,
                                COOKIE_USERNAME,
                                session_context.username.clone(),
                            );
                            username_cookie.make_permanent();
                            jar.add(username_cookie)
                        } else {
                            cookies::destroy(jar, COOKIE_USERNAME, &state)
                        };

                        jar = jar.add(bearer_cookie);

                        jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);

                        // Now, we need to decided where to go.
                        let res = if jar.get(COOKIE_OAUTH2_REQ).is_some() {
                            Redirect::to(Urls::Oauth2Resume.as_ref()).into_response()
                        } else if let Some(auth_loc) = session_context.after_auth_loc {
                            Redirect::to(auth_loc.as_str()).into_response()
                        } else {
                            Redirect::to(Urls::Apps.as_ref()).into_response()
                        };

                        break res;
                    }
                }
            }
            AuthState::Denied(reason) => {
                debug!("🧩 -> AuthState::Denied");
                jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);

                break LoginDeniedView {
                    display_ctx,
                    reason,
                    operation_id: kopid.eventid,
                }
                .into_response();
            }
        }
    };

    Ok((jar, response).into_response())
}

fn add_session_cookie(
    state: &ServerState,
    jar: CookieJar,
    session_context: &SessionContext,
) -> Result<CookieJar, OperationError> {
    cookies::make_signed(state, COOKIE_AUTH_SESSION_ID, session_context)
        .map(|mut cookie| {
            // Not needed when redirecting into this site
            cookie.set_same_site(SameSite::Strict);
            jar.add(cookie)
        })
        .ok_or(OperationError::InvalidSessionState)
}
