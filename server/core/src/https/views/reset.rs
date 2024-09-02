use askama::Template;
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{ErrorResponse, IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use axum_htmx::{
    HxEvent, HxLocation, HxPushUrl, HxRequest, HxReselect, HxResponseTrigger, HxReswap, HxRetarget,
    SwapOption,
};
use futures_util::TryFutureExt;
use qrcode::render::svg;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt;
use std::fmt::{Display, Formatter};
use uuid::Uuid;

use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CURegState, CURegWarning, CURequest, CUSessionToken, CUStatus,
    CredentialDetail, OperationError, PasskeyDetail, PasswordFeedback, TotpAlgo, UserAuthToken,
    COOKIE_CU_SESSION_TOKEN,
};

use super::constants::Urls;
use crate::https::extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::constants::ProfileMenuItems;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use crate::https::ServerState;

use super::UnrecoverableErrorView;

#[derive(Template)]
#[template(path = "user_settings.html")]
struct ProfileView {
    profile_partial: CredStatusView,
}

#[derive(Template)]
#[template(path = "credentials_reset_form.html")]
struct ResetCredFormView {
    domain_info: DomainInfoRead,
    wrong_code: bool,
}

#[derive(Template)]
#[template(path = "credentials_reset.html")]
struct CredResetView {
    domain_info: DomainInfoRead,
    names: String,
    credentials_update_partial: CredResetPartialView,
}

#[derive(Template)]
#[template(path = "credentials_status.html")]
struct CredStatusView {
    domain_info: DomainInfoRead,
    menu_active_item: ProfileMenuItems,
    names: String,
    credentials_update_partial: CredResetPartialView,
}

#[derive(Template)]
#[template(path = "credentials_update_partial.html")]
struct CredResetPartialView {
    ext_cred_portal: CUExtPortal,
    warnings: Vec<CURegWarning>,
    attested_passkeys_state: CUCredState,
    passkeys_state: CUCredState,
    primary_state: CUCredState,
    attested_passkeys: Vec<PasskeyDetail>,
    passkeys: Vec<PasskeyDetail>,
    primary: Option<CredentialDetail>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
// Needs to be visible so axum can create this struct
pub(crate) struct ResetTokenParam {
    token: Option<String>,
}

#[derive(Template)]
#[template(path = "credential_update_add_password_partial.html")]
struct AddPasswordPartial {
    check_res: PwdCheckResult,
}

#[derive(Serialize, Deserialize, Debug)]
enum PwdCheckResult {
    Success,
    Init,
    Failure {
        pwd_equal: bool,
        warnings: Vec<PasswordFeedback>,
    },
}

#[derive(Deserialize, Debug)]
pub(crate) struct NewPassword {
    new_password: String,
    new_password_check: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct NewTotp {
    name: String,
    #[serde(rename = "checkTOTPCode")]
    check_totpcode: u32,
    #[serde(rename = "ignoreBrokenApp")]
    ignore_broken_app: bool,
}

#[derive(Template)]
#[template(path = "credential_update_add_passkey_partial.html")]
struct AddPasskeyPartial {
    // Passkey challenge for adding a new passkey
    challenge: String,
    class: PasskeyClass,
}

#[derive(Deserialize, Debug)]
struct PasskeyCreateResponse {}

#[derive(Deserialize, Debug)]
struct PasskeyCreateExtensions {}

#[derive(Deserialize, Debug)]
pub(crate) struct PasskeyInitForm {
    class: PasskeyClass,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PasskeyCreateForm {
    name: String,
    class: PasskeyClass,
    #[serde(rename = "creationData")]
    creation_data: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PasskeyRemoveData {
    uuid: Uuid,
}

#[derive(Deserialize, Debug)]
pub(crate) struct TOTPRemoveData {
    name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum TotpCheckResult {
    Init {
        secret: String,
        qr_code_svg: String,
        steps: u64,
        digits: u8,
        algo: TotpAlgo,
        uri: String,
    },
    Failure {
        wrong_code: bool,
        broken_app: bool,
        warnings: Vec<TotpFeedback>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum TotpFeedback {
    BlankName,
    DuplicateName,
}

impl Display for TotpFeedback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TotpFeedback::BlankName => write!(f, "Please enter a name."),
            TotpFeedback::DuplicateName => write!(
                f,
                "This name already exists, choose another or remove the existing one."
            ),
        }
    }
}

#[derive(Template)]
#[template(path = "credential_update_add_totp_partial.html")]
struct AddTotpPartial {
    check_res: TotpCheckResult,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum PasskeyClass {
    Any,
    Attested,
}

impl Display for PasskeyClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PasskeyClass::Any => write!(f, "Any"),
            PasskeyClass::Attested => write!(f, "Attested"),
        }
    }
}

pub(crate) async fn commit(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    state
        .qe_w_ref
        .handle_idmcredentialupdatecommit(cu_session_token, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok((HxLocation::from(Uri::from_static("/ui")), "").into_response())
}

pub(crate) async fn cancel_cred_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    state
        .qe_w_ref
        .handle_idmcredentialupdatecancel(cu_session_token, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok((
        HxLocation::from(Uri::from_static(Urls::Profile.as_ref())),
        "",
    )
        .into_response())
}

pub(crate) async fn cancel_mfareg(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::CancelMFAReg, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_alt_creds(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::PrimaryRemove, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_totp(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(totp): Form<TOTPRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::TotpRemove(totp.name),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(passkey): Form<PasskeyRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::PasskeyRemove(passkey.uuid),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn finish_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(passkey_create): Form<PasskeyCreateForm>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(jar).await?;

    match serde_json::from_str(passkey_create.creation_data.as_str()) {
        Ok(creation_data) => {
            let cu_request = match passkey_create.class {
                PasskeyClass::Any => CURequest::PasskeyFinish(passkey_create.name, creation_data),
                PasskeyClass::Attested => {
                    CURequest::AttestedPasskeyFinish(passkey_create.name, creation_data)
                }
            };

            let cu_status = state
                .qe_r_ref
                .handle_idmcredentialupdate(cu_session_token, cu_request, kopid.eventid)
                .map_err(|op_err| HtmxError::new(&kopid, op_err))
                .await?;

            Ok(get_cu_partial_response(cu_status))
        }
        Err(e) => {
            error!("Bad request for passkey creation: {e}");
            Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                HtmxError::new(&kopid, OperationError::Backend).into_response(),
            )
                .into_response())
        }
    }
}

pub(crate) async fn view_new_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(init_form): Form<PasskeyInitForm>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(jar).await?;
    let cu_req = match init_form.class {
        PasskeyClass::Any => CURequest::PasskeyInit,
        PasskeyClass::Attested => CURequest::AttestedPasskeyInit,
    };

    let cu_status: CUStatus = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, cu_req, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let response = match cu_status.mfaregstate {
        CURegState::Passkey(chal) | CURegState::AttestedPasskey(chal) => {
            if let Ok(challenge) = serde_json::to_string(&chal) {
                AddPasskeyPartial {
                    challenge,
                    class: init_form.class,
                }
                .into_response()
            } else {
                UnrecoverableErrorView {
                    err_code: OperationError::UI0001ChallengeSerialisation,
                    operation_id: kopid.eventid,
                }
                .into_response()
            }
        }
        _ => UnrecoverableErrorView {
            err_code: OperationError::UI0002InvalidState,
            operation_id: kopid.eventid,
        }
        .into_response(),
    };

    let passkey_init_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addPasskeySwapped".to_string())]);
    Ok((
        passkey_init_trigger,
        HxPushUrl(Uri::from_static("/ui/reset/add_passkey")),
        response,
    )
        .into_response())
}

pub(crate) async fn view_new_totp(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    opt_form: Option<Form<NewTotp>>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(jar).await?;
    let push_url = HxPushUrl(Uri::from_static("/ui/reset/add_totp"));
    let swapped_handler_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addTotpSwapped".to_string())]);

    let new_totp = match opt_form {
        // Initial response handling, user is entering the form for first time
        None => {
            let cu_status = state
                .qe_r_ref
                .handle_idmcredentialupdate(
                    cu_session_token,
                    CURequest::TotpGenerate,
                    kopid.eventid,
                )
                .await
                // TODO: better handling for invalid mfaregstate state, can be invalid if certain mfa flows were interrupted
                // TODO: We should maybe automatically cancel the other MFA reg
                .map_err(|op_err| HtmxError::new(&kopid, op_err))?;

            let partial = if let CURegState::TotpCheck(secret) = cu_status.mfaregstate {
                let uri = secret.to_uri();
                let svg = match QrCode::new(uri.as_str()) {
                    Ok(qr) => qr.render::<svg::Color>().build(),
                    Err(qr_err) => {
                        error!("Failed to create TOTP QR code: {qr_err}");
                        "QR Code Generation Failed".to_string()
                    }
                };

                AddTotpPartial {
                    check_res: TotpCheckResult::Init {
                        secret: secret.get_secret(),
                        qr_code_svg: svg,
                        steps: secret.step,
                        digits: secret.digits,
                        algo: secret.algo,
                        uri,
                    },
                }
            } else {
                return Err(ErrorResponse::from(HtmxError::new(
                    &kopid,
                    OperationError::CannotStartMFADuringOngoingMFASession,
                )));
            };

            return Ok((swapped_handler_trigger, push_url, partial).into_response());
        }

        // User has submitted a totp code
        Some(Form(new_totp)) => new_totp,
    };

    let cu_status = if new_totp.ignore_broken_app {
        // Cope with SHA1 apps because the user has intended to do so, their totp code was already verified
        state.qe_r_ref.handle_idmcredentialupdate(
            cu_session_token,
            CURequest::TotpAcceptSha1,
            kopid.eventid,
        )
    } else {
        // Validate totp code example
        state.qe_r_ref.handle_idmcredentialupdate(
            cu_session_token,
            CURequest::TotpVerify(new_totp.check_totpcode, new_totp.name),
            kopid.eventid,
        )
    }
    .await
    .map_err(|op_err| HtmxError::new(&kopid, op_err))?;

    let warnings = vec![];
    let check_res = match &cu_status.mfaregstate {
        CURegState::None => return Ok(get_cu_partial_response(cu_status)),
        CURegState::TotpTryAgain => TotpCheckResult::Failure {
            wrong_code: true,
            broken_app: false,
            warnings,
        },
        CURegState::TotpInvalidSha1 => TotpCheckResult::Failure {
            wrong_code: false,
            broken_app: true,
            warnings,
        },
        CURegState::TotpCheck(_)
        | CURegState::BackupCodes(_)
        | CURegState::Passkey(_)
        | CURegState::AttestedPasskey(_) => {
            return Err(ErrorResponse::from(HtmxError::new(
                &kopid,
                OperationError::InvalidState,
            )))
        }
    };

    Ok((
        swapped_handler_trigger,
        push_url,
        AddTotpPartial { check_res },
    )
        .into_response())
}

pub(crate) async fn view_new_pwd(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    opt_form: Option<Form<NewPassword>>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;
    let swapped_handler_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addPasswordSwapped".to_string())]);

    let new_passwords = match opt_form {
        None => {
            return Ok((
                swapped_handler_trigger,
                AddPasswordPartial {
                    check_res: PwdCheckResult::Init,
                },
            )
                .into_response());
        }
        Some(Form(new_passwords)) => new_passwords,
    };

    let pwd_equal = new_passwords.new_password == new_passwords.new_password_check;
    let (warnings, status) = if pwd_equal {
        let res = state
            .qe_r_ref
            .handle_idmcredentialupdate(
                cu_session_token,
                CURequest::Password(new_passwords.new_password),
                kopid.eventid,
            )
            .await;
        match res {
            Ok(cu_status) => return Ok(get_cu_partial_response(cu_status)),
            Err(OperationError::PasswordQuality(password_feedback)) => {
                (password_feedback, StatusCode::UNPROCESSABLE_ENTITY)
            }
            Err(operr) => return Err(ErrorResponse::from(HtmxError::new(&kopid, operr))),
        }
    } else {
        (vec![], StatusCode::UNPROCESSABLE_ENTITY)
    };

    let check_res = PwdCheckResult::Failure {
        pwd_equal,
        warnings,
    };

    Ok((
        status,
        swapped_handler_trigger,
        HxPushUrl(Uri::from_static("/ui/reset/change_password")),
        AddPasswordPartial { check_res },
    )
        .into_response())
}

// Allows authenticated users to get a (cred update) or (reauth into cred update) page, depending on whether they have read write access or not respectively.
pub(crate) async fn view_self_reset_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    if can_rw {
        let (cu_session_token, cu_status) = state
            .qe_w_ref
            .handle_idmcredentialupdate(client_auth_info, uat.uuid.to_string(), kopid.eventid)
            .map_err(|op_err| HtmxError::new(&kopid, op_err))
            .await?;

        let cu_resp = get_cu_response(domain_info, cu_status, true);

        jar = add_cu_cookie(jar, &state, cu_session_token);
        Ok((jar, cu_resp).into_response())
    } else {
        let display_ctx = LoginDisplayCtx {
            domain_info,
            reauth: Some(Reauth {
                username: uat.spn,
                purpose: ReauthPurpose::ProfileSettings,
            }),
            error: None,
        };

        Ok(super::login::view_reauth_get(
            state,
            client_auth_info,
            kopid,
            jar,
            Urls::UpdateCredentials.as_ref(),
            display_ctx,
        )
        .await)
    }
}

// Adds the COOKIE_CU_SESSION_TOKEN to the jar and returns the result
fn add_cu_cookie(
    jar: CookieJar,
    state: &ServerState,
    cu_session_token: CUSessionToken,
) -> CookieJar {
    let mut token_cookie = Cookie::new(COOKIE_CU_SESSION_TOKEN, cu_session_token.token);
    token_cookie.set_secure(state.secure_cookies);
    token_cookie.set_same_site(SameSite::Strict);
    token_cookie.set_http_only(true);
    jar.add(token_cookie)
}

pub(crate) async fn view_reset_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Query(params): Query<ResetTokenParam>,
    mut jar: CookieJar,
) -> axum::response::Result<Response> {
    let push_url = HxPushUrl(Uri::from_static(Urls::CredReset.as_ref()));
    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
    let is_logged_in = state
        .qe_r_ref
        .handle_auth_valid(_client_auth_info.clone(), kopid.eventid)
        .await
        .is_ok();

    if let Some(cookie) = cookie {
        // We already have a session
        let cu_session_token = cookie.value();
        let cu_session_token = CUSessionToken {
            token: cu_session_token.into(),
        };
        let cu_status = match state
            .qe_r_ref
            .handle_idmcredentialupdatestatus(cu_session_token, kopid.eventid)
            .await
        {
            Ok(cu_status) => cu_status,
            Err(
                OperationError::SessionExpired
                | OperationError::InvalidSessionState
                | OperationError::InvalidState,
            ) => {
                // If our previous credential update session expired we want to see the reset form again.
                jar = jar.remove(Cookie::from(COOKIE_CU_SESSION_TOKEN));

                if let Some(token) = params.token {
                    let token_uri_string = format!("{}?token={}", Urls::CredReset, token);
                    return Ok((jar, Redirect::to(&token_uri_string)).into_response());
                }
                return Ok((jar, Redirect::to(Urls::CredReset.as_ref())).into_response());
            }
            Err(op_err) => return Ok(HtmxError::new(&kopid, op_err).into_response()),
        };

        // CU Session cookie is okay
        let cu_resp = get_cu_response(domain_info, cu_status, is_logged_in);
        Ok(cu_resp)
    } else if let Some(token) = params.token {
        // We have a reset token and want to create a new session
        match state
            .qe_w_ref
            .handle_idmcredentialexchangeintent(token, kopid.eventid)
            .await
        {
            Ok((cu_session_token, cu_status)) => {
                let cu_resp = get_cu_response(domain_info, cu_status, is_logged_in);

                jar = add_cu_cookie(jar, &state, cu_session_token);
                Ok((jar, cu_resp).into_response())
            }
            Err(OperationError::SessionExpired) | Err(OperationError::Wait(_)) => {
                // Reset code expired
                Ok((
                    push_url,
                    ResetCredFormView {
                        domain_info,
                        wrong_code: true,
                    },
                )
                    .into_response())
            }
            Err(op_err) => Err(ErrorResponse::from(
                HtmxError::new(&kopid, op_err).into_response(),
            )),
        }
    } else {
        // We don't have any credential, show reset token input form
        Ok((
            push_url,
            ResetCredFormView {
                domain_info,
                wrong_code: false,
            },
        )
            .into_response())
    }
}

fn get_cu_partial(cu_status: CUStatus) -> CredResetPartialView {
    let CUStatus {
        ext_cred_portal,
        warnings,
        passkeys_state,
        attested_passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
        ..
    } = cu_status;

    CredResetPartialView {
        ext_cred_portal,
        warnings,
        attested_passkeys_state,
        passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
    }
}

fn get_cu_partial_response(cu_status: CUStatus) -> Response {
    let credentials_update_partial = get_cu_partial(cu_status);
    (
        HxPushUrl(Uri::from_static(Urls::CredReset.as_ref())),
        HxRetarget("#credentialUpdateDynamicSection".to_string()),
        HxReselect("#credentialUpdateDynamicSection".to_string()),
        HxReswap(SwapOption::OuterHtml),
        credentials_update_partial,
    )
        .into_response()
}

fn get_cu_response(
    domain_info: DomainInfoRead,
    cu_status: CUStatus,
    is_logged_in: bool,
) -> Response {
    let spn = cu_status.spn.clone();
    let displayname = cu_status.displayname.clone();
    let (username, _domain) = spn.split_once('@').unwrap_or(("", &spn));
    let names = format!("{} ({})", displayname, username);
    let credentials_update_partial = get_cu_partial(cu_status);

    if is_logged_in {
        let cred_status_view = CredStatusView {
            menu_active_item: ProfileMenuItems::Credentials,
            domain_info,
            names,
            credentials_update_partial,
        };

        (
            HxPushUrl(Uri::from_static(Urls::UpdateCredentials.as_ref())),
            ProfileView {
                profile_partial: cred_status_view,
            },
        )
            .into_response()
    } else {
        (
            HxPushUrl(Uri::from_static(Urls::CredReset.as_ref())),
            CredResetView {
                domain_info,
                names,
                credentials_update_partial,
            },
        )
            .into_response()
    }
}

async fn get_cu_session(jar: CookieJar) -> Result<CUSessionToken, Response> {
    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
    if let Some(cookie) = cookie {
        let cu_session_token = cookie.value();
        let cu_session_token = CUSessionToken {
            token: cu_session_token.into(),
        };
        Ok(cu_session_token)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Redirect::to(Urls::CredReset.as_ref()),
        )
            .into_response())
    }
}
