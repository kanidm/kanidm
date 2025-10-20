use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{ErrorResponse, IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use axum_extra::extract::cookie::SameSite;
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
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;

pub use sshkey_attest::proto::PublicKey as SshPublicKey;
pub use sshkeys::KeyType;

use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CURegState, CURegWarning, CURequest, CUSessionToken, CUStatus,
    CredentialDetail, OperationError, PasskeyDetail, PasswordFeedback, TotpAlgo, UiHint,
    UserAuthToken, COOKIE_CU_SESSION_TOKEN,
};
use kanidmd_lib::prelude::ClientAuthInfo;

use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::constants::ProfileMenuItems;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use crate::https::views::{cookies, KanidmHxEventName};
use crate::https::ServerState;

use super::UnrecoverableErrorView;

#[derive(Template, WebTemplate)]
#[template(path = "user_settings.html")]
struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: CredStatusView,
}

#[derive(Template, WebTemplate)]
#[template(path = "credentials_reset_form.html")]
struct ResetCredFormView {
    domain_info: DomainInfoRead,
    wrong_code: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "credentials_reset.html")]
struct CredResetView {
    domain_info: DomainInfoRead,
    names: String,
    credentials_update_partial: CredResetPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "credentials_status.html")]
struct CredStatusView {
    domain_info: DomainInfoRead,
    menu_active_item: ProfileMenuItems,
    names: String,
    credentials_update_partial: CredResetPartialView,
}

struct SshKey {
    key_type: KeyType,
    key: String,
    comment: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "credentials_update_partial.html")]
struct CredResetPartialView {
    ext_cred_portal: CUExtPortal,
    can_commit: bool,
    warnings: Vec<CURegWarning>,
    attested_passkeys_state: CUCredState,
    passkeys_state: CUCredState,
    primary_state: CUCredState,
    attested_passkeys: Vec<PasskeyDetail>,
    passkeys: Vec<PasskeyDetail>,
    primary: Option<CredentialDetail>,
    unixcred_state: CUCredState,
    unixcred: Option<CredentialDetail>,
    sshkeys_state: CUCredState,
    sshkeys: BTreeMap<String, SshKey>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
// Needs to be visible so axum can create this struct
pub(crate) struct ResetTokenParam {
    token: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "credential_update_add_password_partial.html")]
struct AddPasswordPartial {
    check_res: PwdCheckResult,
}

#[derive(Template, WebTemplate)]
#[template(path = "credential_update_set_unixcred_partial.html")]
struct SetUnixCredPartial {
    check_res: PwdCheckResult,
}

#[derive(Template, WebTemplate)]
#[template(path = "credential_update_add_ssh_publickey_partial.html")]
struct AddSshPublicKeyPartial {
    key_title: Option<String>,
    title_error: Option<String>,
    key_value: Option<String>,
    key_error: Option<String>,
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
pub(crate) struct NewPublicKey {
    title: String,
    key: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PublicKeyRemoveData {
    name: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct NewTotp {
    name: String,
    #[serde(rename = "checkTOTPCode")]
    check_totpcode: String,
    #[serde(rename = "ignoreBrokenApp")]
    ignore_broken_app: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "credential_update_add_passkey_partial.html")]
struct AddPasskeyPartial {
    // Passkey challenge for adding a new passkey
    challenge: String,
    class: PasskeyClass,
}

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
pub(crate) struct TotpInit {
    secret: String,
    qr_code_svg: String,
    steps: u64,
    digits: u8,
    algo: TotpAlgo,
    uri: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct TotpCheck {
    wrong_code: bool,
    broken_app: bool,
    bad_name: bool,
    taken_name: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "credential_update_add_totp_partial.html")]
struct AddTotpPartial {
    totp_init: Option<TotpInit>,
    totp_name: String,
    totp_value: String,
    check: TotpCheck,
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

/// When the credential update session is ended through a commit or discard of the changes
/// we need to redirect the user to a relevant location. This location depends on the sessions
/// current authentication state. If they are authenticated, they are sent to their profile. If
/// they are not authenticated, they are sent to the login screen.
async fn end_session_response(
    state: ServerState,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let is_logged_in = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await
        .is_ok();

    let redirect_location = if is_logged_in {
        Urls::Profile.as_ref()
    } else {
        Urls::Login.as_ref()
    };

    Ok((jar, HxLocation::from(redirect_location), "").into_response())
}

pub(crate) async fn commit(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    state
        .qe_w_ref
        .handle_idmcredentialupdatecommit(cu_session_token, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info))
        .await?;

    // No longer need the cookie jar.
    let jar = cookies::destroy(jar, COOKIE_CU_SESSION_TOKEN, &state);

    end_session_response(state, kopid, client_auth_info, jar).await
}

pub(crate) async fn cancel_cred_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    state
        .qe_w_ref
        .handle_idmcredentialupdatecancel(cu_session_token, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info))
        .await?;

    // No longer need the cookie jar.
    let jar = cookies::destroy(jar, COOKIE_CU_SESSION_TOKEN, &state);

    end_session_response(state, kopid, client_auth_info, jar).await
}

pub(crate) async fn cancel_mfareg(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::CancelMFAReg, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_alt_creds(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::PrimaryRemove, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_unixcred(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::UnixPasswordRemove,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_ssh_publickey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(publickey): Form<PublicKeyRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::SshPublicKeyRemove(publickey.name),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_totp(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(totp): Form<TOTPRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::TotpRemove(totp.name),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn remove_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(passkey): Form<PasskeyRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(
            cu_session_token,
            CURequest::PasskeyRemove(passkey.uuid),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    Ok(get_cu_partial_response(cu_status))
}

pub(crate) async fn finish_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(passkey_create): Form<PasskeyCreateForm>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(&jar).await?;

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
                .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
                .await?;

            Ok(get_cu_partial_response(cu_status))
        }
        Err(e) => {
            error!("Bad request for passkey creation: {e}");
            Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                HtmxError::new(&kopid, OperationError::Backend, domain_info).into_response(),
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
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(init_form): Form<PasskeyInitForm>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(&jar).await?;
    let cu_req = match init_form.class {
        PasskeyClass::Any => CURequest::PasskeyInit,
        PasskeyClass::Attested => CURequest::AttestedPasskeyInit,
    };

    let cu_status: CUStatus = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, cu_req, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
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
                    domain_info,
                }
                .into_response()
            }
        }
        _ => UnrecoverableErrorView {
            err_code: OperationError::UI0002InvalidState,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response(),
    };

    let passkey_init_trigger =
        HxResponseTrigger::after_swap([HxEvent::from(KanidmHxEventName::AddPasskeySwapped)]);
    Ok((
        passkey_init_trigger,
        HxPushUrl("/ui/reset/add_passkey".to_string()),
        response,
    )
        .into_response())
}

pub(crate) async fn view_new_totp(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(&jar).await?;
    let push_url = HxPushUrl("/ui/reset/add_totp".to_string());

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::TotpGenerate, kopid.eventid)
        .await
        // TODO: better handling for invalid mfaregstate state, can be invalid if certain mfa flows were interrupted
        // TODO: We should maybe automatically cancel the other MFA reg
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

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
            totp_init: Some(TotpInit {
                secret: secret.get_secret(),
                qr_code_svg: svg,
                steps: secret.step,
                digits: secret.digits,
                algo: secret.algo,
                uri,
            }),
            totp_name: Default::default(),
            totp_value: Default::default(),
            check: TotpCheck::default(),
        }
    } else {
        return Err(ErrorResponse::from(HtmxError::new(
            &kopid,
            OperationError::CannotStartMFADuringOngoingMFASession,
            domain_info,
        )));
    };

    Ok((push_url, partial).into_response())
}

pub(crate) async fn add_totp(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    new_totp_form: Form<NewTotp>,
) -> axum::response::Result<Response> {
    let cu_session_token = get_cu_session(&jar).await?;

    let check_totpcode = u32::from_str(&new_totp_form.check_totpcode).unwrap_or_default();
    let swapped_handler_trigger =
        HxResponseTrigger::after_swap([HxEvent::from(KanidmHxEventName::AddTotpSwapped)]);

    // If the user has not provided a name or added only spaces we exit early
    if new_totp_form.name.trim().is_empty() {
        return Ok((
            swapped_handler_trigger,
            AddTotpPartial {
                totp_init: None,
                totp_name: "".into(),
                totp_value: new_totp_form.check_totpcode.clone(),
                check: TotpCheck {
                    bad_name: true,
                    ..Default::default()
                },
            },
        )
            .into_response());
    }

    let cu_status = if new_totp_form.ignore_broken_app {
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
            CURequest::TotpVerify(check_totpcode, new_totp_form.name.clone()),
            kopid.eventid,
        )
    }
    .await
    .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let check = match &cu_status.mfaregstate {
        CURegState::None => return Ok(get_cu_partial_response(cu_status)),
        CURegState::TotpTryAgain => TotpCheck {
            wrong_code: true,
            ..Default::default()
        },
        CURegState::TotpNameTryAgain(val) => TotpCheck {
            taken_name: Some(val.clone()),
            ..Default::default()
        },
        CURegState::TotpInvalidSha1 => TotpCheck {
            broken_app: true,
            ..Default::default()
        },
        CURegState::TotpCheck(_)
        | CURegState::BackupCodes(_)
        | CURegState::Passkey(_)
        | CURegState::AttestedPasskey(_) => {
            return Err(ErrorResponse::from(HtmxError::new(
                &kopid,
                OperationError::InvalidState,
                domain_info,
            )))
        }
    };

    let check_totpcode = if check.wrong_code {
        String::default()
    } else {
        new_totp_form.check_totpcode.clone()
    };

    Ok((
        swapped_handler_trigger,
        AddTotpPartial {
            totp_init: None,
            totp_name: new_totp_form.name.clone(),
            totp_value: check_totpcode,
            check,
        },
    )
        .into_response())
}

#[axum::debug_handler]
pub(crate) async fn view_new_pwd(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(opt_form): Form<Option<NewPassword>>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;
    let swapped_handler_trigger =
        HxResponseTrigger::after_swap([HxEvent::from(KanidmHxEventName::AddPasswordSwapped)]);

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
        Some(new_passwords) => new_passwords,
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
            Err(operr) => {
                return Err(ErrorResponse::from(HtmxError::new(
                    &kopid,
                    operr,
                    domain_info,
                )))
            }
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
        HxPushUrl("/ui/reset/change_password".to_string()),
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
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    if can_rw {
        let (cu_session_token, cu_status) = state
            .qe_w_ref
            .handle_idmcredentialupdate(
                client_auth_info.clone(),
                uat.uuid.to_string(),
                kopid.eventid,
            )
            .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
            .await?;

        let cu_resp = get_cu_response(&uat.ui_hints, domain_info, cu_status, true);

        jar = add_cu_cookie(jar, &state, cu_session_token);
        Ok((jar, cu_resp).into_response())
    } else {
        let display_ctx = LoginDisplayCtx {
            domain_info,
            oauth2: None,
            reauth: Some(Reauth {
                username: uat.spn.clone(),
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
    let mut token_cookie =
        cookies::make_unsigned(state, COOKIE_CU_SESSION_TOKEN, cu_session_token.token);
    token_cookie.set_same_site(SameSite::Strict);
    jar.add(token_cookie)
}

pub(crate) async fn view_set_unixcred(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(opt_form): Form<Option<NewPassword>>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;
    let swapped_handler_trigger =
        HxResponseTrigger::after_swap([HxEvent::from(KanidmHxEventName::AddPasswordSwapped)]);

    let new_passwords = match opt_form {
        None => {
            return Ok((
                swapped_handler_trigger,
                SetUnixCredPartial {
                    check_res: PwdCheckResult::Init,
                },
            )
                .into_response());
        }
        Some(new_passwords) => new_passwords,
    };

    let pwd_equal = new_passwords.new_password == new_passwords.new_password_check;
    let (warnings, status) = if pwd_equal {
        let res = state
            .qe_r_ref
            .handle_idmcredentialupdate(
                cu_session_token,
                CURequest::UnixPassword(new_passwords.new_password),
                kopid.eventid,
            )
            .await;
        match res {
            Ok(cu_status) => return Ok(get_cu_partial_response(cu_status)),
            Err(OperationError::PasswordQuality(password_feedback)) => {
                (password_feedback, StatusCode::UNPROCESSABLE_ENTITY)
            }
            Err(operr) => {
                return Err(ErrorResponse::from(HtmxError::new(
                    &kopid,
                    operr,
                    domain_info,
                )))
            }
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
        HxPushUrl("/ui/reset/set_unixcred".to_string()),
        SetUnixCredPartial { check_res },
    )
        .into_response())
}

struct AddSshPublicKeyError {
    key: Option<String>,
    title: Option<String>,
}

pub(crate) async fn view_add_ssh_publickey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(opt_form): Form<Option<NewPublicKey>>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(&jar).await?;

    let new_key = match opt_form {
        None => {
            return Ok((AddSshPublicKeyPartial {
                key_title: None,
                title_error: None,
                key_value: None,
                key_error: None,
            },)
                .into_response());
        }
        Some(new_key) => new_key,
    };

    let (
        AddSshPublicKeyError {
            key: key_error,
            title: title_error,
        },
        status,
    ) = {
        let publickey = match SshPublicKey::from_string(&new_key.key) {
            Err(_) => {
                return Ok((AddSshPublicKeyPartial {
                    key_title: Some(new_key.title),
                    title_error: None,
                    key_value: Some(new_key.key),
                    key_error: Some("Key cannot be parsed".to_string()),
                },)
                    .into_response());
            }
            Ok(publickey) => publickey,
        };
        let res = state
            .qe_r_ref
            .handle_idmcredentialupdate(
                cu_session_token,
                CURequest::SshPublicKey(new_key.title.clone(), publickey),
                kopid.eventid,
            )
            .await;
        match res {
            Ok(cu_status) => return Ok(get_cu_partial_response(cu_status)),
            Err(e @ (OperationError::InvalidLabel | OperationError::DuplicateLabel)) => (
                AddSshPublicKeyError {
                    title: Some(e.to_string()),
                    key: None,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            Err(e @ OperationError::DuplicateKey) => (
                AddSshPublicKeyError {
                    key: Some(e.to_string()),
                    title: None,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            Err(operr) => {
                return Err(ErrorResponse::from(HtmxError::new(
                    &kopid,
                    operr,
                    domain_info,
                )))
            }
        }
    };

    Ok((
        status,
        HxPushUrl("/ui/reset/add_ssh_publickey".to_string()),
        AddSshPublicKeyPartial {
            key_title: Some(new_key.title),
            title_error,
            key_error,
            key_value: Some(new_key.key),
        },
    )
        .into_response())
}

pub(crate) async fn view_reset_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Query(params): Query<ResetTokenParam>,
    mut jar: CookieJar,
) -> axum::response::Result<Response> {
    let push_url = HxPushUrl(Urls::CredReset.to_string());
    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
    let is_logged_in = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info.clone(), kopid.eventid)
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
                jar = cookies::destroy(jar, COOKIE_CU_SESSION_TOKEN, &state);

                if let Some(token) = params.token {
                    let token_uri_string = format!("{}?token={}", Urls::CredReset, token);
                    return Ok((jar, Redirect::to(&token_uri_string)).into_response());
                }
                return Ok((jar, Redirect::to(Urls::CredReset.as_ref())).into_response());
            }
            Err(op_err) => {
                return Ok(HtmxError::new(&kopid, op_err, domain_info.clone()).into_response())
            }
        };

        // CU Session cookie is okay
        let cu_resp = get_cu_response(&Default::default(), domain_info, cu_status, is_logged_in);

        Ok(cu_resp)
    } else if let Some(token) = params.token {
        // We have a reset token and want to create a new session
        match state
            .qe_w_ref
            .handle_idmcredentialexchangeintent(token, kopid.eventid)
            .await
        {
            Ok((cu_session_token, cu_status)) => {
                let cu_resp =
                    get_cu_response(&Default::default(), domain_info, cu_status, is_logged_in);

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
                HtmxError::new(&kopid, op_err, domain_info).into_response(),
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
        can_commit,
        warnings,
        passkeys_state,
        attested_passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
        unixcred_state,
        unixcred,
        sshkeys_state,
        sshkeys,
        ..
    } = cu_status;

    let sshkeyss: BTreeMap<String, SshKey> = sshkeys
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                SshKey {
                    key_type: v.clone().key_type,
                    key: v.fingerprint().hash,
                    comment: v.comment.clone(),
                },
            )
        })
        .collect();

    CredResetPartialView {
        ext_cred_portal,
        can_commit,
        warnings,
        attested_passkeys_state,
        passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
        unixcred_state,
        unixcred,
        sshkeys_state,
        sshkeys: sshkeyss,
    }
}

fn get_cu_partial_response(cu_status: CUStatus) -> Response {
    let credentials_update_partial = get_cu_partial(cu_status);
    (
        HxPushUrl(Urls::CredReset.to_string()),
        HxRetarget("#credentialUpdateDynamicSection".to_string()),
        HxReselect("#credentialUpdateDynamicSection".to_string()),
        HxReswap(SwapOption::OuterHtml),
        credentials_update_partial,
    )
        .into_response()
}

fn get_cu_response(
    ui_hints: &BTreeSet<UiHint>,
    domain_info: DomainInfoRead,
    cu_status: CUStatus,
    is_logged_in: bool,
) -> Response {
    let spn = cu_status.spn.clone();
    let displayname = cu_status.displayname.clone();
    let (username, _domain) = spn.split_once('@').unwrap_or(("", &spn));
    let names = format!("{displayname} ({username})");
    let credentials_update_partial = get_cu_partial(cu_status);

    if is_logged_in {
        let cred_status_view = CredStatusView {
            menu_active_item: ProfileMenuItems::Credentials,
            domain_info: domain_info.clone(),
            names,
            credentials_update_partial,
        };

        (
            HxPushUrl(Urls::UpdateCredentials.to_string()),
            ProfileView {
                navbar_ctx: NavbarCtx::new(domain_info, ui_hints),
                profile_partial: cred_status_view,
            },
        )
            .into_response()
    } else {
        (
            HxPushUrl(Urls::CredReset.to_string()),
            CredResetView {
                domain_info,
                names,
                credentials_update_partial,
            },
        )
            .into_response()
    }
}

async fn get_cu_session(jar: &CookieJar) -> Result<CUSessionToken, Response> {
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
