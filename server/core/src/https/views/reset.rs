use crate::https::extractors::VerifiedClientInformation;
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{ErrorResponse, IntoResponse, Redirect, Response};
use axum::{Extension, Form, Json};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use axum_htmx::{HxEvent, HxPushUrl, HxRequest, HxResponseTrigger, HxRetarget};
use futures_util::TryFutureExt;
use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CUIntentToken, CURegState, CURegWarning, CURequest, CUSessionToken,
    CUStatus, CredentialDetail, OperationError, PasskeyDetail, PasswordFeedback,
    COOKIE_CU_SESSION_TOKEN,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;

#[derive(Template)]
#[template(path = "credentials_reset_form.html")]
struct ResetCredFormView {
    domain: String,
}

#[derive(Template)]
#[template(path = "credentials_reset.html")]
struct CredResetView {
    domain: String,
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
#[template(path = "cred_update/add_password_partial.html")]
struct AddPasswordModalPartial {
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

#[derive(Template)]
#[template(path = "cred_update/add_passkey_partial.html")]
struct AddPasskeyModalPartial {
    // Passkey challenge for adding a new passkey
    challenge: String,
}

#[derive(Deserialize, Debug)]
struct PasskeyCreateResponse {}

#[derive(Deserialize, Debug)]
struct PasskeyCreateExtensions {}

#[derive(Deserialize, Debug)]
pub(crate) struct PasskeyCreateForm {
    name: String,
    #[serde(rename = "creationData")]
    creation_data: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PasskeyRemoveData {
    uuid: Uuid
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

    Ok(get_cu_partial_template(cu_status).into_response())
}

async fn get_cu_session(jar: CookieJar) -> Result<CUSessionToken, Response> {
    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
    return if let Some(cookie) = cookie {
        let cu_session_token = cookie.value();
        let cu_session_token = CUSessionToken {
            token: cu_session_token.into(),
        };
        Ok(cu_session_token)
    } else {
        Err((StatusCode::FORBIDDEN, Redirect::to("/ui/reset")).into_response())
    };
}

pub(crate) async fn remove_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Json(passkey): Json<PasskeyRemoveData>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_status = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::PasskeyRemove(passkey.uuid), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    Ok(get_cu_partial_template(cu_status).into_response())
}

pub(crate) async fn finish_passkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(passkey_create): Form<PasskeyCreateForm>,
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    match serde_json::from_str(passkey_create.creation_data.as_str()) {
        Ok(creation_data) => {
            let cu_request = CURequest::PasskeyFinish(passkey_create.name, creation_data);

            let cu_status = state
                .qe_r_ref
                .handle_idmcredentialupdate(cu_session_token, cu_request, kopid.eventid)
                .map_err(|op_err| HtmxError::new(&kopid, op_err))
                .await?;

            Ok(get_cu_partial_template(cu_status).into_response())
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
) -> axum::response::Result<Response> {
    let cu_session_token: CUSessionToken = get_cu_session(jar).await?;

    let cu_satus: CUStatus = state
        .qe_r_ref
        .handle_idmcredentialupdate(cu_session_token, CURequest::PasskeyInit, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let response = match cu_satus.mfaregstate {
        CURegState::Passkey(chal) => HtmlTemplate(AddPasskeyModalPartial {
            challenge: serde_json::to_string(&chal).unwrap(),
        })
        .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            HtmxError::new(&kopid, OperationError::Backend).into_response(),
        )
            .into_response(),
    };

    let passkey_init_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addPasskeySwapped".to_string())]);
    Ok((passkey_init_trigger, response).into_response())
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
    let swap_on_err_trigger =
        HxResponseTrigger::normal([HxEvent::new("addPasswordSwapOnErr".to_string())]);

    let new_passwords = match opt_form {
        None => {
            let partial = AddPasswordModalPartial {
                check_res: PwdCheckResult::Init,
            };
            return Ok((swapped_handler_trigger, HtmlTemplate(partial)).into_response());
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
            Ok(cu_status) => return Ok(get_cu_partial_template(cu_status).into_response()),
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
    let template = HtmlTemplate(AddPasswordModalPartial { check_res });

    Ok((
        status,
        swapped_handler_trigger,
        swap_on_err_trigger,
        template,
    )
        .into_response())
}

pub(crate) async fn view_reset_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Query(params): Query<ResetTokenParam>,
    mut jar: CookieJar,
) -> axum::response::Result<Response> {
    let domain_display_name = state.qe_r_ref.get_domain_display_name(kopid.eventid).await;
    let cred_form_view = ResetCredFormView {
        domain: domain_display_name.clone(),
    };

    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
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
                    let token_uri_string = format!("/ui/reset?token={token}");
                    return Ok((jar, Redirect::to(token_uri_string.as_str())).into_response());
                }
                return Ok((jar, Redirect::to("/ui/reset")).into_response());
            }
            Err(op_err) => return Ok(HtmxError::new(&kopid, op_err).into_response()),
        };
        let template = get_cu_template(domain_display_name, cu_status);

        Ok(template.into_response())
    } else if let Some(token) = params.token {
        // We have a reset token and want to create a new session
        let (cu_session_token, cu_status): (CUSessionToken, CUStatus) = state
            .qe_w_ref
            .handle_idmcredentialexchangeintent(CUIntentToken { token }, kopid.eventid)
            .map_err(|op_err| HtmxError::new(&kopid, op_err))
            .await?;

        let template = get_cu_template(domain_display_name, cu_status);

        let mut token_cookie = Cookie::new(COOKIE_CU_SESSION_TOKEN, cu_session_token.token);
        token_cookie.set_secure(state.secure_cookies);
        token_cookie.set_same_site(SameSite::Strict);
        token_cookie.set_http_only(true);
        jar = jar.add(token_cookie);

        Ok((jar, HxPushUrl(Uri::from_static("/ui/reset")), template).into_response())
    } else {
        // We don't have any credential, show reset token input form
        Ok((
            HxPushUrl(Uri::from_static("/ui/reset")),
            HxRetarget("body".to_string()),
            HtmlTemplate(cred_form_view),
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

    return CredResetPartialView {
        ext_cred_portal,
        warnings,
        attested_passkeys_state,
        passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
    };
}

fn get_cu_partial_template(cu_status: CUStatus) -> HtmlTemplate<CredResetPartialView> {
    let credentials_update_partial = get_cu_partial(cu_status);
    HtmlTemplate(credentials_update_partial)
}

fn get_cu_template(domain: String, cu_status: CUStatus) -> HtmlTemplate<CredResetView> {
    let spn = cu_status.spn.clone();
    let displayname = cu_status.displayname.clone();
    let (username, _domain) = spn.split_once('@').unwrap_or(("", &spn));
    let names = format!("{} ({})", displayname, username);
    let credentials_update_partial = get_cu_partial(cu_status);
    HtmlTemplate(CredResetView {
        domain,
        names,
        credentials_update_partial,
    })
}

// Any filter defined in the module `filters` is accessible in your template.
mod filters {
    pub fn blank_if<T: std::fmt::Display>(
        implicit_arg: T,
        condition: bool,
    ) -> ::askama::Result<String> {
        blank_iff(implicit_arg, &condition)
    }
    pub fn ternary<T: std::fmt::Display, F: std::fmt::Display>(
        implicit_arg: &bool,
        true_case: T,
        false_case: F,
    ) -> ::askama::Result<String> {
        if *implicit_arg {
            Ok(format!("{true_case}"))
        } else {
            Ok(format!("{false_case}"))
        }
    }
    pub fn blank_iff<T: std::fmt::Display>(
        implicit_arg: T,
        condition: &bool,
    ) -> ::askama::Result<String> {
        return if *condition {
            Ok("".into())
        } else {
            Ok(format!("{implicit_arg}"))
        };
    }
}
