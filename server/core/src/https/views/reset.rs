use askama::Template;
use axum::{Extension, Form};
use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{ErrorResponse, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest, HxRetarget};
use futures_util::TryFutureExt;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use kanidm_proto::internal::{COOKIE_CU_SESSION_TOKEN, CredentialDetail, CUCredState, CUExtPortal, CUIntentToken, CURegWarning, CURequest, CUSessionToken, CUStatus, OperationError, PasskeyDetail, PasswordFeedback};

use crate::https::extractors::VerifiedClientInformation;
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;

#[derive(Template)]
#[template(path = "credentials_reset_form.html")]
struct ResetCredFormView {
    domain: String,
}


#[derive(Template)]
#[template(path = "credentials_reset.html")]
struct CredResetView {
    credentials_update_partial: CredResetPartialView,
}

#[derive(Template)]
#[template(path = "credentials_update_partial.html")]
struct CredResetPartialView {
    domain: String,
    names: String,
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
#[template(path = "cred_update/add_password_modal_partial.html")]
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

pub(crate) async fn view_new_pwd(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(new_passwords): Form<NewPassword>,
) -> axum::response::Result<Response> {
    let cookie = jar.get(COOKIE_CU_SESSION_TOKEN);
    return if let Some(cookie) = cookie {
        let cu_session_token = cookie.value();
        let cu_session_token = CUSessionToken { token: cu_session_token.into() };

        let eq = new_passwords.new_password == new_passwords.new_password_check;
        let (check_res, status) = if eq {
            let res = state.qe_r_ref.handle_idmcredentialupdate(cu_session_token, CURequest::Password(new_passwords.new_password), kopid.eventid).await;
            match res {
                Ok(_) => (PwdCheckResult::Success, StatusCode::OK),
                Err(OperationError::PasswordQuality(password_feedback)) => {
                    (PwdCheckResult::Failure {
                        pwd_equal: eq,
                        warnings: password_feedback,
                    }, StatusCode::UNPROCESSABLE_ENTITY)
                }
                Err(operr) => {
                    return Err(ErrorResponse::from(HtmxError::new(&kopid, operr)))
                }
            }
        } else {
            (PwdCheckResult::Failure {
                pwd_equal: eq,
                warnings: vec![],
            }, StatusCode::UNPROCESSABLE_ENTITY)
        };

        let template = HtmlTemplate(AddPasswordModalPartial { check_res });
        Ok((status, template).into_response())
    } else {
        Ok((StatusCode::FORBIDDEN, Redirect::to("/ui/reset")).into_response())
    };
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
        domain: domain_display_name.clone()
    };

    if let Some(token) = params.token {
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

        Ok((jar, template).into_response())
    } else {
        Ok((
            HxPushUrl(Uri::from_static("/ui/reset")),
            HxRetarget("body".to_string()),
            HtmlTemplate(cred_form_view),
        ).into_response())
    }
}

fn get_cu_template(domain_display_name: String, cu_status: CUStatus) -> HtmlTemplate<CredResetView> {
    let CUStatus {
        spn,
        displayname,
        ext_cred_portal,
        mfaregstate: _,

        // warnings,
        passkeys_state,
        attested_passkeys_state,
        attested_passkeys,
        passkeys,
        primary_state,
        primary,
        ..
    } = cu_status;

    let warnings = vec![CURegWarning::Unsatisfiable, CURegWarning::AttestedPasskeyRequired, CURegWarning::MfaRequired, CURegWarning::PasskeyRequired, CURegWarning::WebauthnAttestationUnsatisfiable];

    let (username, _domain) = spn.split_once('@').unwrap_or(("", &spn));
    let names = format!("{} ({})", displayname, username);

    let cred_view = CredResetView {
        credentials_update_partial: CredResetPartialView {
            domain: domain_display_name,
            names,
            ext_cred_portal,
            warnings,
            attested_passkeys_state,
            passkeys_state,
            attested_passkeys,
            passkeys,
            primary_state,
            primary,
        }
    };

    let template = HtmlTemplate(cred_view);
    template
}


// Any filter defined in the module `filters` is accessible in your template.
mod filters {
    pub fn blank_if<T: std::fmt::Display>(implicit_arg: T, condition: bool) -> ::askama::Result<String> {
        return if condition {
            Ok("".into())
        } else {
            Ok(format!("{implicit_arg}"))
        };
    }
    pub fn blank_iff<T: std::fmt::Display>(implicit_arg: T, condition: &bool) -> ::askama::Result<String> {
        return if *condition {
            Ok("".into())
        } else {
            Ok(format!("{implicit_arg}"))
        };
    }
}
