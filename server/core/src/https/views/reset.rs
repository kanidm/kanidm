use askama::Template;
use axum::Extension;
use axum::extract::{Query, State};
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest, HxRetarget};
use futures_util::TryFutureExt;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use kanidm_proto::internal::{COOKIE_CU_SESSION_TOKEN, CredentialDetail, CUCredState, CUExtPortal, CUIntentToken, CURegWarning, CUSessionToken, CUStatus, PasskeyDetail};

use crate::https::extractors::VerifiedClientInformation;
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;

#[derive(Template)]
#[template(path = "credentials_reset_form.html")]
struct ResetCredFormView {
    domain: String
}


#[derive(Template)]
#[template(path = "credentials_reset.html")]
struct CredResetView {
    credentials_update_partial: CredResetPartialView
}

#[derive(Template)]
#[template(path = "credentials_update_partial.html", print = "all")]
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
    token: Option<String>
}

pub(crate) async fn view_reset_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(_hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Query(params): Query<ResetTokenParam>,
    mut jar: CookieJar
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
            primary
        }
    };

    let template = HtmlTemplate(cred_view);
    template
}
