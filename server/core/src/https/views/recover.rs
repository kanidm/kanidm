// use super::constants::Urls;
//use super::UnrecoverableErrorView;

use crate::https::extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation};

// use crate::https::middleware::KOpId;
// use crate::https::views::cookies;

use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::CookieJar;
use kanidmd_lib::prelude::duration_from_epoch_now;
use serde::Deserialize;

// use axum_extra::extract::cookie::SameSite;
// use serde_with::skip_serializing_none;

use super::csrf::{self, CsrfData, CsrfSolution};

#[derive(Template, WebTemplate)]
#[template(path = "recover_disabled.html")]
struct RecoverDisabledView {
    domain_info: DomainInfoRead,
}

#[derive(Template, WebTemplate)]
#[template(path = "recover_form.html")]
struct RecoverView {
    domain_info: DomainInfoRead,
    csrf: CsrfData,
}

#[derive(Template, WebTemplate)]
#[template(path = "recover_complete.html")]
struct RecoverComplete {
    domain_info: DomainInfoRead,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub(crate) struct RecoverForm {
    email: String,
    #[serde(flatten)]
    csrf_solution: CsrfSolution,
}

pub(crate) async fn view_recover_get(
    State(state): State<ServerState>,
    // Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Query(params): Query<ResetTokenParam>,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    // Return an error if this feature is disabled. NOTE that this is NOT a security
    // control, but a user experience once. The feature is also checked in the submission
    // flow.

    if !domain_info.allow_credential_reset_email() {
        return Ok(RecoverDisabledView { domain_info }.into_response());
    }

    let (jar, csrf) = csrf::generate_parameters(&state, jar, "email")
        .map_err(|_err| "Failed to generate CSRF parameters")?;

    Ok((jar, RecoverView { domain_info, csrf }).into_response())
}

pub(crate) async fn view_recover_post(
    State(state): State<ServerState>,
    // Extension(kopid): Extension<KOpId>,
    // VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Query(params): Query<ResetTokenParam>,
    jar: CookieJar,
    Form(recover_form): Form<RecoverForm>,
) -> axum::response::Result<Response> {
    // Prevent the post if this feature is disabled. Still not a "security control"
    // IMO, but it prevents a lot of damage at least.
    if !domain_info.allow_credential_reset_email() {
        return Ok(RecoverDisabledView { domain_info }.into_response());
    }

    // Validate
    let current_time = duration_from_epoch_now();

    match csrf::verify_parameters(
        &state,
        &jar,
        recover_form.email.as_bytes(),
        &recover_form.csrf_solution,
        current_time,
    ) {
        Ok(()) => {
            // Actually submit the requested operation.

            warn!("CSRF Pass!");
        }
        Err(()) => {
            warn!("CSRF verification failed, silently ignoring to confuse the spammers.");
        }
    };

    Ok(RecoverComplete { domain_info }.into_response())
}
