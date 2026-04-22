use super::csrf::{self, CsrfData, CsrfSolution};
use crate::https::extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Form;
use axum_extra::extract::CookieJar;
use kanidmd_lib::prelude::duration_from_epoch_now;
use serde::Deserialize;
use tokio::time::{sleep_until, Duration, Instant};

const CONSTANT_TIME_DEADLINE: Duration = Duration::from_millis(500);

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
    jar: CookieJar,
) -> axum::response::Result<Response> {
    // Return an error if this feature is disabled. NOTE that this is NOT a security
    // control, but a user experience once. The feature is also checked in the submission
    // flow.
    if !domain_info.allow_account_recovery() {
        return Ok(RecoverDisabledView { domain_info }.into_response());
    }

    let (jar, csrf) = csrf::generate_parameters(&state, jar, "email")
        .map_err(|_err| "Failed to generate CSRF parameters")?;

    Ok((jar, RecoverView { domain_info, csrf }).into_response())
}

pub(crate) async fn view_recover_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    // VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(recover_form): Form<RecoverForm>,
) -> axum::response::Result<Response> {
    // Prevent the post if this feature is disabled. Still not a "security control"
    // IMO, but it prevents a lot of damage at least.
    if !domain_info.allow_account_recovery() {
        return Ok(RecoverDisabledView { domain_info }.into_response());
    }

    // Setup a deadline so that we always return in constant time.
    // This prevents a specific type of information leak where the
    // timing of the operation can yield if the email address
    // existed or not.
    let deadline = Instant::now() + CONSTANT_TIME_DEADLINE;

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
            // Actually submit the requested operation since the CSRF passed.
            if let Err(err) = state
                .qe_w_ref
                .action_account_recovery(recover_form.email, kopid.eventid)
                .await
            {
                warn!(
                    ?err,
                    "Account recovery failed - returning a false positive for privacy."
                );
            }
        }
        Err(()) => {
            warn!("CSRF verification failed, silently ignoring to confuse the spammers.");
        }
    };

    // Let the deadline pass.
    sleep_until(deadline).await;

    // We always return a positive response so that we don't disclose email address presence
    // or other potential information to a potential attacker.
    Ok(RecoverComplete { domain_info }.into_response())
}
