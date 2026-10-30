#![allow(clippy::result_large_err)]
use super::{
    constants::Urls,
    csrf::{self, CsrfData, CsrfSolution},
};
use crate::https::{
    extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation},
    middleware::KOpId,
    ServerState,
};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{ErrorResponse, IntoResponse, Redirect, Response},
    Extension, Form,
};
use axum_extra::extract::CookieJar;
use kanidmd_lib::prelude::duration_from_epoch_now;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tokio::time::{sleep_until, Duration, Instant};

const CONSTANT_TIME_DEADLINE: Duration = Duration::from_millis(500);

#[derive(Template, WebTemplate)]
#[template(path = "signup_disabled.html")]
struct SignupDisabledView {
    domain_info: DomainInfoRead,
}

#[derive(Template, WebTemplate)]
#[template(path = "signup_form.html")]
struct SignupView {
    domain_info: DomainInfoRead,
    csrf: CsrfData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub(crate) struct SignupForm {
    username: String,
    display_name: String,
    email: String,
    #[serde(flatten)]
    csrf_solution: CsrfSolution,
}

#[derive(Template, WebTemplate)]
#[template(path = "signup_complete.html")]
struct SignupComplete {
    domain_info: DomainInfoRead,
}

#[derive(Template, WebTemplate)]
#[template(path = "signup_verify.html")]
struct SignupVerify {
    domain_info: DomainInfoRead,
    username: String,
    display_name: String,
}

pub(crate) async fn view_signup_get(
    State(state): State<ServerState>,
    // Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    // Return an error if this feature is disabled. NOTE that this is NOT a security
    // control, but a user experience once. The feature is also checked in the submission
    // flow.
    if !domain_info.allow_account_signup() {
        return Ok(SignupDisabledView { domain_info }.into_response());
    }

    let (jar, csrf) = csrf::generate_parameters(&state, jar, "email")
        .map_err(|_err| "Failed to generate CSRF parameters")?;

    Ok((jar, SignupView { domain_info, csrf }).into_response())
}

pub(crate) async fn view_signup_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    // VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(signup_form): Form<SignupForm>,
) -> axum::response::Result<Response> {
    // Prevent the post if this feature is disabled. Still not a "security control"
    // IMO, but it prevents a lot of damage at least.
    if !domain_info.allow_account_signup() {
        return Ok(SignupDisabledView { domain_info }.into_response());
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
        signup_form.email.as_bytes(),
        &signup_form.csrf_solution,
        current_time,
    ) {
        Ok(()) => {
            // Actually submit the requested operation since the CSRF passed.
            if let Err(err) = state
                .qe_w_ref
                .action_account_signup(
                    signup_form.username,
                    signup_form.display_name,
                    signup_form.email,
                    kopid.eventid,
                )
                .await
            {
                warn!(
                    ?err,
                    "Account signup failed - returning a false positive for privacy."
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
    Ok(SignupComplete { domain_info }.into_response())
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
// Needs to be visible so axum can create this struct
pub(crate) struct TokenParam {
    token: Option<String>,
}

pub(crate) async fn view_signup_verify_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Query(params): Query<TokenParam>,
) -> axum::response::Result<Response> {
    if !domain_info.allow_account_signup() {
        return Err(StatusCode::FORBIDDEN.into());
    }

    if let Some(token) = params.token {
        // Proceed with the verification form
        let display = state
            .qe_r_ref
            .action_account_signup_display(token.clone(), kopid.eventid)
            .await
            .map_err(|_| ErrorResponse::from(StatusCode::FORBIDDEN))?;

        Ok(SignupVerify {
            domain_info,
            username: display.username,
            display_name: display.display_name,
        }
        .into_response())
    } else {
        // Display an error
        Err(StatusCode::FORBIDDEN.into())
    }
}

pub(crate) async fn view_signup_verify_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Query(params): Query<TokenParam>,
) -> axum::response::Result<Response> {
    if !domain_info.allow_account_signup() {
        return Err(StatusCode::FORBIDDEN.into());
    }

    if let Some(token) = params.token {
        // Proceed with the verification form
        let reset = state
            .qe_w_ref
            .action_account_signup_verify(token.clone(), kopid.eventid)
            .await
            .map_err(|_| ErrorResponse::from(StatusCode::FORBIDDEN))?;

        let token_uri_string = format!("{}?token={}", Urls::CredReset, reset.token);
        Ok((Redirect::to(&token_uri_string)).into_response())
    } else {
        // Display an error
        Err(StatusCode::FORBIDDEN.into())
    }
}
