use askama::Template;

use axum::{
    response::Redirect,
    routing::{get, post},
    Router,
};

use axum_htmx::HxRequestGuardLayer;

use constants::Urls;
use kanidmd_lib::prelude::{OperationError, Uuid};

use crate::https::{
    // extractors::VerifiedClientInformation, middleware::KOpId, v1::SessionId,
    ServerState,
};

mod apps;
mod constants;
mod cookies;
mod errors;
mod login;
mod oauth2;
mod profile;
mod reset;

#[derive(Template)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
}

pub fn view_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route(
            "/",
            get(|| async { Redirect::permanent(Urls::Login.as_ref()) }),
        )
        .route("/apps", get(apps::view_apps_get))
        .route("/reset", get(reset::view_reset_get))
        .route("/update_credentials", get(reset::view_self_reset_get))
        .route("/profile", get(profile::view_profile_get))
        .route("/profile/unlock", get(profile::view_profile_unlock_get))
        .route("/logout", get(login::view_logout_get))
        .route("/oauth2", get(oauth2::view_index_get))
        .route("/oauth2/resume", get(oauth2::view_resume_get))
        .route("/oauth2/consent", post(oauth2::view_consent_post))
        // The login routes are htmx-free to make them simpler, which means
        // they need manual guarding for direct get requests which can occur
        // if a user attempts to reload the page.
        .route("/login", get(login::view_index_get))
        .route(
            "/login/passkey",
            post(login::view_login_passkey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/seckey",
            post(login::view_login_seckey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/begin",
            post(login::view_login_begin_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/mech_choose",
            post(login::view_login_mech_choose_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/backup_code",
            post(login::view_login_backupcode_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/totp",
            post(login::view_login_totp_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/login/pw",
            post(login::view_login_pw_post).get(|| async { Redirect::to("/ui") }),
        );

    // The webauthn post is unguarded because it's not a htmx event.

    // Anything that is a partial only works if triggered from htmx
    let guarded_router = Router::new()
        .route("/reset/add_totp", post(reset::view_new_totp))
        .route("/reset/add_password", post(reset::view_new_pwd))
        .route("/reset/change_password", post(reset::view_new_pwd))
        .route("/reset/add_passkey", post(reset::view_new_passkey))
        .route("/reset/set_unixcred", post(reset::view_set_unixcred))
        .route("/api/delete_alt_creds", post(reset::remove_alt_creds))
        .route("/api/delete_unixcred", post(reset::remove_unixcred))
        .route("/api/remove_totp", post(reset::remove_totp))
        .route("/api/remove_passkey", post(reset::remove_passkey))
        .route("/api/finish_passkey", post(reset::finish_passkey))
        .route("/api/cancel_mfareg", post(reset::cancel_mfareg))
        .route("/api/cu_cancel", post(reset::cancel_cred_update))
        .route("/api/cu_commit", post(reset::commit))
        .layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::Deserialize;
    use std::str::FromStr;

    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s)
            .map_err(serde::de::Error::custom)
            .map(Some),
    }
}
