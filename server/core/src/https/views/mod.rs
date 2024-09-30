use askama::Template;

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};

use axum_htmx::HxRequestGuardLayer;

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
mod sshkeys;

#[derive(Template)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
}

pub fn view_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/", get(|| async { Redirect::permanent("/ui/login") }))
        .route("/apps", get(apps::view_apps_get))
        .route("/reset", get(reset::view_reset_get))
        .route("/ssh_keys", get(sshkeys::view_sshkeys_get))
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
        .route("/api/delete_alt_creds", post(reset::remove_alt_creds))
        .route("/api/remove_totp", post(reset::remove_totp))
        .route("/api/remove_passkey", post(reset::remove_passkey))
        .route("/api/finish_passkey", post(reset::finish_passkey))
        .route("/api/cancel_mfareg", post(reset::cancel_mfareg))
        .route("/api/cu_cancel", post(reset::cancel))
        .route("/api/cu_commit", post(reset::commit))
        .layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

struct HtmlTemplate<T>(T);

/// Allows us to convert Askama HTML templates into valid HTML for axum to serve in the response.
impl<T> IntoResponse for HtmlTemplate<T>
where
    T: askama::Template,
{
    fn into_response(self) -> Response {
        // Attempt to render the template with askama
        match self.0.render() {
            // If we're able to successfully parse and aggregate the template, serve it
            Ok(html) => Html(html).into_response(),
            // If we're not, return an error or some bit of fallback HTML
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
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
