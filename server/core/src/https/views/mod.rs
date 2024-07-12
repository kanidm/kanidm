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
mod errors;
mod login;

#[derive(Template)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
}

pub fn view_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/", get(login::view_index_get))
        .route("/apps", get(apps::view_apps_get))
        .route("/logout", get(login::view_logout_get))
        // The login routes are htmx-free to make them simpler, which means
        // they need manual guarding for direct get requests which can occur
        // if a user attempts to reload the page.
        .route(
            "/api/login_passkey",
            post(login::view_login_passkey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_seckey",
            post(login::view_login_seckey_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_begin",
            post(login::view_login_begin_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_mech_choose",
            post(login::view_login_mech_choose_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_backup_code",
            post(login::view_login_backupcode_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_totp",
            post(login::view_login_totp_post).get(|| async { Redirect::to("/ui") }),
        )
        .route(
            "/api/login_pw",
            post(login::view_login_pw_post).get(|| async { Redirect::to("/ui") }),
        );

    // The webauthn post is unguarded because it's not a htmx event.

    // Anything that is a partial only works if triggered from htmx
    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

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
