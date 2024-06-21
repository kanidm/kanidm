use askama::Template;

use axum::{
    http::StatusCode,
    extract::State,
    response::{Html, Redirect, Response, IntoResponse},
    routing::{get, post},
    Form,
    Extension,
    Router,

};

use axum_extra::extract::cookie::{
    // Cookie,
    CookieJar,
    // SameSite
};

// use axum_htmx::HxRequestGuardLayer;

use kanidmd_lib::prelude::{
    OperationError,
    Uuid,
};

use kanidm_proto::v1::{
    AuthRequest, AuthStep
};

use kanidmd_lib::idm::event::AuthResult;

use serde::Deserialize;

use crate::https::{
    extractors::VerifiedClientInformation,
    middleware::KOpId,
    ServerState,
};

#[derive(Template)]
#[template(path = "unrecoverable_error.html")]
struct UnrecoverableErrorView {
    err_code: OperationError,
    operation_id: Uuid,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginView<'a> {
    username: &'a str,
    remember_me: bool,
}

pub(crate) async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    _jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            Redirect::temporary("/ui/apps").into_response()
        }
        Err(OperationError::NotAuthenticated) |
        Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.

            HtmlTemplate(LoginView {
                username: "",
                remember_me: false,
            })
                .into_response()

        }
        Err(err_code) =>
            HtmlTemplate(UnrecoverableErrorView { err_code, operation_id: kopid.eventid })
                .into_response(),
    }
}




#[derive(Debug, Clone, Deserialize)]
struct LoginBeginForm {
    username: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    remember_me: Option<u8>,
}

async fn partial_view_login_begin_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    _jar: CookieJar,
    Form(login_begin_form): Form<LoginBeginForm>,
) -> Response {
    trace!(?login_begin_form);

    let LoginBeginForm {
        username,
        remember_me
    } = login_begin_form;

    trace!(?remember_me);

    // Init the login.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(None, AuthRequest {
            step: AuthStep::Init(username),
        }, kopid.eventid, client_auth_info)
        .await;
    debug!("Auth result: {:?}", inter);

    // What was requested?

    // Based on that, step.

    partial_view_login_step(inter).await
}

async fn partial_view_login_step(
    step_result: Result<AuthResult, OperationError>
) -> Response {
    trace!(?step_result);

    match step_result {
        
    }


    todo!();
}


pub fn view_router() -> Router<ServerState> {
    Router::new()
        .route("/", get(view_index_get))

        // Anything that is a partial only works if triggered from htmx
        // .layer(HxRequestGuardLayer::default())
        .route("/api/login_begin", post(partial_view_login_begin_post))

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


