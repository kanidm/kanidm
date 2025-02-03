use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Redirect};
use axum::{Extension, Json};
use kanidmd_lib::status::StatusRequestEvent;

use super::middleware::KOpId;
use super::views::constants::Urls;
use super::ServerState;

#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "Ok", content_type = "application/json"),
    ),
    tag = "system",

)]
/// Status endpoint used for health checks, returns true when the server is up.
pub async fn status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Json<bool> {
    state
        .status_ref
        .handle_request(StatusRequestEvent {
            eventid: kopid.eventid,
        })
        .await
        .into()
}

#[utoipa::path(
    get,
    path = "/robots.txt",
    responses(
        (status = 200, description = "Ok"),
    ),
    tag = "ui",
    operation_id = "robots_txt",

)]
pub async fn robots_txt() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain;charset=utf-8")],
        axum::response::Html(
            r#"User-agent: *
        Disallow: /
"#,
        ),
    )
}

#[utoipa::path(
    get,
    path = Urls::WellKnownChangePassword.as_ref(),
    responses(
        (status = 303, description = "See other"),
    ),
    tag = "ui",
)]
pub async fn redirect_to_update_credentials() -> impl IntoResponse {
    Redirect::to(Urls::UpdateCredentials.as_ref())
}
