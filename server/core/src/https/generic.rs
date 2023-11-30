use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use kanidmd_lib::status::StatusRequestEvent;

use super::middleware::KOpId;
use super::ServerState;

#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "Ok"),
    ),
    tag = "system",

)]
/// Status endpoint used for health checks, returns true when the server is up.
pub async fn status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> String {
    let r = state
        .status_ref
        .handle_request(StatusRequestEvent {
            eventid: kopid.eventid,
        })
        .await;
    format!("{}", r)
}

#[utoipa::path(
    get,
    path = "/robots.txt",
    responses(
        (status = 200, description = "Ok"),
    ),
    tag = "ui",

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

pub(crate) fn route_setup() -> Router<ServerState> {
    Router::new()
        .route("/robots.txt", get(robots_txt))
        .route("/status", get(status))
}
