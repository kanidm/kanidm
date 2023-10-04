use axum::extract::State;
use axum::response::IntoResponse;
use axum::Extension;
use http::header::CONTENT_TYPE;
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
