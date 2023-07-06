use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use http::header::CONTENT_TYPE;
use kanidmd_lib::status::StatusRequestEvent;

use super::middleware::KOpId;
use super::ServerState;

/// Status endpoint used for healthchecks
pub async fn status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let r = state
        .status_ref
        .handle_request(StatusRequestEvent {
            eventid: kopid.eventid,
        })
        .await;
    Response::new(format!("{}", r))
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
