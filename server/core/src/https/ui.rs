use axum::extract::State;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use http::header::CONTENT_TYPE;

use super::middleware::KOpId;
use super::ServerState;

pub(crate) fn spa_router() -> Router<ServerState> {
    Router::new()
        .route("/", get(ui_handler))
        .fallback(ui_handler)
}

pub(crate) fn spa_router_admin() -> Router<ServerState> {
    Router::new()
        .route("/", get(ui_handler_admin))
        .fallback(ui_handler)
}

pub(crate) async fn ui_handler_admin(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<String> {
    ui_handler_generic(state, kopid, "wasmloader_admin.js").await
}

pub(crate) async fn ui_handler(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<String> {
    ui_handler_generic(state, kopid, "wasmloader.js").await
}

pub(crate) async fn ui_handler_generic(
    state: ServerState,
    kopid: KOpId,
    wasmloader: &str,
) -> Response<String> {
    let domain_display_name = state.qe_r_ref.get_domain_display_name(kopid.eventid).await;

    // this feels icky but I felt that adding a trait on Vec<JavaScriptFile> which generated the string was going a bit far
    let mut jsfiles: Vec<String> = state
        .js_files
        .all_pages
        .into_iter()
        .map(|j| j.as_tag())
        .collect();
    if let Some(jsfile) = state.js_files.selected.get(wasmloader) {
        jsfiles.push(jsfile.clone().as_tag())
    };

    let jstags = jsfiles.join("\n");
    // TODO: load the right JS based on which page we're on

    let body = format!(
        include_str!("ui_html.html"),
        domain_display_name.as_str(),
        jstags,
    );

    let mut res = Response::new(body);
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html;charset=utf-8"),
    );
    res
}
