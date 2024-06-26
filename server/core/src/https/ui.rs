use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};

use super::middleware::KOpId;
use super::ServerState;

pub(crate) fn spa_router_user_ui() -> Router<ServerState> {
    Router::new()
        .route("/", get(ui_handler_user_ui))
        .fallback(ui_handler_user_ui)
}

/// This handles /ui/admin and all sub-paths
pub(crate) fn spa_router_admin() -> Router<ServerState> {
    Router::new()
        .route("/", get(ui_handler_admin))
        .fallback(ui_handler_admin)
}

/// This handles the following base paths:
/// - /ui/login
/// - /ui/reauth
/// - /ui/oauth2
pub(crate) fn spa_router_login_flows() -> Router<ServerState> {
    Router::new()
        .route("/", get(ui_handler_login_flows))
        .fallback(ui_handler_login_flows)
}

pub(crate) async fn ui_handler_user_ui(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<String> {
    ui_handler_generic(state, kopid, "wasmloader_user.js").await
}

pub(crate) async fn ui_handler_admin(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<String> {
    ui_handler_generic(state, kopid, "wasmloader_admin.js").await
}

pub(crate) async fn ui_handler_login_flows(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<String> {
    ui_handler_generic(state, kopid, "wasmloader_login_flows.js").await
}

pub(crate) async fn ui_handler_generic(
    state: ServerState,
    kopid: KOpId,
    wasmloader: &str,
) -> Response<String> {
    trace!("ui_handler_generic");
    let domain_display_name = state.qe_r_ref.get_domain_display_name(kopid.eventid).await;

    // let's get the tags we want to load the javascript files
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
