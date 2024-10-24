use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::get;
use axum::Router;

use super::ServerState;

use crate::https::extractors::{DomainInfo, DomainInfoRead};

pub const CSS_NAVBAR_NAV: &str = "navbar navbar-expand-md navbar-dark bg-dark mb-4";
pub const CSS_NAVBAR_BRAND: &str = "navbar-brand d-flex align-items-center";
pub const CSS_NAVBAR_LINKS_UL: &str = "navbar-nav";

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
    DomainInfo(domain_info): DomainInfo,
) -> Response<String> {
    ui_handler_generic(state, "wasmloader_user.js", domain_info).await
}

pub(crate) async fn ui_handler_admin(
    State(state): State<ServerState>,
    DomainInfo(domain_info): DomainInfo,
) -> Response<String> {
    ui_handler_generic(state, "wasmloader_admin.js", domain_info).await
}

pub(crate) async fn ui_handler_login_flows(
    State(state): State<ServerState>,
    DomainInfo(domain_info): DomainInfo,
) -> Response<String> {
    ui_handler_generic(state, "wasmloader_login_flows.js", domain_info).await
}

pub(crate) async fn ui_handler_generic(
    state: ServerState,
    wasmloader: &str,
    domain_info: DomainInfoRead,
) -> Response<String> {
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

    let body: String = format!(
        include_str!("ui_html.html"),
        jstags = jsfiles.join("\n"),
        cache_buster_key = crate::https::cache_buster::get_cache_buster_key(),
        display_name = domain_info.display_name()
    );

    let mut res = Response::new(body);
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html;charset=utf-8"),
    );
    res
}
