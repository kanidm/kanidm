use crate::https::ServerState;
use axum::routing::get;
use axum::Router;
use axum_htmx::HxRequestGuardLayer;

mod admin;
mod accounts;
mod groups;

pub fn admin_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/", get(admin::view_admin_get))
        .route("/accounts", get(accounts::view_accounts_get))
        .route("/groups", get(groups::view_groups_get))
        .route("/group/create", get(groups::view_group_create_get));

    let guarded_router = Router::new()
        .layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}