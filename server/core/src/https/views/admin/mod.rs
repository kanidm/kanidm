use crate::https::ServerState;
use axum::routing::{get, post};
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
        .route("/groups/unlock", get(groups::view_groups_unlock_get))
        .route("/group/create", get(groups::view_group_create_get))
        .route("/group/:group_uuid/delete", post(groups::view_group_delete_post))
        .route("/group/:group_uuid/edit", get(groups::view_group_edit_get))
        .route("/group/:group_uuid/view", get(groups::view_group_view_get))
        .route("/group/create", post(groups::view_group_create_post));

    let guarded_router = Router::new()
        .layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}