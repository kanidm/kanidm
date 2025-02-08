use crate::https::ServerState;
use axum::routing::get;
use axum::Router;
use axum_htmx::HxRequestGuardLayer;

mod accounts;
mod groups;

pub fn admin_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/accounts", get(accounts::view_accounts_get))
        .route("/account/:account_uuid/view", get(accounts::view_account_view_get))
        .route("/groups", get(groups::view_groups_get))
        .route("/group/:group_uuid/view", get(groups::view_group_view_get));

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}
