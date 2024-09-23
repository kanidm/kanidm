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
        .layer(HxRequestGuardLayer::new("/ui"))
        .route("/api/group/:group_uuid", post(groups::view_group_save_post))
        .route("/api/group/:group_uuid/member", post(groups::view_group_new_member_post))
        .route("/api/group/:group_uuid/mail", post(groups::view_group_new_mail_post));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

// Any filter defined in the module `filters` is accessible in your template.
mod filters {
    use std::hash::{DefaultHasher, Hash, Hasher};

    // This filter does not have extra arguments
    pub fn hash<T: std::fmt::Display + Hash>(t: T) -> ::askama::Result<u64> {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        Ok(s.finish())
    }
}
