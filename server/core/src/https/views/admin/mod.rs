use crate::https::ServerState;
use axum::routing::{get, post};
use axum::Router;
use axum_htmx::HxRequestGuardLayer;

pub(crate) mod groups;
pub(crate) mod persons;

pub fn admin_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/persons", get(persons::view_persons_get))
        .route(
            "/person/{person_uuid}/view",
            get(persons::view_person_view_get),
        )
        .route("/groups", get(groups::view_groups_get))
        .route("/group/{group_uuid}/view", get(groups::view_group_view_get));

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

pub fn admin_api_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/group/{group_uuid}", post(groups::edit_group))
        .route("/group/{group_uuid}/add_member", post(groups::add_member))
        .route(
            "/group/{group_uuid}/remove_member",
            post(groups::remove_member),
        );

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}
