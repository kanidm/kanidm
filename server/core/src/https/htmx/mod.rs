use super::*;

pub(crate) mod groups;

pub(crate) fn htmx_router() -> Router<ServerState> {
    Router::new().route("/groups", get(groups::group_list))
}
