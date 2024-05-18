use askama::Template;
use axum::extract::State;
use axum::response::Html;
use axum::Extension;

use crate::https::middleware::KOpId;
// use crate::https::extractors::VerifiedClientInformation;
use crate::https::ServerState; // bring trait in scope

#[derive(Template)] // this will generate the code...
#[template(path = "groups.html")] // using the template in this path, relative
// to the `templates` dir in the crate root
#[allow(dead_code)]
struct GroupList {
    // the name of the struct can be anything
    domain_display_name: String,
}
#[allow(dead_code)]
async fn group_list(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Html<String> {
    let domain_display_name = state.qe_r_ref.get_domain_display_name(kopid.eventid).await;

    let group_list = GroupList {
        domain_display_name,
    }; // instantiate your struct
    group_list.render().unwrap().into()
}
