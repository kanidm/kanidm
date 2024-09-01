use crate::https::extractors::{AccessInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::HtmlTemplate;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct OverView {
    access_info: AccessInfo,
    partial: OverviewPartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_overview_partial.html")]
struct OverviewPartialView {}

pub(crate) async fn view_admin_get(
    State(_state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(_kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let overview_partial = OverviewPartialView {};

    let push_url = HxPushUrl(Uri::from_static("/ui/admin"));

    Ok(
        if is_htmx {
            (push_url, HtmlTemplate(overview_partial).into_response()).into_response()
        } else {
            let apps_view = OverView {
                access_info: AccessInfo::new(),
                partial: overview_partial,
            };

            (push_url, HtmlTemplate(apps_view).into_response()).into_response()
        }
    )
}
