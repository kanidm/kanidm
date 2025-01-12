use askama::Template;
use axum::{
    extract::State,
    http::uri::Uri,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::HxPushUrl;

use kanidm_proto::internal::AppLink;

use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::views::errors::HtmxError;
use crate::https::{
    extractors::DomainInfo, extractors::VerifiedClientInformation, middleware::KOpId, ServerState,
};

#[derive(Template)]
#[template(path = "apps.html")]
struct AppsView {
    navbar_ctx: NavbarCtx,
    apps_partial: AppsPartialView,
}

#[derive(Template)]
#[template(path = "apps_partial.html")]
struct AppsPartialView {
    apps: Vec<AppLink>,
}

pub(crate) async fn view_apps_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    // Because this is the route where the login page can land, we need to actually alter
    // our response as a result. If the user comes here directly we need to render the full
    // page, otherwise we need to render the partial.

    let app_links = state
        .qe_r_ref
        .handle_list_applinks(client_auth_info, kopid.eventid)
        .await
        .map_err(|old| HtmxError::new(&kopid, old, domain_info.clone()))?;

    Ok({
        (
            HxPushUrl(Uri::from_static(Urls::Apps.as_ref())),
            AppsView {
                navbar_ctx: NavbarCtx { domain_info },
                apps_partial: AppsPartialView { apps: app_links },
            },
        )
            .into_response()
    })
}
