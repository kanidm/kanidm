use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::HxPushUrl;

use kanidm_proto::internal::{AppLink, UserAuthToken};

use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::views::errors::HtmxError;
use crate::https::{
    extractors::DomainInfo, extractors::VerifiedClientInformation, middleware::KOpId, ServerState,
};

#[derive(Template, WebTemplate)]
#[template(path = "apps.html")]
struct AppsView {
    navbar_ctx: NavbarCtx,
    apps_partial: AppsPartialView,
}

#[derive(Template, WebTemplate)]
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
        .handle_list_applinks(client_auth_info.clone(), kopid.eventid)
        .await
        .map_err(|old| HtmxError::new(&kopid, old, domain_info.clone()))?;
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let apps_partial = AppsPartialView { apps: app_links };

    println!("{:?}", &uat.ui_hints);
    Ok({
        let apps_view = AppsView {
            navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),

            apps_partial,
        };
        (HxPushUrl(Urls::Apps.to_string()), apps_view).into_response()
    })
}
