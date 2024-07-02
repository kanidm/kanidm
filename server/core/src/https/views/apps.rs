use askama::Template;

use axum::{
    extract::State,
    http::uri::Uri,
    response::{IntoResponse, Response},
    Extension,
};

use axum_htmx::extractors::HxRequest;

use axum_htmx::{HxPushUrl, HxReswap, HxRetarget, SwapOption};

use crate::https::{extractors::VerifiedClientInformation, middleware::KOpId, ServerState};

use super::{
    HtmlTemplate,
    // UnrecoverableErrorView,
};

#[derive(Template)]
#[template(path = "apps.html")]
struct AppsView {
    apps_partial: AppsPartialView,
}

#[derive(Template)]
#[template(path = "apps_partial.html")]
struct AppsPartialView {
    // todo - actually list the applications the user can access here.
}

pub(crate) async fn view_apps_get(
    State(_state): State<ServerState>,
    Extension(_kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
) -> Response {
    // Because this is the route where the login page can land, we need to actually alter
    // our response as a result. If the user comes here directly we need to render the full
    // page, otherwise we need to render the partial.

    let apps_partial = AppsPartialView {};

    if hx_request {
        (
            // On the redirect during a login we don't push urls. We set these headers
            // so that the url is updated, and we swap the correct element.
            HxPushUrl(Uri::from_static("/ui/apps")),
            // Tell htmx that we want to update the body instead. There is no need
            // set the swap value as it defaults to innerHTML. This is because we came here
            // from an htmx request so we only need to render the inner portion.
            HxRetarget("#main".to_string()),
            // We send our own main, replace the existing one.
            HxReswap(SwapOption::OuterHtml),
            HtmlTemplate(apps_partial),
        )
            .into_response()
    } else {
        HtmlTemplate(AppsView { apps_partial }).into_response()
    }
}
