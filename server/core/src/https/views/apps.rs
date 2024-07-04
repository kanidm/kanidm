use askama::Template;
use axum::{
    Extension,
    extract::State,
    http::uri::Uri,
    response::{IntoResponse, Response},
};
use axum_htmx::{HxPushUrl, HxReswap, HxRetarget, SwapOption};
use axum_htmx::extractors::HxRequest;
use uuid::Uuid;

use kanidm_proto::internal::{AppLink, OperationError};

use crate::https::{extractors::VerifiedClientInformation, middleware::KOpId, ServerState};
use crate::https::views::login::LoginView;

use super::{HtmlTemplate, UnrecoverableErrorView};

#[derive(Template)]
#[template(path = "apps.html")]
struct AppsView {
    apps_partial: AppsPartialView,
}

#[derive(Template)]
#[template(path = "apps_partial.html")]
struct AppsPartialView {
    apps: Vec<AppLink>,
}

fn get_transformer(op_id: Uuid) -> impl Fn(OperationError) -> Response {
    move |error| {
        match error {
            OperationError::SessionExpired => {
                HtmlTemplate(LoginView {
                    username: "",
                    remember_me: false,
                }).into_response()
            }
            _ => {
                HtmlTemplate(UnrecoverableErrorView {
                    err_code: error,
                    operation_id: op_id,
                }).into_response()
            }
        }
    }
}

pub(crate) async fn view_apps_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Response {
    // Because this is the route where the login page can land, we need to actually alter
    // our response as a result. If the user comes here directly we need to render the full
    // page, otherwise we need to render the partial.
    let handler = get_transformer(kopid.eventid);
    let app_links = state
        .qe_r_ref
        .handle_list_applinks(client_auth_info, kopid.eventid)
        .await;

    let app_links = match app_links {
        Ok(app_links) => app_links,
        Err(err) => return handler(err),
    };

    let apps_view = AppsView {
        apps_partial: AppsPartialView {
            apps: app_links,
        },
    };

    if hx_request {
        (
            // On the redirect during a login we don't push urls. We set these headers
            // so that the url is updated, and we swap the correct element.
            HxPushUrl(Uri::from_static("/ui/apps")),
            // Tell htmx that we want to update the body instead. There is no need
            // set the swap value as it defaults to innerHTML. This is because we came here
            // from an htmx request so we only need to render the inner portion.
            HxRetarget("body".to_string()),
            // We send our own main, replace the existing one.
            HxReswap(SwapOption::OuterHtml),
            HtmlTemplate(apps_view),
        )
            .into_response()
    } else {
        HtmlTemplate(apps_view).into_response()
    }
}
