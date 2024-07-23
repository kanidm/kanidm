use askama::Template;
use axum::Extension;
use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::internal::UserAuthToken;
use crate::https::extractors::VerifiedClientInformation;
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileView {
    profile_partial: ProfilePartialView,
}

#[derive(Template, Clone)]
#[template(path = "profile_partial.html")]
struct ProfilePartialView {
    can_rw: bool,
    name: String,
    legal_name: String,
    email: Option<String>,
    posix_enabled: bool
}

pub(crate) async fn view_profile_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state.qe_r_ref.handle_whoami_uat(client_auth_info, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let time = time::OffsetDateTime::now_utc()+ time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    let profile_partial_view = ProfilePartialView {
        can_rw,
        name: uat.displayname.clone(),
        legal_name: uat.name().to_string(),
        email: uat.mail_primary.clone(),
        posix_enabled: false,
    };
    let profile_view = ProfileView {
        profile_partial: profile_partial_view.clone(),
    };

    Ok(if hx_request {
        (
            HxPushUrl(Uri::from_static("/ui/profile")),
            HtmlTemplate(profile_partial_view),
        ).into_response()
    } else {
        HtmlTemplate(profile_view).into_response()
    })
}
