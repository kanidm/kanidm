use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::CookieJar;
use kanidm_proto::internal::UserAuthToken;

use super::constants::{ProfileMenuItems, Urls};
use super::navbar::NavbarCtx;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};

#[derive(Template, WebTemplate)]
#[template(path = "user_settings.html")]
pub(crate) struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: RadiusPartialView,
}

#[derive(Template, Clone, WebTemplate)]
#[template(path = "radius.html")]
pub(crate) struct RadiusPartialView {
    menu_active_item: ProfileMenuItems,
    radius_password: Option<String>,
}

pub(crate) async fn view_radius_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    // The user lacks an elevated session, request a re-auth
    if !can_rw {
        let display_ctx = LoginDisplayCtx {
            domain_info,
            oauth2: None,
            reauth: Some(Reauth {
                username: uat.spn.clone(),
                purpose: ReauthPurpose::ProfileSettings,
            }),
            error: None,
        };

        return Ok(super::login::view_reauth_get(
            state,
            client_auth_info,
            kopid,
            jar,
            Urls::Radius.as_ref(),
            display_ctx,
        )
        .await);
    }

    let radius_password = state
        .qe_r_ref
        .handle_internalradiusread(client_auth_info.clone(), uat.spn.clone(), kopid.eventid)
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    Ok(ProfileView {
        navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
        profile_partial: RadiusPartialView {
            menu_active_item: ProfileMenuItems::Radius,
            radius_password,
        },
    }
    .into_response())
}

pub(crate) async fn view_radius_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat_client_auth_info = client_auth_info.clone();
    let uat: &UserAuthToken = uat_client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let radius_password = state
        .qe_w_ref
        .handle_regenerateradius(client_auth_info, uat.uuid.to_string(), kopid.eventid)
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    Ok(RadiusPartialView {
        menu_active_item: ProfileMenuItems::Radius,
        radius_password: Some(radius_password),
    }
    .into_response())
}
