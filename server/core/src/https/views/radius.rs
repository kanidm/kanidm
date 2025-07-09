use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::Extension;
use kanidm_proto::internal::UserAuthToken;

use super::constants::{ProfileMenuItems, /*UiMessage,*/ Urls};
use super::navbar::NavbarCtx;

#[derive(Template)]
#[template(path = "user_settings.html")]
pub(crate) struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: RadiusPartialView,
}

#[derive(Template, Clone)]
#[template(path = "radius.html")]
pub(crate) struct RadiusPartialView {
    menu_active_item: ProfileMenuItems,
    password_available: bool,
    radius_password: String,
}

pub(crate) async fn view_radius_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> Result<ProfileView, WebError> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .await?;

    let radius_password = state
        .qe_r_ref
        .handle_internalradiusread(client_auth_info, uat.spn.clone(), kopid.eventid)
        .await?;

    if let Some(radius_password) = radius_password {
        Ok(ProfileView {
            navbar_ctx: NavbarCtx { domain_info },

            profile_partial: RadiusPartialView {
                menu_active_item: ProfileMenuItems::Radius,
                password_available: true,
                radius_password: radius_password,
            },
        })
    } else {
        Ok(ProfileView {
            navbar_ctx: NavbarCtx { domain_info },

            profile_partial: RadiusPartialView {
                menu_active_item: ProfileMenuItems::Radius,
                password_available: false,
                radius_password: String::new(),
            },
        })
    }
}

pub(crate) async fn view_radius_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(_domain_info): DomainInfo,
) -> Result<RadiusPartialView, WebError> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .await?;

    state
        .qe_w_ref
        .handle_regenerateradius(
            client_auth_info.clone(),
            uat.uuid.clone().to_string(),
            kopid.eventid,
        )
        .await?;

    let radius_password = state
        .qe_r_ref
        .handle_internalradiusread(
            client_auth_info,
            uat.uuid.clone().to_string(),
            kopid.eventid,
        )
        .await?;

    if let Some(radius_password) = radius_password {
        Ok(RadiusPartialView {
            menu_active_item: ProfileMenuItems::Radius,
            password_available: true,
            radius_password,
        })
    } else {
        Ok(RadiusPartialView {
            menu_active_item: ProfileMenuItems::Radius,
            password_available: false,
            radius_password: String::new(),
        })
    }
}
