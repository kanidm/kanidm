use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::response::Response;
use axum::Extension;
use axum_extra::extract::cookie::CookieJar;
use kanidm_proto::internal::UserAuthToken;

use super::constants::{ProfileMenuItems, UiMessage, Urls};
use super::errors::HtmxError;
use super::login::{LoginDisplayCtx, Reauth, ReauthPurpose};

#[derive(Template)]
#[template(path = "user_settings.html")]
pub(crate) struct ProfileView {
    profile_partial: ProfilePartialView,
}

#[derive(Template, Clone)]
#[template(path = "user_settings_profile_partial.html")]
struct ProfilePartialView {
    menu_active_item: ProfileMenuItems,
    can_rw: bool,
    account_name: String,
    display_name: String,
    email: Option<String>,
}

pub(crate) async fn view_profile_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<ProfileView, WebError> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info, kopid.eventid)
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    Ok(ProfileView {
        profile_partial: ProfilePartialView {
            menu_active_item: ProfileMenuItems::UserProfile,
            can_rw,
            account_name: uat.name().to_string(),
            display_name: uat.displayname.clone(),
            email: uat.mail_primary.clone(),
        },
    })
}

// #[axum::debug_handler]
pub(crate) async fn view_profile_unlock_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Extension(kopid): Extension<KOpId>,
    jar: CookieJar,
) -> Result<Response, HtmxError> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err))?;

    let display_ctx = LoginDisplayCtx {
        domain_info,
        reauth: Some(Reauth {
            username: uat.spn,
            purpose: ReauthPurpose::ProfileSettings,
        }),
        error: None,
    };

    Ok(super::login::view_reauth_get(
        state,
        client_auth_info,
        kopid,
        jar,
        Urls::Profile.as_ref(),
        display_ctx,
    )
    .await)
}
