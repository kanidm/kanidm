use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use crate::https::views::HtmlTemplate;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::cookie::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::internal::UserAuthToken;

use super::constants::{ProfileMenuItems, Urls};

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
    legal_name: String,
    email: Option<String>,
    posix_enabled: bool,
}

#[axum::debug_handler]
pub(crate) async fn view_profile_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<ProfileView, Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err).into_response())
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    Ok(ProfileView {
        profile_partial: ProfilePartialView {
            menu_active_item: ProfileMenuItems::UserProfile,
            can_rw,
            account_name: uat.name().to_string(),
            display_name: uat.displayname.clone(),
            // TODO: this should be the legal name
            legal_name: uat.name().to_string(),
            email: uat.mail_primary.clone(),
            posix_enabled: false,
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
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let display_ctx = LoginDisplayCtx {
        domain_info,
        reauth: Some(Reauth {
            username: uat.spn,
            purpose: ReauthPurpose::ProfileSettings,
        }),
    };

    super::login::view_reauth_get(
        state,
        client_auth_info,
        kopid,
        jar,
        Urls::Profile.as_ref(),
        display_ctx,
    )
    .await
}

#[derive(Template)]
#[template(path = "user_settings_ssh_partial.html")]
struct SshProfilePartialView {
    menu_active_item: ProfileMenuItems,
    can_rw: bool,
    ssh_keys: Vec<String>,
    posix_enabled: bool,
}

pub(crate) async fn ssh_keys(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Response, Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err).into_response())
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    Ok(if hx_request {
        (
            HxPushUrl(Uri::from_static(Urls::Profile.as_ref())),
            HtmlTemplate(SshProfilePartialView {
                menu_active_item: ProfileMenuItems::SshKeys,
                can_rw,
                ssh_keys: Vec::new(),
                // TODO: fill in posix enabled
                posix_enabled: false,
            }),
        )
            .into_response()
    } else {
        // HtmlTemplate(profile_view).into_response()
        todo!()
    })
}
