use askama::Template;
use askama_web::WebTemplate;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;

use axum_extra::extract::CookieJar;
use kanidm_proto::internal::UserAuthToken;

use qrcode::render::svg;
use qrcode::QrCode;
use url::Url;

use std::time::Duration;

use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::constants::ProfileMenuItems;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use crate::https::ServerState;

#[derive(Template, WebTemplate)]
#[template(path = "user_settings.html")]
struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: EnrolDeviceView,
}

#[derive(Template, WebTemplate)]
#[template(path = "enrol_device.html")]
pub(crate) struct EnrolDeviceView {
    menu_active_item: ProfileMenuItems,
    secret: String,
    qr_code_svg: String,
    uri: Url,
}

pub(crate) async fn view_enrol_get(
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

    // The user lacks an elevated session, request a re-auth.
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
            Urls::EnrolDevice.as_ref(),
            display_ctx,
        )
        .await);
    }

    let spn = uat.spn.clone();

    let cu_intent = state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            client_auth_info.clone(),
            spn,
            Some(Duration::from_secs(900)),
            kopid.eventid,
        )
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let secret = cu_intent.token;

    let mut uri = state.origin.clone();
    uri.set_path(Urls::CredReset.as_ref());
    uri.set_query(Some(format!("token={secret}").as_str()));

    let qr_code_svg = match QrCode::new(uri.as_str()) {
        Ok(qr) => qr.render::<svg::Color>().build(),
        Err(qr_err) => {
            error!("Failed to create TOTP QR code: {qr_err}");
            "QR Code Generation Failed".to_string()
        }
    };

    Ok(ProfileView {
        navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),

        profile_partial: EnrolDeviceView {
            menu_active_item: ProfileMenuItems::EnrolDevice,
            qr_code_svg,
            secret,
            uri,
        },
    }
    .into_response())
}
