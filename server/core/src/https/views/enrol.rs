use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::constants::ProfileMenuItems;
use crate::https::views::errors::HtmxError;
use crate::https::views::login::ReauthPurpose;
use crate::https::views::reauth::{
    render_readonly, render_reauth, uat_privilege_decision, PrivilegeDecision,
};
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::CookieJar;
use kanidm_proto::internal::UserAuthToken;
use qrcode::render::svg;
use qrcode::QrCode;
use std::time::Duration;
use url::Url;

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

    match uat_privilege_decision(uat) {
        PrivilegeDecision::Proceed => {}
        PrivilegeDecision::ReauthRequired => {
            return render_reauth(
                state,
                jar,
                domain_info,
                client_auth_info,
                kopid,
                ReauthPurpose::ProfileSettings,
                Urls::EnrolDevice,
            )
            .await
        }
        PrivilegeDecision::ReadOnly => return render_readonly(domain_info, uat, kopid).await,
    };

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
