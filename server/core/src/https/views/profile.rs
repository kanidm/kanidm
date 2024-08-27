use crate::https::extractors::VerifiedClientInformation;
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::HtmlTemplate;
use crate::https::ServerState;
use askama::Template;
use axum::extract::State;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Form};
use axum_extra::extract::cookie::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_LEGALNAME,
};
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::v1::Entry;
use kanidmd_lib::filter::{f_and, f_eq, f_id};
use kanidmd_lib::prelude::FC;
use kanidmd_lib::prelude::{Attribute, Filter};
use kanidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Template)]
#[template(path = "user_settings.html")]
struct ProfileView {
    profile_partial: ProfilePartialView,
}

#[derive(Template, Clone)]
#[template(path = "user_settings_profile_partial.html")]
struct ProfilePartialView {
    can_rw: bool,
    attrs: ProfileAttributes,
    posix_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProfileAttributes {
    account_name: String,
    display_name: String,
    legal_name: String,
    emails: Vec<String>,
    primary_email: Option<String>
}

#[derive(Template, Clone)]
#[template(path = "user_settings/profile_changes_partial.html")]
struct ProfileChangesPartialView {
    can_rw: bool,
    attrs: ProfileAttributes,
    new_attrs: ProfileAttributes,
    posix_enabled: bool,
}

impl Display for ProfileAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub(crate) async fn view_profile_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let filter = filter_all!(f_and!([f_eq(Attribute::Uuid, PartialValue::Uuid(uat.uuid))]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(
            client_auth_info.clone(),
            filter,
            None,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let self_entry = base.first().expect("Self no longer exists");
    let empty = vec![];
    let emails = self_entry.attrs.get("mail").unwrap_or(&empty).clone();
    let primary_email = emails.first().cloned();

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    let profile_partial_view = ProfilePartialView {
        can_rw,
        attrs: ProfileAttributes {
            account_name: uat.name().to_string(),
            display_name: uat.displayname.clone(),
            legal_name: "hardcoded".to_string(),
            emails,
            primary_email,
        },
        posix_enabled: false,
    };
    let profile_view = ProfileView {
        profile_partial: profile_partial_view.clone(),
    };

    Ok((
        HxPushUrl(Uri::from_static("/ui/profile")),
        if hx_request {
            HtmlTemplate(profile_partial_view).into_response()
        } else {
            HtmlTemplate(profile_view).into_response()
        },
    )
        .into_response())
}

pub(crate) async fn view_profile_diff_start_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Form(new_attrs): Form<ProfileAttributes>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    let filter = filter_all!(f_and!([f_eq(Attribute::Uuid, PartialValue::Uuid(uat.uuid))]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(
            client_auth_info.clone(),
            filter,
            None,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let self_entry = base.first().expect("Self no longer exists");
    let empty = vec![];
    let emails = self_entry.attrs.get("mail").unwrap_or(&empty).clone();
    let primary_email = emails.first().cloned();

    let profile_view = ProfileChangesPartialView {
        can_rw,
        attrs: ProfileAttributes {
            account_name: uat.name().to_string(),
            display_name: uat.displayname.clone(),
            legal_name: "hardcoded".to_string(),
            emails,
            primary_email,
        },
        new_attrs,
        posix_enabled: true,
    };

    Ok((
        HxPushUrl(Uri::from_static("/ui/profile/diff")),
        HtmlTemplate(profile_view),
    )
        .into_response())
}

pub(crate) async fn view_profile_diff_confirm_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    HxRequest(hx_request): HxRequest,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Form(new_attrs): Form<ProfileAttributes>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;
    dbg!(&new_attrs);

    let filter = filter_all!(f_and!([f_id(uat.uuid.to_string().as_str())]));

    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            uat.uuid.to_string(),
            ATTR_LEGALNAME.to_string(),
            vec![new_attrs.legal_name],
            filter.clone(),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            uat.uuid.to_string(),
            ATTR_DISPLAYNAME.to_string(),
            vec![new_attrs.display_name],
            filter.clone(),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    // TODO: These are normally not permitted, user should be prevented from changing non modifiable fields in the UI though
    // state
    //     .qe_w_ref
    //     .handle_setattribute(
    //         client_auth_info.clone(),
    //         uat.uuid.to_string(),
    //         ATTR_EMAIL.to_string(),
    //         vec![new_attrs.email.unwrap_or("".to_string())],
    //         filter.clone(),
    //         kopid.eventid,
    //     )
    //     .map_err(|op_err| HtmxError::new(&kopid, op_err))
    //     .await?;
    //
    // state
    //     .qe_w_ref
    //     .handle_setattribute(
    //         client_auth_info.clone(),
    //         uat.uuid.to_string(),
    //         ATTR_NAME.to_string(),
    //         vec![new_attrs.account_name],
    //         filter.clone(),
    //         kopid.eventid,
    //     )
    //     .map_err(|op_err| HtmxError::new(&kopid, op_err))
    //     .await?;

    // TODO: Calling this here returns the old attributes
    view_profile_get(
        State(state),
        Extension(kopid),
        HxRequest(hx_request),
        VerifiedClientInformation(client_auth_info),
    )
    .await
}

// #[axum::debug_handler]
pub(crate) async fn view_profile_unlock_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    super::login::view_reauth_get(state, client_auth_info, kopid, jar, "/ui/profile").await
}
