use super::constants::{ProfileMenuItems, Urls};
use super::errors::HtmxError;
use super::login::{LoginDisplayCtx, Reauth, ReauthPurpose};
use super::navbar::NavbarCtx;
use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::http::Uri;
use axum::response::Response;
use axum::Extension;
use axum_extra::extract::cookie::CookieJar;
use axum_extra::extract::Form;
use axum_htmx::{HxEvent, HxPushUrl, HxResponseTrigger};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_LEGALNAME, ATTR_MAIL};
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::v1::Entry;
use kanidmd_lib::filter::{f_eq, f_id, Filter};
use kanidmd_lib::prelude::f_and;
use kanidmd_lib::prelude::PartialValue;
use kanidmd_lib::prelude::FC;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Template)]
#[template(path = "user_settings.html")]
pub(crate) struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: ProfilePartialView,
}

#[derive(Template, Clone)]
#[template(path = "user_settings_profile_partial.html")]
struct ProfilePartialView {
    menu_active_item: ProfileMenuItems,
    can_rw: bool,
    attrs: ProfileAttributes
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProfileAttributes {
    account_name: String,
    display_name: String,
    legal_name: String,
    #[serde(rename = "emails[]")]
    emails: Vec<String>,
    primary_email: Option<String>,
}

#[derive(Template, Clone)]
#[template(path = "user_settings/profile_changes_partial.html")]
struct ProfileChangesPartialView {
    menu_active_item: ProfileMenuItems,
    can_rw: bool,
    attrs: ProfileAttributes,
    new_attrs: ProfileAttributes,
}

#[derive(Template, Clone)]
#[template(path = "user_settings/form_modifiable_entry_modifiable_list_partial.html")]
// Modifiable entry in a modifiable list partial
pub(crate) struct FormModEntryModListPartial {
    can_rw: bool,
    r#type: String,
    name: String,
    value: String,
    invalid_feedback: String,
}

impl Display for ProfileAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub(crate) async fn view_profile_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> Result<ProfileView, WebError> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .await?;

    let filter = filter_all!(f_and!([f_eq(
        Attribute::Uuid,
        PartialValue::Uuid(uat.uuid)
    )]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .await?;

    let self_entry = base.first().expect("Self no longer exists");
    let empty = vec![];
    let emails = self_entry.attrs.get(ATTR_MAIL).unwrap_or(&empty).clone();
    let primary_email = emails.first().cloned();

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    Ok(ProfileView {
        navbar_ctx: NavbarCtx { domain_info },

        profile_partial: ProfilePartialView {
            menu_active_item: ProfileMenuItems::UserProfile,
            can_rw,
            attrs: ProfileAttributes {
                account_name: uat.name().to_string(),
                display_name: uat.displayname.clone(),
                legal_name: "hardcoded".to_string(),
                emails,
                primary_email,
            },
        },
    })
}

pub(crate) async fn view_profile_diff_start_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Form must be the last parameter because it consumes the request body
    Form(new_attrs): Form<ProfileAttributes>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    let filter = filter_all!(f_and!([f_eq(
        Attribute::Uuid,
        PartialValue::Uuid(uat.uuid)
    )]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info))
        .await?;

    let self_entry = base.first().expect("Self no longer exists");
    let empty = vec![];
    let emails = self_entry.attrs.get(ATTR_MAIL).unwrap_or(&empty).clone();
    let primary_email = emails.first().cloned();

    let profile_view = ProfileChangesPartialView {
        menu_active_item: ProfileMenuItems::UserProfile,
        can_rw,
        attrs: ProfileAttributes {
            account_name: uat.name().to_string(),
            display_name: uat.displayname.clone(),
            legal_name: "hardcoded".to_string(),
            emails,
            primary_email,
        },
        new_attrs
    };

    Ok((
        HxPushUrl(Uri::from_static("/ui/profile/diff")),
        profile_view,
    )
        .into_response())
}

pub(crate) async fn view_profile_diff_confirm_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Form must be the last parameter because it consumes the request body
    Form(new_attrs): Form<ProfileAttributes>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
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
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
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
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            uat.uuid.to_string(),
            ATTR_MAIL.to_string(),
            new_attrs.emails,
            filter.clone(),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
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
    match view_profile_get(
        State(state),
        Extension(kopid),
        VerifiedClientInformation(client_auth_info),
        DomainInfo(domain_info)
    ).await {
        Ok(pv) => Ok(pv.into_response()),
        Err(e) => Ok(e.into_response()),
    }
}

// Sends the user a new email input to fill in :)
pub(crate) async fn view_new_email_entry_partial(
    State(_state): State<ServerState>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Extension(_kopid): Extension<KOpId>,
) -> axum::response::Result<Response> {
    let passkey_init_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addEmailSwapped".to_string())]);
    Ok((
        passkey_init_trigger,
        FormModEntryModListPartial {
            can_rw: true,
            r#type: "email".to_string(),
            name: "emails[]".to_string(),
            value: "".to_string(),
            invalid_feedback: "Please enter a valid email address.".to_string(),
        },
    )
        .into_response())
}

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
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let display_ctx = LoginDisplayCtx {
        domain_info,
        oauth2: None,
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
