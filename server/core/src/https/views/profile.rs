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
use axum::extract::{Query, State};
use axum::http::Uri;
use axum::response::Response;
use axum::Extension;
use axum_extra::extract::cookie::CookieJar;
use axum_extra::extract::Form;
use axum_htmx::{HxEvent, HxPushUrl, HxResponseTrigger};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_MAIL};
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimPerson};
use kanidm_proto::scim_v1::ScimMail;
use kanidmd_lib::filter::{f_id, Filter};
use kanidmd_lib::prelude::f_and;
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
    person: ScimPerson,
    scim_effective_access: ScimEffectiveAccess,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SaveProfileQuery {
    #[serde(rename = "name")]
    account_name: String,
    #[serde(rename = "displayname")]
    display_name: String,
    #[serde(rename = "email_index")]
    emails_indexes: Vec<u16>,
    #[serde(rename = "emails[]")]
    emails: Vec<String>,
    // radio buttons are used to pick a primary index, remove causes holes, map back into [emails] using [emails_indexes]
    primary_email_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProfileAttributes {
    account_name: String,
    display_name: String,
    emails: Vec<ScimMail>,
}

#[derive(Template, Clone)]
#[template(path = "user_settings/profile_changes_partial.html")]
struct ProfileChangesPartialView {
    menu_active_item: ProfileMenuItems,
    can_rw: bool,
    person: ScimPerson,
    new_attrs: ProfileAttributes,
}

#[derive(Template, Clone)]
#[template(path = "user_settings/form_email_entry_partial.html")]
pub(crate) struct FormEmailEntryListPartial {
    can_edit: bool,
    value: String,
    primary: bool,
    index: u16,
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

    let (scim_person, scim_effective_access) =
        crate::https::views::admin::persons::get_person_info(
            uat.uuid,
            state,
            &kopid,
            client_auth_info.clone(),
        )
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);

    Ok(ProfileView {
        navbar_ctx: NavbarCtx { domain_info },

        profile_partial: ProfilePartialView {
            menu_active_item: ProfileMenuItems::UserProfile,
            can_rw,
            person: scim_person,
            scim_effective_access,
        },
    })
}

pub(crate) async fn view_profile_diff_start_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SaveProfileQuery>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);
    // TODO: A bit overkill to request scimEffectiveAccess here.
    let (scim_person, _) = crate::https::views::admin::persons::get_person_info(
        uat.uuid,
        state,
        &kopid,
        client_auth_info.clone(),
    )
    .await?;

    let primary_index = query
        .emails_indexes
        .iter()
        .position(|ei| ei == &query.primary_email_index)
        .unwrap_or(0);
    let new_mails = query
        .emails
        .iter()
        .enumerate()
        .map(|(ei, email)| ScimMail {
            primary: ei == primary_index,
            value: email.to_string(),
        })
        .collect();

    let profile_view = ProfileChangesPartialView {
        menu_active_item: ProfileMenuItems::UserProfile,
        can_rw,
        person: scim_person,
        new_attrs: ProfileAttributes {
            account_name: query.account_name,
            display_name: query.display_name,
            emails: new_mails,
        },
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
    Form(mut new_attrs): Form<ProfileAttributes>,
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
            ATTR_DISPLAYNAME.to_string(),
            vec![new_attrs.display_name],
            filter.clone(),
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    new_attrs
        .emails
        .sort_by_key(|sm| if sm.primary { 0 } else { 1 });
    let email_addresses = new_attrs.emails.into_iter().map(|sm| sm.value).collect();
    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            uat.uuid.to_string(),
            ATTR_MAIL.to_string(),
            email_addresses,
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
        DomainInfo(domain_info),
    )
    .await
    {
        Ok(pv) => Ok(pv.into_response()),
        Err(e) => Ok(e.into_response()),
    }
}

#[derive(Deserialize)]
pub(crate) struct AddEmailQuery {
    // the last email index is passed so we can return an incremented id
    email_index: Option<u16>,
}

// Sends the user a new email input to fill in :)
pub(crate) async fn view_new_email_entry_partial(
    State(_state): State<ServerState>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Extension(_kopid): Extension<KOpId>,
    Query(email_query): Query<AddEmailQuery>,
) -> axum::response::Result<Response> {
    let add_email_trigger =
        HxResponseTrigger::after_swap([HxEvent::new("addEmailSwapped".to_string())]);
    Ok((
        add_email_trigger,
        FormEmailEntryListPartial {
            can_edit: true,
            value: "".to_string(),
            primary: email_query.email_index.is_none(),
            index: email_query.email_index.map(|i| i + 1).unwrap_or(0),
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
