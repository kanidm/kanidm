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
use axum::response::{Redirect, Response};
use axum::Extension;
use axum_extra::extract::cookie::CookieJar;
use axum_extra::extract::Form;
use axum_htmx::{HxEvent, HxPushUrl, HxResponseTrigger};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{OperationError, UserAuthToken};
use kanidm_proto::scim_v1::client::{ScimEntryPutGeneric, ScimEntryPutKanidm};
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimPerson, ScimValueKanidm};
use kanidm_proto::scim_v1::ScimMail;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
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
pub(crate) struct CommitSaveProfileQuery {
    #[serde(rename = "account_name")]
    account_name: Option<String>,
    #[serde(rename = "display_name")]
    display_name: Option<String>,
    #[serde(rename = "emails[]")]
    emails: Vec<String>,
    #[serde(rename = "new_primary_mail")]
    new_primary_mail: Option<String>,
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
    primary_mail: Option<String>,
    new_attrs: ProfileAttributes,
    new_primary_mail: Option<String>,
    emails_are_same: bool,
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
    let old_primary_mail = scim_person
        .mails
        .iter()
        .find(|sm| sm.primary)
        .map(|sm| sm.value.clone());

    let emails_are_same = scim_person.mails == new_mails;

    let profile_view = ProfileChangesPartialView {
        menu_active_item: ProfileMenuItems::UserProfile,
        can_rw,
        person: scim_person,
        primary_mail: old_primary_mail,
        new_attrs: ProfileAttributes {
            account_name: query.account_name,
            display_name: query.display_name,
            emails: new_mails,
        },
        emails_are_same,
        new_primary_mail: query.emails.get(primary_index).cloned(),
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
    Form(query): Form<CommitSaveProfileQuery>,
) -> axum::response::Result<Response> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let mut attrs = BTreeMap::<Attribute, Option<ScimValueKanidm>>::new();
    if let Some(account_name) = query.account_name {
        attrs.insert(Attribute::Name, Some(ScimValueKanidm::String(account_name)));
    }
    if let Some(display_name) = query.display_name {
        attrs.insert(
            Attribute::DisplayName,
            Some(ScimValueKanidm::String(display_name)),
        );
    }
    let mut scim_mails = query
        .emails
        .into_iter()
        .map(|e| ScimMail {
            primary: false,
            value: e,
        })
        .collect::<Vec<_>>();
    if let Some(primary_mail) = query.new_primary_mail {
        scim_mails.push(ScimMail {
            primary: true,
            value: primary_mail,
        })
    }
    attrs.insert(Attribute::Email, Some(ScimValueKanidm::Mail(scim_mails)));

    let generic = ScimEntryPutGeneric::try_from(ScimEntryPutKanidm {
        id: uat.uuid,
        attrs,
    })
    .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;

    // TODO: Use returned KanidmScimPerson below instead of view_profile_get.
    state
        .qe_w_ref
        .handle_scim_entry_put(client_auth_info.clone(), kopid.eventid, generic, true)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    // TODO: Calling this here returns the old attributes
    match view_profile_get(
        State(state),
        Extension(kopid),
        VerifiedClientInformation(client_auth_info),
        DomainInfo(domain_info),
    )
    .await
    {
        Ok(_) => Ok(Redirect::to(Urls::Profile.as_ref()).into_response()),
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
