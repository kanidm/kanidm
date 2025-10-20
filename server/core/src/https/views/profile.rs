use super::constants::{ProfileMenuItems, Urls};
use super::errors::HtmxError;
use super::navbar::NavbarCtx;
use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use axum_extra::extract::Form;
use axum_htmx::{HxEvent, HxPushUrl, HxResponseTrigger};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{OperationError, UserAuthToken};
use kanidm_proto::scim_v1::client::ScimEntryPutKanidm;
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimPerson, ScimValueKanidm};
use kanidm_proto::scim_v1::ScimMail;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Template, WebTemplate)]
#[template(path = "user_settings.html")]
pub(crate) struct ProfileView {
    navbar_ctx: NavbarCtx,
    profile_partial: ProfilePartialView,
}

#[derive(Template, Clone, WebTemplate)]
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
    emails_indexes: Option<Vec<u16>>,
    #[serde(rename = "emails[]")]
    emails: Option<Vec<String>>,
    // radio buttons are used to pick a primary index, remove causes holes, map back into [emails] using [emails_indexes]
    primary_email_index: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CommitSaveProfileQuery {
    #[serde(rename = "account_name")]
    account_name: Option<String>,
    #[serde(rename = "display_name")]
    display_name: Option<String>,
    #[serde(rename = "emails[]")]
    emails: Option<Vec<String>>,
    #[serde(rename = "new_primary_mail")]
    new_primary_mail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProfileAttributes {
    account_name: String,
    display_name: String,
    emails: Vec<ScimMail>,
}

#[derive(Template, Clone, WebTemplate)]
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

#[derive(Template, Clone, WebTemplate)]
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
) -> Result<Response, WebError> {
    let uat: &UserAuthToken = client_auth_info.pre_validated_uat()?;

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

    let rehook_email_removal_buttons =
        HxResponseTrigger::after_swap([HxEvent::new("addEmailSwapped".to_string())]);
    Ok((
        rehook_email_removal_buttons,
        HxPushUrl("/ui/profile".to_string()),
        ProfileView {
            navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
            profile_partial: ProfilePartialView {
                menu_active_item: ProfileMenuItems::UserProfile,
                can_rw,
                person: scim_person,
                scim_effective_access,
            },
        },
    )
        .into_response())
}

pub(crate) async fn view_profile_diff_start_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SaveProfileQuery>,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);

    let (scim_person, _) = crate::https::views::admin::persons::get_person_info(
        uat.uuid,
        state,
        &kopid,
        client_auth_info.clone(),
    )
    .await?;

    let (new_emails, emails_are_same) =
        if let (Some(email_indices), Some(emails)) = (query.emails_indexes, query.emails) {
            let primary_index = query.primary_email_index.unwrap_or(0);

            let primary_index = email_indices
                .iter()
                .position(|ei| ei == &primary_index)
                .unwrap_or(0);
            let new_mails = emails
                .iter()
                .enumerate()
                .map(|(ei, email)| ScimMail {
                    primary: ei == primary_index,
                    value: email.to_string(),
                })
                .collect();

            let emails_are_same = scim_person.mails == new_mails;

            (new_mails, emails_are_same)
        } else {
            (vec![], true)
        };

    let primary_mail = scim_person
        .mails
        .iter()
        .find(|sm| sm.primary)
        .map(|sm| sm.value.clone());

    let new_primary_mail = new_emails
        .iter()
        .find(|sm| sm.primary)
        .map(|sm| sm.value.clone());

    let profile_view = ProfileChangesPartialView {
        menu_active_item: ProfileMenuItems::UserProfile,
        can_rw,
        person: scim_person,
        primary_mail,
        new_attrs: ProfileAttributes {
            account_name: query.account_name,
            display_name: query.display_name,
            emails: new_emails,
        },
        new_primary_mail,
        emails_are_same,
    };

    Ok((HxPushUrl("/ui/profile/diff".to_string()), profile_view).into_response())
}

pub(crate) async fn view_profile_diff_confirm_save_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<CommitSaveProfileQuery>,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

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

    if query.emails.is_some() || query.new_primary_mail.is_some() {
        let mut scim_mails = if let Some(secondary_mails) = query.emails {
            secondary_mails
                .into_iter()
                .map(|secondary_mail| ScimMail {
                    primary: false,
                    value: secondary_mail,
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        if let Some(primary_mail) = query.new_primary_mail {
            scim_mails.push(ScimMail {
                primary: true,
                value: primary_mail,
            })
        }

        attrs.insert(
            Attribute::Mail,
            if scim_mails.is_empty() {
                None
            } else {
                Some(ScimValueKanidm::Mail(scim_mails))
            },
        );
    }

    let generic = ScimEntryPutKanidm {
        id: uat.uuid,
        attrs,
    }
    .try_into()
    .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;

    // TODO: Use returned KanidmScimPerson below instead of view_profile_get.
    state
        .qe_w_ref
        .handle_scim_entry_put(client_auth_info.clone(), kopid.eventid, generic)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

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
