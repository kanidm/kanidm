use crate::https::extractors::{AccessInfo, DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::Urls;
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::response::{ErrorResponse, IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use std::collections::BTreeSet;

use crate::https::views::navbar::NavbarCtx;
use kanidm_proto::internal::OperationError;
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimEntryKanidm, ScimReference};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimMail};
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_and, f_eq, Filter, FC};
use kanidmd_lib::idm::server::DomainInfoRead;
use kanidmd_lib::idm::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct GroupsView {
    access_info: AccessInfo,
    partial: GroupsPartialView,
    navbar_ctx: NavbarCtx,
}

#[derive(Template)]
#[template(path = "admin/admin_groups_partial.html")]
struct GroupsPartialView {
    groups: Vec<GroupInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GroupInfo {
    uuid: Uuid,
    name: String,
    spn: String,
    description: Option<String>,
    entry_managed_by: Option<String>,
    mails: Vec<ScimMail>,
    members: Vec<ScimReference>,
    scim_effective_access: ScimEffectiveAccess,
    acp: GroupACP,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GroupACP {
    enabled: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct GroupDetailsFormData {
    name: String,
    spn: String,
    entry_manager: String,
}

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct GroupView {
    access_info: AccessInfo,
    partial: GroupViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template)]
#[template(path = "admin/admin_group_view_partial.html")]
struct GroupViewPartial {
    group: GroupInfo,
}

pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let group = get_group_info(uuid, state, &kopid, client_auth_info, domain_info.clone()).await?;
    let groups_partial = GroupViewPartial { group };

    let path_string = format!("/ui/admin/group/{uuid}/view");
    let uri = Uri::from_str(path_string.as_str())
        .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;
    let push_url = HxPushUrl(uri);
    Ok(if is_htmx {
        (push_url, groups_partial).into_response()
    } else {
        (
            push_url,
            GroupView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
                navbar_ctx: NavbarCtx { domain_info },
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_groups_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let groups = get_groups_info(state, &kopid, client_auth_info, domain_info.clone()).await?;
    let groups_partial = GroupsPartialView { groups };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/groups"));
    Ok(if is_htmx {
        (push_url, groups_partial).into_response()
    } else {
        (
            push_url,
            GroupsView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
                navbar_ctx: NavbarCtx { domain_info },
            },
        )
            .into_response()
    })
}

async fn get_group_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<GroupInfo, ErrorResponse> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Group,
            ScimEntryGetQuery {
                attributes: Some(vec![
                    Attribute::Description,
                    Attribute::Name,
                    Attribute::Spn,
                    Attribute::EntryManagedBy,
                    Attribute::Member,
                ]),
                ext_access_check: true,
            },
        )
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))
        .await?;

    if let Some(group_info) = scimentry_into_groupinfo(scim_entry) {
        Ok(group_info)
    } else {
        Err(HtmxError::new(kopid, OperationError::InvalidState, domain_info.clone()).into())
    }
}

async fn get_groups_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<Vec<GroupInfo>, ErrorResponse> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into())]));
    let attrs = Some(BTreeSet::from([
        Attribute::Uuid,
        Attribute::EntryManagedBy,
        Attribute::Name,
        Attribute::Spn,
        Attribute::Description,
        Attribute::Member,
    ]));
    let base: Vec<ScimEntryKanidm> = state
        .qe_r_ref
        .scim_entry_search(client_auth_info.clone(), filter, kopid.eventid, attrs, true)
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))
        .await?;

    // TODO: inefficient to sort here
    let mut groups: Vec<_> = base
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_groupinfo)
        .collect();

    groups.sort_by_key(|gi| gi.uuid);
    groups.reverse();
    Ok(groups)
}

fn scimentry_into_groupinfo(scim_entry: ScimEntryKanidm) -> Option<GroupInfo> {
    let uuid = scim_entry.header.id;
    let name = scim_entry.attr_str(&Attribute::Name)?.to_string();
    let spn = scim_entry.attr_str(&Attribute::Spn)?.to_string();
    let description = scim_entry
        .attr_str(&Attribute::Description)
        .map(|t| t.to_string());
    let entry_managed_by = scim_entry
        .attr_str(&Attribute::EntryManagedBy)
        .map(|t| t.to_string());
    let mails = scim_entry.attr_mails().cloned().unwrap_or_default();
    let members = scim_entry
        .attr_references(&Attribute::Member)
        .cloned()
        .unwrap_or_default();
    let acp_enable = scim_entry
        .attr_bool(&Attribute::AcpEnable)
        .cloned()
        .unwrap_or(false);

    let option = scim_entry.ext_access_check;
    let scim_effective_access = option?; // TODO: This should be an error msg.
    let acp = GroupACP {
        enabled: acp_enable,
    };

    Some(GroupInfo {
        scim_effective_access,
        uuid,
        name,
        spn,
        acp,
        description,
        entry_managed_by,
        mails,
        members,
    })
}
