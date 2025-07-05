use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::Urls;
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::OperationError;
use kanidm_proto::scim_v1::client::ScimFilter;
use kanidm_proto::scim_v1::server::{
    ScimEffectiveAccess, ScimEntryKanidm, ScimListResponse, ScimGroup,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::idm::ClientAuthInfo;
use std::str::FromStr;
use uuid::Uuid;

pub const GROUP_ATTRIBUTES: [Attribute; 2] = [
    Attribute::Uuid,
    Attribute::Name
];

#[derive(Template)]
#[template(path = "admin/admin_panel_template.html")]
pub(crate) struct GroupsView {
    navbar_ctx: NavbarCtx,
    partial: GroupsPartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_groups_partial.html")]
struct GroupsPartialView {
    groups: Vec<(ScimGroup, ScimEffectiveAccess)>,
}

#[derive(Template)]
#[template(path = "admin/admin_panel_template.html")]
struct GroupView {
    partial: GroupViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template)]
#[template(path = "admin/admin_group_view_partial.html")]
struct GroupViewPartial {
    group: ScimGroup,
    scim_effective_access: ScimEffectiveAccess,
}

pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (group, scim_effective_access) =
        get_group_info(uuid, state, &kopid, client_auth_info).await?;
    let group_partial = GroupViewPartial {
        group,
        scim_effective_access,
    };

    let path_string = format!("/ui/admin/group/{uuid}/view");
    let uri = Uri::from_str(path_string.as_str())
        .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;
    let push_url = HxPushUrl(uri);
    Ok(if is_htmx {
        (push_url, group_partial).into_response()
    } else {
        (
            push_url,
            GroupView {
                partial: group_partial,
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
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let groups = get_groups_info(state, &kopid, client_auth_info).await?;
    let groups_partial = GroupsPartialView { groups };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/groups"));
    Ok(if is_htmx {
        (push_url, groups_partial).into_response()
    } else {
        (
            push_url,
            GroupsView {
                navbar_ctx: NavbarCtx { domain_info },
                partial: groups_partial,
            },
        )
            .into_response()
    })
}

pub async fn get_group_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<(ScimGroup, ScimEffectiveAccess), WebError> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Group,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(GROUP_ATTRIBUTES)),
                ext_access_check: true,
            },
        )
        .await?;

    if let Some(groupinfo_info) = scimentry_into_groupinfo(scim_entry) {
        Ok(groupinfo_info)
    } else {
        Err(WebError::from(OperationError::InvalidState))
    }
}

async fn get_groups_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Vec<(ScimGroup, ScimEffectiveAccess)>, WebError> {
    let filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Group.into());

    let base: ScimListResponse = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(GROUP_ATTRIBUTES)),
                ext_access_check: true,
            },
        )
        .await?;

    // TODO: inefficient to sort here
    let mut groups: Vec<_> = base
        .resources
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_groupinfo)
        .collect();

    groups.sort_by_key(|(sp, _)| sp.uuid);
    groups.reverse();

    Ok(groups)
}

fn scimentry_into_groupinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimGroup, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let group = ScimGroup::try_from(scim_entry).ok()?;

    Some((group, scim_effective_access))
}
