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
use axum_extra::extract::Form;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{OperationError, UserAuthToken};
use kanidm_proto::scim_v1::server::{
    ScimEffectiveAccess, ScimEntryKanidm, ScimGroup, ScimListResponse, ScimValueKanidm,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::scim_v1::{client::ScimEntryPutKanidm, ScimFilter};
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::idm::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;
use uuid::Uuid;

pub const GROUP_ATTRIBUTES: [Attribute; 2] = [Attribute::Uuid, Attribute::Name];

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
    can_rw: bool,
    scim_effective_access: ScimEffectiveAccess,
}

#[derive(Template)]
#[template(path = "admin/saved_toast.html")]
struct SavedToast {}

pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (group, scim_effective_access) =
        get_group_info(uuid, state.clone(), &kopid, client_auth_info.clone()).await?;
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);
    let can_rw = uat.purpose_readwrite_active(time);
    let group_partial = GroupViewPartial {
        group,
        can_rw,
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
                ..Default::default()
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
                sort_by: Some(Attribute::Name),
                ..Default::default()
            },
        )
        .await?;

    let groups: Vec<_> = base
        .resources
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_groupinfo)
        .collect();

    Ok(groups)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SaveGroupForm {
    uuid: Uuid,
    #[serde(rename = "name")]
    account_name: String,
}

pub(crate) async fn edit_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SaveGroupForm>,
) -> axum::response::Result<Response> {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        Attribute::Name,
        Some(ScimValueKanidm::String(query.account_name)),
    );

    let generic = ScimEntryPutKanidm {
        id: query.uuid,
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

    // return floating notification: saved/failed
    Ok((SavedToast {}).into_response())
}

fn scimentry_into_groupinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimGroup, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let group = ScimGroup::try_from(scim_entry).ok()?;

    Some((group, scim_effective_access))
}
