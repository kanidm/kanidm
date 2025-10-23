use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::{ErrorToastPartial, Urls};
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
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
use kanidmd_lib::filter::{f_eq, Filter};
use kanidmd_lib::idm::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const GROUP_ATTRIBUTES: [Attribute; 4] = [
    Attribute::Uuid,
    Attribute::Name,
    Attribute::Description,
    Attribute::Member,
];

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
pub(crate) struct GroupsView {
    navbar_ctx: NavbarCtx,
    partial: GroupsPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_groups_partial.html")]
struct GroupsPartialView {
    groups: Vec<(ScimGroup, ScimEffectiveAccess)>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct GroupView {
    partial: GroupViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_group_view_partial.html")]
struct GroupViewPartial {
    group: ScimGroup,
    can_rw: bool,
    scim_effective_access: ScimEffectiveAccess,
}

#[derive(Template, WebTemplate)]
#[template(
    ext = "html",
    source = "\
(% include \"admin/admin_group_member_entry_partial.html\" %)\
(% include \"admin/saved_toast.html\" %)\
"
)]
struct GroupMemberEntryResponse {
    group_uuid: Uuid,
    member_name: String,
    can_edit_member: bool,
}

#[derive(Template, WebTemplate)]
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
    let push_url = HxPushUrl(path_string);
    Ok(if is_htmx {
        (push_url, group_partial).into_response()
    } else {
        (
            push_url,
            GroupView {
                partial: group_partial,
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
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
    let groups = get_groups_info(state, &kopid, client_auth_info.clone()).await?;
    let groups_partial = GroupsPartialView { groups };
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let push_url = HxPushUrl("/ui/admin/groups".to_string());
    Ok(if is_htmx {
        (push_url, groups_partial).into_response()
    } else {
        (
            push_url,
            GroupsView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
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
    #[serde(rename = "name")]
    account_name: String,
    description: Option<String>,
}

pub(crate) async fn edit_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SaveGroupForm>,
) -> axum::response::Result<Response> {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        Attribute::Name,
        Some(ScimValueKanidm::String(query.account_name)),
    );

    let (group_info, _) =
        get_group_info(group_uuid, state.clone(), &kopid, client_auth_info.clone()).await?;

    // query.description can't be Some("") since axum deserializes "" to None.
    // Also meaning that I can't check if someone wants to unset a field or couldn't set the field.
    // Thus, I check if there's a difference below to make up for this.
    if group_info.description != query.description {
        attrs.insert(
            Attribute::Description,
            query.description.map(ScimValueKanidm::String),
        );
    }

    let generic = ScimEntryPutKanidm {
        id: group_uuid,
        attrs,
    }
    .try_into()
    .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;

    state
        .qe_w_ref
        .handle_scim_entry_put(client_auth_info.clone(), kopid.eventid, generic)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    // return floating notification: saved/failed
    Ok((SavedToast {}).into_response())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AddMemberForm {
    member: String,
}

pub(crate) async fn add_member(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<AddMemberForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

    let get_query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Member]),
        ext_access_check: false,
        sort_by: None,
        sort_order: None,
        start_index: None,
        count: None,
        filter: None,
    };
    let get_member_query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Spn]),
        ext_access_check: false,
        sort_by: None,
        sort_order: None,
        start_index: None,
        count: None,
        filter: None,
    };
    let group_uuid_str = String::from(group_uuid);
    let before = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            group_uuid_str.clone(),
            EntryClass::Group,
            get_query.clone(),
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;
    state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            group_uuid_str.clone(),
            "member".to_string(),
            vec![query.member.clone()],
            filter,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let after = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            group_uuid_str.clone(),
            EntryClass::Group,
            get_query,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let before_len = if let Some(ScimValueKanidm::EntryReferences(members_before)) =
        before.attrs.get(&Attribute::Member)
    {
        members_before.len()
    } else {
        0
    };
    let after_len = if let Some(ScimValueKanidm::EntryReferences(members_after)) =
        after.attrs.get(&Attribute::Member)
    {
        members_after.len()
    } else {
        0
    };

    if before_len + 1 == after_len {
        let added_member_scim = state
            .qe_r_ref
            .scim_entry_id_get(
                client_auth_info.clone(),
                kopid.eventid,
                query.member.clone(),
                EntryClass::Object,
                get_member_query,
            )
            .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
            .await?;

        let Some(ScimValueKanidm::String(added_member_spn)) =
            added_member_scim.attrs.get(&Attribute::Spn)
        else {
            return Ok((ErrorToastPartial {
                err_code: OperationError::UI0004MemberAlreadyExists,
                operation_id: kopid.eventid,
            })
            .into_response());
        };
        // New entry + saved toast.
        Ok((GroupMemberEntryResponse {
            group_uuid,
            member_name: added_member_spn.to_string(),
            can_edit_member: true,
        })
        .into_response())
    } else {
        // Duplicate entry toast.
        Ok((ErrorToastPartial {
            err_code: OperationError::UI0004MemberAlreadyExists,
            operation_id: kopid.eventid,
        })
        .into_response())
    }
}

pub(crate) async fn remove_member(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<AddMemberForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

    state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            String::from(group_uuid),
            "member".to_string(),
            vec![query.member],
            filter,
            kopid.eventid,
        )
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
