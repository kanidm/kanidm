use crate::https::extractors::{AccessInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::{login, HtmlTemplate};
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::response::{ErrorResponse, IntoResponse, Response};
use axum::{Extension, Form};
use axum_extra::extract::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_NAME, ATTR_UUID};
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::v1::Entry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_and, f_eq, Filter, FC};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use kanidmd_lib::idm::ClientAuthInfo;

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct GroupsView {
    access_info: AccessInfo,
    partial: GroupsPartialView,
}


#[derive(Template)]
#[template(path = "admin/admin_groups_partial.html")]
struct GroupsPartialView {
    can_rw: bool,
    groups: Vec<GroupInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GroupInfo {
    uuid: String,
    name: String,
    displayname: String,
}

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct GroupCreateView {
    access_info: AccessInfo,
    partial: GroupCreatePartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_group_create_partial.html")]
struct GroupCreatePartialView {
    can_rw: bool,
    groups: Vec<GroupInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GroupCreateFormData {
    name: String,
    guid: Option<String>,
    managed_by: Option<String>
}

pub(crate) async fn view_group_create_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let can_rw = get_can_rw(&state, &kopid, &client_auth_info).await?;

    let groups = get_groups_info(state, &kopid, client_auth_info).await?;
    let groups_partial = GroupCreatePartialView { can_rw, groups };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/group/create"));
    Ok(if is_htmx {
        (push_url, HtmlTemplate(groups_partial)).into_response()
    } else {
        (
            push_url,
            HtmlTemplate(GroupCreateView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
            }),
        ).into_response()
    })
}

pub(crate) async fn view_group_delete_post(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    Path(group_uuid): Path<Uuid>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    dbg!(group_uuid);
    view_groups_get(State(state), HxRequest(is_htmx), Extension(kopid), VerifiedClientInformation(client_auth_info)).await
}

pub(crate) async fn view_group_create_post(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Form(data): Form<GroupCreateFormData>
) -> axum::response::Result<Response> {
    dbg!(data);
    view_groups_get(State(state), HxRequest(is_htmx), Extension(kopid), VerifiedClientInformation(client_auth_info)).await
}


pub(crate) async fn view_group_edit_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    view_groups_get(State(state), HxRequest(is_htmx), Extension(kopid), VerifiedClientInformation(client_auth_info)).await
}


pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    view_groups_get(State(state), HxRequest(is_htmx), Extension(kopid), VerifiedClientInformation(client_auth_info)).await
}

pub(crate) async fn view_groups_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let can_rw = get_can_rw(&state, &kopid, &client_auth_info).await?;

    let groups = get_groups_info(state, &kopid, client_auth_info).await?;
    let groups_partial = GroupsPartialView { can_rw, groups };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/groups"));
    Ok(if is_htmx {
        (push_url, HtmlTemplate(groups_partial)).into_response()
    } else {
        (
            push_url,
            HtmlTemplate(GroupsView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
            }),
        ).into_response()
    })
}

pub(crate) async fn view_groups_unlock_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    login::view_reauth_get(state, client_auth_info, kopid, jar, "/ui/admin/groups").await
}

async fn get_can_rw(state: &ServerState, kopid: &KOpId, client_auth_info: &ClientAuthInfo) -> Result<bool, ErrorResponse> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);
    Ok(can_rw)
}

async fn get_groups_info(state: ServerState, kopid: &KOpId, client_auth_info: ClientAuthInfo) -> Result<Vec<GroupInfo>, ErrorResponse> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into())]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let mut groups: Vec<_> = base
        .into_iter()
        .map(|entry: Entry| {
            let uuid = entry
                .attrs
                .get(ATTR_UUID)
                .unwrap_or(&vec![])
                .first()
                .unwrap_or(&"".to_string())
                .clone();
            let name = entry
                .attrs
                .get(ATTR_NAME)
                .unwrap_or(&vec![])
                .first()
                .unwrap_or(&"".to_string())
                .clone();
            let displayname = entry
                .attrs
                .get(ATTR_DISPLAYNAME)
                .unwrap_or(&vec![])
                .first()
                .unwrap_or(&"".to_string())
                .clone();
            GroupInfo {
                uuid,
                name,
                displayname,
            }
        })
        .collect();
    groups.sort_by_key(|gi| gi.uuid.clone());
    groups.reverse();
    Ok(groups)
}
