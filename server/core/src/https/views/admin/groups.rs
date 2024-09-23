use crate::https::extractors::{AccessInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::admin::filters;
use crate::https::views::errors::HtmxError;
use crate::https::views::{login, HtmlTemplate};
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Uri};
use axum::response::{ErrorResponse, IntoResponse, Response};
use axum::{Extension, Form};
use axum_extra::extract::CookieJar;
use axum_htmx::{HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_ENTRY_MANAGED_BY, ATTR_MAIL, ATTR_MEMBER, ATTR_NAME, ATTR_SPN, ATTR_UUID,
};
use kanidm_proto::internal::{OperationError, UserAuthToken};
use kanidm_proto::v1::Entry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_and, f_eq, f_id, f_or, Filter, FC};
use kanidmd_lib::idm::ClientAuthInfo;
use kanidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GroupInfo {
    uuid: String,
    name: String,
    spn: String,
    entry_manager: Option<String>,
    acp: GroupACP,
    mails: Vec<String>,
    members: Vec<MemberInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GroupACP {
    enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MemberInfo {
    uuid: String,
    name: String,
    spn: String,
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
    managed_by: Option<String>,
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
        )
            .into_response()
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
    view_groups_get(
        State(state),
        HxRequest(is_htmx),
        Extension(kopid),
        VerifiedClientInformation(client_auth_info),
    )
    .await
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct GroupDetailsFormData {
    name: String,
    spn: String,
    entry_manager: String,
}

#[derive(Template)]
#[template(path = "admin/admin_group_details_partial.html")]
struct GroupMemberDetailsPartialView {
    group: GroupInfo,
    can_edit: bool,
}

pub(crate) async fn view_group_save_post(
    State(state): State<ServerState>,
    HxRequest(_is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(guuid): Path<Uuid>,
    Form(data): Form<GroupDetailsFormData>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into())]));
    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            guuid.to_string(),
            ATTR_NAME.to_string(),
            vec![data.name.clone()],
            filter,
            kopid.eventid,
        )
        .await
        .map_err(|x| HtmxError::new(&kopid, x))?;

    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into())]));
    state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            guuid.to_string(),
            ATTR_ENTRY_MANAGED_BY.to_string(),
            vec![data.name.clone()],
            filter,
            kopid.eventid,
        )
        .await
        .map_err(|x| HtmxError::new(&kopid, x))?;

    let group_info = get_group_info(guuid, state.clone(), &kopid, client_auth_info.clone())
        .await?;

    Ok((HtmlTemplate(GroupMemberDetailsPartialView {
        group: group_info,
        can_edit: true,
    }))
    .into_response())
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct GroupAddMemberFormData {
    member: String,
}

#[derive(Template)]
#[template(path = "admin/admin_group_member_partial.html")]
struct GroupMemberPartialView {
    can_edit: bool,
    group_uuid: Uuid,
    member: MemberInfo,
}

pub(crate) async fn view_group_new_member_post(
    State(state): State<ServerState>,
    HxRequest(_is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(guuid): Path<Uuid>,
    Form(data): Form<GroupAddMemberFormData>,
) -> axum::response::Result<Response> {
    let mut ors = vec![f_id(data.member.as_str())];
    let class_filter = vec![
        f_eq(Attribute::Class, EntryClass::Group.into()),
        f_eq(Attribute::Class, EntryClass::Account.into()),
    ];
    let spn_value = data
        .member
        .split_once('@')
        .map(|x| PartialValue::Spn(x.0.into(), x.1.into()));
    if let Some(spn_value) = spn_value {
        ors.push(f_eq(Attribute::Spn, spn_value))
    }

    let filter = filter_all!(f_and!([f_or(class_filter), f_or(ors)]));

    let perfect_members = state
        .qe_r_ref
        .handle_internalsearch(
            client_auth_info.clone(),
            filter,
            None,
            kopid.clone().eventid,
        )
        .await
        .map_err(|x| HtmxError::new(&kopid, x))?;

    dbg!(perfect_members.clone());

    if let Some(perfect_entry) = perfect_members.first() {
        let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into()),]));
        let uuid = perfect_entry
            .attrs
            .get(ATTR_UUID)
            .unwrap_or(&vec![])
            .first()
            .unwrap()
            .clone();
        state
            .qe_w_ref
            .handle_appendattribute(
                client_auth_info,
                guuid.into(),
                ATTR_MEMBER.to_string(),
                vec![uuid],
                filter,
                kopid.eventid,
            )
            .await
            .map_err(|x| HtmxError::new(&kopid, x))?;

        Ok(HtmlTemplate(GroupMemberPartialView {
            can_edit: true,
            group_uuid: guuid,
            member: entry_into_memberinfo(perfect_entry),
        })
        .into_response())
    } else {
        Ok("".into_response())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct GroupAddMailFormData {
    mail: String,
}

#[derive(Template)]
#[template(path = "admin/admin_group_mail_partial.html")]
struct GroupMailPartialView {
    can_edit: bool,
    group_uuid: Uuid,
    mail: String,
}

pub(crate) async fn view_group_new_mail_post(
    State(state): State<ServerState>,
    HxRequest(_is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(guuid): Path<Uuid>,
    Form(data): Form<GroupAddMailFormData>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into()),]));
    let mail = data.mail;
    state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info,
            guuid.into(),
            ATTR_MAIL.to_string(),
            vec![mail.clone()],
            filter,
            kopid.eventid,
        )
        .await
        .map_err(|x| HtmxError::new(&kopid, x))?;

    Ok(HtmlTemplate(GroupMailPartialView {
        can_edit: true,
        group_uuid: guuid,
        mail,
    })
    .into_response())
}

pub(crate) async fn view_group_create_post(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Form(data): Form<GroupCreateFormData>,
) -> axum::response::Result<Response> {
    dbg!(data);
    view_groups_get(
        State(state),
        HxRequest(is_htmx),
        Extension(kopid),
        VerifiedClientInformation(client_auth_info),
    )
    .await
}

pub(crate) async fn view_group_edit_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    let can_rw = get_can_rw(&state, &kopid, &client_auth_info).await?;
    let group = get_group_info(uuid, state, &kopid, client_auth_info).await?;
    let groups_partial = GroupViewPartial {
        can_rw,
        can_edit: true,
        group,
    };

    let path_string = format!("/ui/admin/group/{uuid}/edit").clone();
    let src = path_string.clone();
    let push_url = HxPushUrl(Uri::from_str(src.as_str()).expect("T"));
    Ok(if is_htmx {
        (push_url, HtmlTemplate(groups_partial)).into_response()
    } else {
        (
            push_url,
            HtmlTemplate(GroupView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
            }),
        )
            .into_response()
    })
}

#[derive(Template)]
#[template(path = "admin/admin_overview.html")]
struct GroupView {
    access_info: AccessInfo,
    partial: GroupViewPartial,
}

#[derive(Template)]
#[template(path = "admin/admin_group_view_partial.html")]
struct GroupViewPartial {
    can_rw: bool,
    can_edit: bool,
    group: GroupInfo,
}

pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    let can_rw = get_can_rw(&state, &kopid, &client_auth_info).await?;
    let group = get_group_info(uuid, state, &kopid, client_auth_info).await?;
    let groups_partial = GroupViewPartial {
        can_rw,
        can_edit: false,
        group,
    };

    let path_string = format!("/ui/admin/group/{uuid}/view").clone();
    let src = path_string.clone();
    let push_url = HxPushUrl(Uri::from_str(src.as_str()).expect("T"));
    Ok(if is_htmx {
        (push_url, HtmlTemplate(groups_partial)).into_response()
    } else {
        (
            push_url,
            HtmlTemplate(GroupView {
                access_info: AccessInfo::new(),
                partial: groups_partial,
            }),
        )
            .into_response()
    })
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
        )
            .into_response()
    })
}

pub(crate) async fn view_groups_unlock_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> axum::response::Result<Response> {
    let referrer = match headers.get(header::REFERER) {
        Some(header_value) => header_value.to_str().map_err(|x| {
            warn!("referer header couldn't be converted to string: {x}");
            HtmxError::OperationError(kopid.eventid, OperationError::InvalidRequestState)
        })?,
        None => "/ui/admin/groups",
    };
    login::view_reauth_get(state, client_auth_info, kopid, jar, referrer).await
}

async fn get_can_rw(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &ClientAuthInfo,
) -> Result<bool, ErrorResponse> {
    let uat: UserAuthToken = state
        .qe_r_ref
        .handle_whoami_uat(client_auth_info.clone(), kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let time = time::OffsetDateTime::now_utc() + time::Duration::new(60, 0);

    let can_rw = uat.purpose_readwrite_active(time);
    Ok(can_rw)
}

async fn get_group_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<GroupInfo, ErrorResponse> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::Group.into()),
        f_id(uuid.to_string().as_str())
    ]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let first = base.first().ok_or(HtmxError::OperationError(
        kopid.eventid,
        OperationError::NoMatchingEntries,
    ))?;
    Ok(entry_into_groupinfo(first))
}
async fn get_groups_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Vec<GroupInfo>, ErrorResponse> {
    let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Group.into())]));
    let base: Vec<Entry> = state
        .qe_r_ref
        .handle_internalsearch(client_auth_info.clone(), filter, None, kopid.eventid)
        .map_err(|op_err| HtmxError::new(&kopid, op_err))
        .await?;

    let mut groups: Vec<_> = base
        .iter()
        .map(|entry: &Entry| entry_into_groupinfo(entry))
        .collect();
    groups.sort_by_key(|gi| gi.uuid.clone());
    groups.reverse();
    Ok(groups)
}

fn entry_into_memberinfo(entry: &Entry) -> MemberInfo {
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
    let spn = entry
        .attrs
        .get(ATTR_SPN)
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

    MemberInfo {
        uuid,
        name,
        spn,
        displayname,
    }
}

fn entry_into_groupinfo(entry: &Entry) -> GroupInfo {
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

    let spn = entry
        .attrs
        .get(ATTR_SPN)
        .unwrap_or(&vec![])
        .first()
        .unwrap_or(&format!("{name}@localhost").to_string())
        .clone();

    let entry_manager = entry
        .attrs
        .get(ATTR_ENTRY_MANAGED_BY)
        .unwrap_or(&vec![])
        .first()
        .cloned();
    let mails = entry
        .attrs
        .get(ATTR_MAIL)
        .unwrap_or(&vec![format!("{name}@melijn.com")])
        .clone();

    GroupInfo {
        uuid,
        name: name.clone(),
        spn,
        entry_manager,
        acp: GroupACP { enabled: false },
        mails,
        members: vec![
            MemberInfo {
                uuid: "793e3694-9766-433f-b898-6da5052334d1".to_string(),
                name: "merlijn".to_string(),
                spn: "merlijn@localhost".to_string(),
                displayname: "PixelHamster".to_string(),
            },
            MemberInfo {
                uuid: "4af67f60-8f80-4750-87a4-7151eb305831".to_string(),
                name: "alt".to_string(),
                spn: "alt@localhost".to_string(),
                displayname: "ToxicMushroom".to_string(),
            },
        ],
    }
}
