use std::net::SocketAddr;
#[allow(unused_imports)]
// //! The V1 API things!
use std::str::FromStr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::headers::{CacheControl, HeaderMapExt};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};

use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use axum_sessions::extractors::{ReadableSession, WritableSession};
use compact_jwt::Jws;
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper::Body;
use kanidm_proto::v1::{
    AccountUnixExtend, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, CUIntentToken, CURequest, CUSessionToken, CreateRequest,
    DeleteRequest, Entry as ProtoEntry, GroupUnixExtend, ModifyRequest, SearchRequest,
    SingleStringRequest,
};

use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::https::to_axum_response;

use super::middleware::caching::dont_cache_me;
use super::middleware::KOpId;
use super::v1_scim::*;
use super::ServerState;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SessionId {
    pub sessionid: Uuid,
}

#[debug_handler]
pub async fn create(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<CreateRequest>,
) -> Response<Body> {
    // parse the req to a CreateRequest
    // let msg: CreateRequest = req.body_json().await?;

    let res = state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn v1_modify(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<ModifyRequest>,
) -> Response<Body> {
    let res = state
        .qe_w_ref
        .handle_modify(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn v1_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<DeleteRequest>,
) -> Response<Body> {
    let res = state
        .qe_w_ref
        .handle_delete(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn search(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<SearchRequest>,
) -> Response<Body> {
    let res = state
        .qe_r_ref
        .handle_search(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[debug_handler]
pub async fn whoami(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<Body> {
    // New event, feed current auth data from the token to it.
    let res = state.qe_r_ref.handle_whoami(kopid.uat, kopid.eventid).await;
    to_axum_response(res)
}

pub async fn whoami_uat(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    session: ReadableSession,
) -> impl IntoResponse {
    let uat = match kopid.uat {
        Some(val) => Some(val),
        None => session.get("bearer"),
    };
    let res = state.qe_r_ref.handle_whoami_uat(uat, kopid.eventid).await;
    to_axum_response(res)
}

pub async fn logout(
    State(state): State<ServerState>,
    mut msession: WritableSession,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // Now lets nuke any cookies for the session. We do this before the handle_logout
    // so that if any errors occur, the cookies are still removed.
    msession.remove("auth-session-id");
    msession.remove("bearer");

    let res = state.qe_w_ref.handle_logout(kopid.uat, kopid.eventid).await;

    to_axum_response(res)
}

// // =============== REST generics ========================

#[instrument(level = "trace", skip(state, kopid))]
pub async fn json_rest_event_get(
    state: ServerState,
    attrs: Option<Vec<String>>,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await;

    to_axum_response(res)
}

pub async fn json_rest_event_get_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn json_rest_event_delete_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let res = state
        .qe_w_ref
        .handle_internaldelete(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_get_attr(
    state: ServerState,
    id: &str,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));
    let attrs = Some(vec![attr.clone()]);
    let res: Result<Option<_>, _> = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
    to_axum_response(res)
}

pub async fn json_rest_event_get_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

pub async fn json_rest_event_post(
    state: ServerState,
    classes: Vec<String>,
    obj: ProtoEntry,
    kopid: KOpId,
) -> impl IntoResponse {
    debug_assert!(!classes.is_empty());

    let mut obj = obj;
    obj.attrs.insert("class".to_string(), classes);
    let msg = CreateRequest {
        entries: vec![obj.to_owned()],
    };

    let res = state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_post_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_put_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_setattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_post_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let uuid_or_name = id;
    let res = state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, uuid_or_name, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_put_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_delete_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_attr(
    state: ServerState,
    uuid_or_name: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    let values = match values {
        Some(val) => val,
        None => vec![],
    };

    if values.is_empty() {
        let res = state
            .qe_w_ref
            .handle_purgeattribute(kopid.uat, uuid_or_name, attr, filter, kopid.eventid)
            .await;
        to_axum_response(res)
    } else {
        let res = state
            .qe_w_ref
            .handle_removeattributevalues(
                kopid.uat,
                uuid_or_name,
                attr,
                values,
                filter,
                kopid.eventid,
            )
            .await;
        to_axum_response(res)
    }
}

// // Okay, so a put normally needs
// //  * filter of what we are working on (id + class)
// //  * a Map<String, Vec<String>> that we turn into a modlist.
// //
// // OR
// //  * filter of what we are working on (id + class)
// //  * a Vec<String> that we are changing
// //  * the attr name  (as a param to this in path)
// //
// // json_rest_event_put_id(path, req, state

pub async fn schema_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("class", PartialValue::new_class("classtype"))
    ]));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_attributetype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_attributetype_get_id(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // These can't use get_id because the attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8(id.as_str()))
    ]));

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn schema_classtype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_classtype_get_id(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8(id.as_str()))
    ]));
    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

// // == person ==
pub async fn person_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get(state, None, filter, kopid).await
}

// expects the following fields in the attrs field of the req: [name, displayname]
#[debug_handler]
pub async fn person_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "person".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn person_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn person_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

// // == account ==

pub async fn service_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn service_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "service_account".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn service_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn service_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_accont")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

pub async fn service_account_credential_generate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_credential_generate(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Due to how the migrations work in 6 -> 7, we can accidentally
// // mark "accounts" as service accounts when they are persons. This
// // allows migrating them to the person type due to it's similarities.
// //
// // In the future this will be REMOVED!
pub async fn service_account_into_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_into_person(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Api Token
pub async fn service_account_api_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_service_account_api_token_get(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn service_account_api_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ApiTokenGenerate>, // TODO work out if this limits the fields?
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_api_token_generate(
            kopid.uat,
            id,
            obj.label,
            obj.expiry,
            obj.read_write,
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

pub async fn service_account_api_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_api_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Account stuff
// TODO: shouldn't this be service_account?
pub async fn account_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

pub async fn account_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn account_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

pub async fn account_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

pub async fn account_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    // Update a value / attrs

    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let res = state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_credential_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdate(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[instrument(level = "trace", skip(state, kopid))]
pub async fn account_get_id_credential_update_intent_ttl(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Query(ttl): Query<u64>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            kopid.uat,
            id,
            Some(Duration::from_secs(ttl)),
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

#[instrument(level = "trace", skip(state, kopid))]
pub async fn account_get_id_credential_update_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdateintent(kopid.uat, id, None, kopid.eventid)
        .await;
    // panic!("res: {:?}", res);
    to_axum_response(res)
}

pub async fn account_get_id_user_auth_token(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_account_user_auth_token_get(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_user_auth_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_account_user_auth_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_exchange_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(intent_token): Json<CUIntentToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialexchangeintent(intent_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmcredentialupdatestatus(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

// #[derive(Deserialize, Debug, Clone)]
// struct CUBody {
//     pub session_token: CUSessionToken,
//     pub scr: CURequest,
// }
#[instrument(level = "debug", skip(state, kopid))]
pub async fn credential_update_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(cubody): Json<Vec<serde_json::Value>>,
) -> impl IntoResponse {
    let scr: CURequest = match serde_json::from_value(cubody[0].clone()) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to deserialize CURequest: {:?}", err);
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };
    let session_token = match serde_json::from_value(cubody[1].clone()) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to deserialize session token: {:?}", err);
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };
    debug!("session_token: {:?}", session_token);
    debug!("scr: {:?}", scr);
    let res = state
        .qe_r_ref
        .handle_idmcredentialupdate(session_token, scr, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_commit(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdatecommit(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_cancel(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdatecancel(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_credential_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmcredentialstatus(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Return a vec of str
pub async fn account_get_id_ssh_pubkeys(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsshkeyread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_ssh_pubkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    // Add a msg here
    let res = state
        .qe_w_ref
        .handle_sshkeycreate(kopid.uat, id, tag, key, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_ssh_pubkey_tag(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsshkeytagread(kopid.uat, id, tag, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_ssh_pubkey_tag(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> impl IntoResponse {
    let attr = "ssh_publickey".to_string();
    let values = vec![tag];
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let res = state
        .qe_w_ref
        .handle_removeattributevalues(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Get and return a single str
pub async fn account_get_id_radius(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalradiusread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_radius_regenerate(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Need to to send the regen msg
    let res = state
        .qe_w_ref
        .handle_regenerateradius(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_radius(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

pub async fn account_get_id_radius_token(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalradiustokenread(kopid.uat, id, kopid.eventid)
        .await;
    let mut res = to_axum_response(res);
    debug!("Response: {:?}", res);
    let cache_header = CacheControl::new()
        .with_max_age(Duration::from_secs(300))
        .with_private();
    res.headers_mut().typed_insert(cache_header);
    res
}

pub async fn account_post_id_unix(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AccountUnixExtend>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmaccountunixextend(kopid.uat, id, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalunixusertokenread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_unix_auth(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmaccountunixauth(kopid.uat, id, obj.value, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_put_id_unix_credential(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmaccountunixsetcred(kopid.uat, id, obj.value, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_unix_credential(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("posixaccount")));
    let res = state
        .qe_w_ref
        .handle_purgeattribute(
            kopid.uat,
            id,
            "unix_password".to_string(),
            filter,
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

pub async fn group_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn group_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn group_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn group_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid).await
}

pub async fn group_id_post_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn group_id_delete_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    values: Option<Json<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    let values = values.map(|v| v.0);
    json_rest_event_delete_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn group_id_put_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_put_id_attr(state, id, attr, filter, values, kopid).await
}
pub async fn group_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

pub async fn group_post_id_unix(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<GroupUnixExtend>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmgroupunixextend(kopid.uat, id, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn group_get_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalunixgrouptokenread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn domain_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_DOMAIN_INFO)));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn domain_get_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_attr(state, STR_UUID_DOMAIN_INFO, attr, filter, kopid).await
}

pub async fn domain_put_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_put_attr(
        state,
        STR_UUID_DOMAIN_INFO.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn domain_delete_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_delete_attr(
        state,
        STR_UUID_DOMAIN_INFO.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn system_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_SYSTEM_CONFIG)));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn system_get_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_get_attr(state, STR_UUID_SYSTEM_CONFIG, attr, filter, kopid).await
}

pub async fn system_post_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_post_attr(
        state,
        STR_UUID_SYSTEM_CONFIG.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn system_delete_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_delete_attr(
        state,
        STR_UUID_SYSTEM_CONFIG.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn recycle_bin_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_pres("class"));
    let attrs = None;
    let res = state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn recycle_bin_id_get(
    State(state): State<ServerState>,

    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    let res = state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn recycle_bin_revive_id_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_id(id.as_str()));
    let res = state
        .qe_w_ref
        .handle_reviverecycled(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn applinks_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    session: ReadableSession,
) -> impl IntoResponse {
    let uat = match kopid.uat {
        Some(val) => Some(val),
        None => session.get("bearer"),
    };
    let res = state
        .qe_r_ref
        .handle_list_applinks(uat, kopid.eventid)
        .await;
    to_axum_response(res)
}

// TODO: routemap things
// pub async fn do_routemap(State(state): State<RouteMap>) -> impl IntoResponse {
//     Json(state.do_map())
// }

pub async fn reauth(
    State(state): State<ServerState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>, // TODO: test x-ff-headers
    Extension(kopid): Extension<KOpId>,
    session: WritableSession,
    Json(obj): Json<AuthIssueSession>,
) -> impl IntoResponse {
    // TODO: xff things check that we can get the remote IP address first, since this doesn't touch the backend at all
    // let ip_addr = req.get_remote_addr().ok_or_else(|| {
    //     error!("Unable to get remote addr for auth event, refusing to proceed");
    //     tide::Error::from_str(
    //         tide::StatusCode::InternalServerError,
    //         "unable to validate peer address",
    //     )
    // })?;

    // This may change in the future ...
    let inter = state
        .qe_r_ref
        .handle_reauth(kopid.uat, obj, kopid.eventid, addr.ip())
        .await;
    debug!("REAuth result: {:?}", inter);
    auth_session_state_management(state, inter, session)
}

pub async fn auth(
    State(state): State<ServerState>,
    session: WritableSession,
    headers: HeaderMap,
    Extension(kopid): Extension<KOpId>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(obj): Json<AuthRequest>,
) -> impl IntoResponse {
    // TODO: check this trusts the x-ff-header
    let ip_addr = addr.ip();
    // check that we can get the remote IP address first, since this doesn't touch the backend at all
    // let ip_addr = req.get_remote_addr().ok_or_else(|| {
    //     error!("Unable to get remote addr for auth event, refusing to proceed");
    //     tide::Error::from_str(
    //         tide::StatusCode::InternalServerError,
    //         "unable to validate peer address",
    //     )
    // })?;

    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    // TODO
    let maybe_sessionid = state.get_current_auth_session_id(&headers, &session);
    debug!("Session ID: {:?}", maybe_sessionid);
    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, kopid.eventid, ip_addr)
        .await;

    debug!("Auth result: {:?}", inter);

    auth_session_state_management(state, inter, session)
}

#[instrument(skip(state))]
fn auth_session_state_management(
    state: ServerState,
    inter: Result<AuthResult, OperationError>,
    mut msession: WritableSession,
) -> impl IntoResponse {
    let mut auth_session_id_tok = None;

    let res: Result<AuthResponse, _> = match inter {
        Ok(AuthResult {
            state: auth_state,
            sessionid,
        }) => {
            // Do some response/state management.
            match auth_state {
                AuthState::Choose(allowed) => {
                    debug!("🧩 -> AuthState::Choose"); // TODO: this should be ... less work

                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .and_then(|_| {
                            let kref = &state.jws_signer;
                            let jws = Jws::new(SessionId { sessionid });
                            // Get the header token ready.
                            jws.sign(kref)
                                .map(|jwss| {
                                    auth_session_id_tok = Some(jwss.to_string());
                                })
                                .map_err(|e| {
                                    error!(?e);
                                    OperationError::InvalidSessionState
                                })
                        })
                        .map(|_| ProtoAuthState::Choose(allowed))
                }
                AuthState::Continue(allowed) => {
                    debug!("🧩 -> AuthState::Continue");

                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    trace!(?sessionid, "🔥  🔥 ");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .and_then(|_| {
                            let kref = &state.jws_signer;
                            // Get the header token ready.
                            let jws = Jws::new(SessionId { sessionid });
                            jws.sign(kref)
                                .map(|jwss| {
                                    auth_session_id_tok = Some(jwss.to_string());
                                })
                                .map_err(|e| {
                                    error!(?e);
                                    OperationError::InvalidSessionState
                                })
                        })
                        .map(|_| ProtoAuthState::Continue(allowed))
                }
                AuthState::Success(token, issue) => {
                    debug!("🧩 -> AuthState::Success");
                    // Remove the auth-session-id

                    msession.remove("auth-session-id");
                    // Create a session cookie?
                    msession.remove("bearer");

                    match issue {
                        AuthIssueSession::Cookie => msession
                            .insert("bearer", token)
                            .map_err(|_| OperationError::InvalidSessionState)
                            .map(|_| ProtoAuthState::SuccessCookie),
                        AuthIssueSession::Token => Ok(ProtoAuthState::Success(token)),
                    }
                }
                AuthState::Denied(reason) => {
                    debug!("🧩 -> AuthState::Denied");
                    // Remove the auth-session-id
                    msession.remove("auth-session-id");
                    Ok(ProtoAuthState::Denied(reason))
                }
            }
            .map(|state| AuthResponse { sessionid, state })
        }
        Err(e) => Err(e),
    };

    let mut res = to_axum_response(res);

    // if the sessionid was injected into our cookie, set it in the header too.
    match auth_session_id_tok {
        Some(tok) => {
            #[allow(clippy::unwrap_used)]
            res.headers_mut().insert(
                "X-KANIDM-AUTH-SESSION-ID",
                HeaderValue::from_str(&tok).unwrap(),
            );
            res
        }
        None => res,
    }
}

pub async fn auth_valid(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    session: ReadableSession,
) -> impl IntoResponse {
    let uat = match kopid.uat {
        Some(val) => Some(val),
        None => session.get("bearer"),
    };
    let res = state.qe_r_ref.handle_auth_valid(uat, kopid.eventid).await;
    to_axum_response(res)
}

#[instrument(skip(state))]
pub fn router(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route("/oauth2", get(super::oauth2::oauth2_get))
        .route(
            "/oauth2/:rs_name",
            get(super::oauth2::oauth2_id_get)
                .patch(super::oauth2::oauth2_id_patch)
                .delete(super::oauth2::oauth2_id_delete),
        )
        .route(
            "/oauth2/:rs_name/_basic_secret",
            get(super::oauth2::oauth2_id_get_basic_secret),
        )
        .route("/oauth2/_basic", post(super::oauth2::oauth2_basic_post))
        .route(
            "/oauth2/:rs_name/_scopemap/:group",
            post(super::oauth2::oauth2_id_scopemap_post)
                .delete(super::oauth2::oauth2_id_scopemap_delete),
        )
        .route(
            "/oauth2/:rs_name/_sup_scopemap/:group",
            post(super::oauth2::oauth2_id_sup_scopemap_post)
                .delete(super::oauth2::oauth2_id_sup_scopemap_delete),
        )
        .route("/raw/create", post(create))
        .route("/raw/modify", post(v1_modify))
        .route("/raw/delete", post(v1_delete))
        .route("/raw/search", post(search))
        .route("/schema", get(schema_get))
        .route(
            "/schema/attributetype",
            get(schema_attributetype_get), // post(|| async { "TODO" })
        )
        .route(
            "/schema/attributetype/:id",
            get(schema_attributetype_get_id),
        )
        // .route("/schema/attributetype/:id", put(|| async { "TODO" }).patch(|| async { "TODO" }))
        .route(
            "/schema/classtype",
            get(schema_classtype_get), // .post(|| async { "TODO" })
        )
        .route(
            "/schema/classtype/:id",
            get(schema_classtype_get_id)
                .put(|| async { "TODO" })
                .patch(|| async { "TODO" }),
        )
        .route("/self", get(whoami))
        .route("/self/_uat", get(whoami_uat))
        .route("/self/_attr/:attr", get(|| async { "TODO" }))
        .route("/self/_credential", get(|| async { "TODO" }))
        .route("/self/_credential/:cid/_lock", get(|| async { "TODO" }))
        .route(
            "/self/_radius",
            get(|| async { "TODO" })
                .delete(|| async { "TODO" })
                .post(|| async { "TODO" }),
        )
        .route("/self/_radius/_config", post(|| async { "TODO" }))
        .route("/self/_radius/_config/:token", get(|| async { "TODO" }))
        .route(
            "/self/_radius/_config/:token/apple",
            get(|| async { "TODO" }),
        )
        // Applinks are the list of apps this account can access.
        .route("/self/_applinks", get(applinks_get))
        // Person routes
        .route("/person", get(person_get))
        .route("/person", post(person_post))
        .route(
            "/person/:id",
            get(person_id_get)
                .patch(account_id_patch)
                .delete(person_account_id_delete),
        )
        .route(
            "/person/:id/_attr/:attr",
            get(account_id_get_attr)
                .put(account_id_put_attr)
                .post(account_id_post_attr)
                .delete(account_id_delete_attr),
        )
        .route("/person/:id/_lock", get(|| async { "TODO" }))
        .route("/person/:id/_credential", get(|| async { "TODO" }))
        .route(
            "/person/:id/_credential/_status",
            get(account_get_id_credential_status),
        )
        .route(
            "/person/:id/_credential/:cid/_lock",
            get(|| async { "TODO" }),
        )
        .route(
            "/person/:id/_credential/_update",
            get(account_get_id_credential_update),
        )
        .route(
            "/person/:id/_credential/_update_intent/:ttl",
            get(account_get_id_credential_update_intent_ttl),
        )
        .route(
            "/person/:id/_credential/_update_intent",
            get(account_get_id_credential_update_intent),
        )
        .route(
            "/person/:id/_ssh_pubkeys",
            get(account_get_id_ssh_pubkeys).post(account_post_id_ssh_pubkey),
        )
        .route(
            "/person/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag).delete(account_delete_id_ssh_pubkey_tag),
        )
        .route(
            "/person/:id/_radius",
            get(account_get_id_radius)
                .post(account_post_id_radius_regenerate)
                .delete(account_delete_id_radius),
        )
        .route(
            "/person/:id/_radius/_token",
            get(account_get_id_radius_token),
        ) // TODO: make this cacheable
        .route("/person/:id/_unix", post(account_post_id_unix))
        .route(
            "/person/:id/_unix/_credential",
            put(account_put_id_unix_credential).delete(account_delete_id_unix_credential),
        )
        // Service accounts
        .route(
            "/service_account",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/service_account/",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/service_account/:id",
            get(service_account_id_get).delete(service_account_id_delete),
        )
        .route(
            "/service_account/:id/_attr/:attr",
            get(account_id_get_attr)
                .put(account_id_put_attr)
                .post(account_id_post_attr)
                .delete(account_id_delete_attr),
        )
        .route("/service_account/:id/_lock", get(|| async { "TODO" }))
        .route(
            "/service_account/:id/_into_person",
            post(service_account_into_person),
        )
        .route(
            "/service_account/:id/_api_token",
            post(service_account_api_token_post).get(service_account_api_token_get),
        )
        .route(
            "/service_account/:id/_api_token/:token_id",
            delete(service_account_api_token_delete),
        )
        .route("/service_account/:id/_credential", get(|| async { "TODO" }))
        .route(
            "/service_account/:id/_credential/_generate",
            get(service_account_credential_generate),
        )
        .route(
            "/service_account/:id/_credential/_status",
            get(account_get_id_credential_status),
        )
        .route(
            "/service_account/:id/_credential/:cid/_lock",
            get(|| async { "TODO" }),
        )
        .route(
            "/service_account/:id/_ssh_pubkeys",
            get(account_get_id_ssh_pubkeys).post(account_post_id_ssh_pubkey),
        )
        .route(
            "/service_account/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag).delete(account_delete_id_ssh_pubkey_tag),
        )
        .route("/service_account/:id/_unix", post(account_post_id_unix))
        .route("/account/:id/_unix/_auth", post(account_post_id_unix_auth))
        .route(
            "/account/:id/_unix/_token",
            post(account_get_id_unix_token).get(account_get_id_unix_token), // TODO: make this cacheable
        )
        .route(
            "/account/:id/_radius/_token",
            post(account_get_id_radius_token).get(account_get_id_radius_token), // TODO: make this cacheable
        )
        .route("/account/:id/_ssh_pubkeys", get(account_get_id_ssh_pubkeys))
        .route(
            "/account/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag),
        )
        .route(
            "/account/:id/_user_auth_token",
            get(account_get_id_user_auth_token),
        )
        .route(
            "/account/:id/_user_auth_token/:token_id",
            delete(account_user_auth_token_delete),
        )
        .route(
            "/credential/_exchange_intent",
            post(credential_update_exchange_intent),
        )
        .route("/credential/_status", post(credential_update_status))
        .route("/credential/_update", post(credential_update_update))
        .route("/credential/_commit", post(credential_update_commit))
        .route("/credential/_cancel", post(credential_update_cancel))
        // domain-things
        .route("/domain", get(domain_get))
        .route(
            "/domain/_attr/:attr",
            get(domain_get_attr)
                .put(domain_put_attr)
                .delete(domain_delete_attr),
        )
        .route("/group/:id/_unix/_token", get(group_get_id_unix_token))
        .route("/group/:id/_unix", post(group_post_id_unix))
        .route("/group", get(group_get).post(group_post))
        .route("/group/:id", get(group_id_get).delete(group_id_delete))
        .route(
            "/group/:id/_attr/:attr",
            delete(group_id_delete_attr)
                .get(group_id_get_attr)
                .put(group_id_put_attr)
                .post(group_id_post_attr),
        )
        .with_state(state.clone())
        .route("/system", get(system_get))
        .route(
            "/system/_attr/:attr",
            get(system_get_attr)
                .post(system_post_attr)
                .delete(system_delete_attr),
        )
        .route("/recycle_bin", get(recycle_bin_get))
        .route("/recycle_bin/:id", get(recycle_bin_id_get))
        .route("/recycle_bin/:id/_revive", post(recycle_bin_revive_id_post))
        .route("/access_profile", get(|| async { "TODO" }))
        .route("/access_profile/:id", get(|| async { "TODO" }))
        .route("/access_profile/:id/_attr/:attr", get(|| async { "TODO" }))
        .route("/auth", post(auth))
        .route("/auth/valid", get(auth_valid))
        .route("/logout", get(logout))
        .route("/reauth", post(reauth))
        .route(
            "/sync_account",
            get(sync_account_get).post(sync_account_post),
        )
        .route(
            "/sync_account/",
            get(sync_account_get).post(sync_account_post),
        )
        .route(
            "/sync_account/:id",
            get(sync_account_id_get).patch(sync_account_id_patch),
        )
        .route(
            "/sync_account/:id/_attr/:attr",
            get(sync_account_id_get_attr).put(sync_account_id_put_attr),
        )
        .route(
            "/sync_account/:id/_finalise",
            get(sync_account_id_get_finalise),
        )
        .route(
            "/sync_account/:id/_terminate",
            get(sync_account_id_get_terminate),
        )
        .route(
            "/sync_account/:id/_sync_token",
            // .get(&mut sync_account_token_get)
            post(sync_account_token_post).delete(sync_account_token_delete),
        )
        .with_state(state)
        .layer(from_fn(dont_cache_me))
}
