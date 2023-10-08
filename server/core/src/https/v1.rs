//! The V1 API things!

use std::net::IpAddr;

use axum::extract::{Path, Query, State};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use compact_jwt::Jws;
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use kanidm_proto::internal::{AppLink, IdentifyUserRequest, IdentifyUserResponse};
use kanidm_proto::v1::{
    AccountUnixExtend, ApiToken, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, CUIntentToken, CURequest, CUSessionToken, CUStatus, CreateRequest,
    CredentialStatus, DeleteRequest, Entry as ProtoEntry, GroupUnixExtend, ModifyRequest,
    RadiusAuthToken, SearchRequest, SearchResponse, SingleStringRequest, UatStatus, UnixGroupToken,
    UnixUserToken, UserAuthToken, WhoamiResponse,
};
use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::value::PartialValue;

use super::apidocs::path_schema;
use super::errors::WebError;
use super::middleware::caching::{cache_me, dont_cache_me};
use super::middleware::KOpId;
use super::ServerState;
use crate::https::apidocs::response_schema::{DefaultApiResponse, ApiResponseWithout200};
use crate::https::extractors::TrustedClientIp;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SessionId {
    pub sessionid: Uuid,
}

#[utoipa::path(
    post,
    path = "/v1/raw/create",
    responses(
        DefaultApiResponse,
    ),
    request_body=CreateRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_create(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<CreateRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/raw/modify",
    responses(
        DefaultApiResponse,
    ),
    request_body=ModifyRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_modify(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<ModifyRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_modify(kopid.uat, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/raw/delete",
    responses(
        DefaultApiResponse,
    ),
    request_body=DeleteRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<DeleteRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_delete(kopid.uat, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/raw/search",
    responses(
        ApiResponseWithout200,
    ),
    request_body=SearchRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_search(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, WebError> {
    state
        .qe_r_ref
        .handle_search(kopid.uat, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self",
    responses(DefaultApiResponse),
    security(("token_jwt" = [])),
    tag = "v1/self",
)]
// Whoami?
pub async fn whoami(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<WhoamiResponse>, WebError> {
    // New event, feed current auth data from the token to it.
    state
        .qe_r_ref
        .handle_whoami(kopid.uat, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self/_uat",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/self",
)]
pub async fn whoami_uat(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<UserAuthToken>, WebError> {
    state
        .qe_r_ref
        .handle_whoami_uat(kopid.uat, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/logout",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/auth",
)]
pub async fn logout(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_logout(kopid.uat, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

// // =============== REST generics ========================

#[instrument(level = "trace", skip(state, kopid))]
pub async fn json_rest_event_get(
    state: ServerState,
    attrs: Option<Vec<String>>,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_get_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
    kopid: KOpId,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_delete_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internaldelete(kopid.uat, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_get_attr(
    state: ServerState,
    id: &str,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));
    let attrs = Some(vec![attr.clone()]);
    state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)))
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_get_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

pub async fn json_rest_event_post(
    state: ServerState,
    classes: Vec<String>,
    obj: ProtoEntry,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    debug_assert!(!classes.is_empty());

    let mut obj = obj;
    obj.attrs.insert(Attribute::Class.to_string(), classes);
    let msg = CreateRequest {
        entries: vec![obj.to_owned()],
    };

    state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_post_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_put_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_setattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await
        .map_err(WebError::from)
        .map(Json::from)
}

pub async fn json_rest_event_post_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

// Okay, so a put normally needs
///  * filter of what we are working on (id + class)
///  * a `Map<String, Vec<String>>` that we turn into a modlist.
///
/// OR
///  * filter of what we are working on (id + class)
///  * a `Vec<String>` that we are changing
///  * the attr name  (as a param to this in path)
///
pub async fn json_rest_event_put_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    json_rest_event_delete_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_attr(
    state: ServerState,
    uuid_or_name: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> Result<Json<()>, WebError> {
    let values = match values {
        Some(val) => val,
        None => vec![],
    };

    if values.is_empty() {
        state
            .qe_w_ref
            .handle_purgeattribute(kopid.uat, uuid_or_name, attr, filter, kopid.eventid)
            .await
    } else {
        state
            .qe_w_ref
            .handle_removeattributevalues(
                kopid.uat,
                uuid_or_name,
                attr,
                values,
                filter,
                kopid.eventid,
            )
            .await
    }
    .map(Json::from)
    .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/schema",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
)]
// Whoami?
pub async fn schema_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq(Attribute::Class, EntryClass::AttributeType.into()),
        f_eq(Attribute::Class, EntryClass::ClassType.into())
    ]));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/attributetype",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
)]
pub async fn schema_attributetype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::AttributeType.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/attributetype/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
)]
pub async fn schema_attributetype_get_id(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    // These can't use get_id because the attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::AttributeType.into()),
        f_eq(
            Attribute::AttributeName,
            PartialValue::new_iutf8(id.as_str())
        )
    ]));

    state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/schema/classtype",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
)]
pub async fn schema_classtype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ClassType.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/classtype/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
)]
pub async fn schema_classtype_get_id(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::ClassType.into()),
        f_eq(Attribute::ClassName, PartialValue::new_iutf8(id.as_str()))
    ]));
    state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn person_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/person",
    request_body=Json, // TODO: ProtoEntry can't be serialized, so we need to do this manually
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
/// Expects the following fields in the attrs field of the req: [name, displayname]
pub async fn person_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![
        EntryClass::Person.into(),
        EntryClass::Account.into(),
        EntryClass::Object.into(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}",
    responses(
        (status = 200, description = "Ok"),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn person_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn person_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

// // == account ==

#[utoipa::path(
    get,
    path = "/v1/service_account",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/service_account",
    request_body=Json, // TODO ProtoEntry can't be serialized, so we need to do this manually
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![
        EntryClass::ServiceAccount.into(),
        EntryClass::Account.into(),
        EntryClass::Object.into(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_credential/_generate",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_credential_generate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<String>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_credential_generate(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_into_person",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
/// Due to how the migrations work in 6 -> 7, we can accidentally
/// mark "accounts" as service accounts when they are persons. This
/// allows migrating them to the person type due to its similarities.
///
/// In the future this will be REMOVED!
#[deprecated]
pub async fn service_account_into_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_into_person(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_spi_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_api_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Vec<ApiToken>>, WebError> {
    state
        .qe_r_ref
        .handle_service_account_api_token_get(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_spi_token",
    params(
        path_schema::Id,
    ),
    request_body = ApiTokenGenerate,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_api_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ApiTokenGenerate>,
) -> Result<Json<String>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_api_token_generate(
            kopid.uat,
            id,
            obj.label,
            obj.expiry,
            obj.read_write,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}/_spi_token/{token_id}",
    params(
        path_schema::Id,
        path_schema::TokenId,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_api_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_api_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
)]
pub async fn person_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_attr/{attr}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_attr/{attr}",
    params(
        path_schema::Id,
        path_schema::Attr,
    ),
    request_body= Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
)]
pub async fn person_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_attr/{attr}",
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
)]
pub async fn person_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}/_attr/{attr}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

#[utoipa::path(
    put,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
)]
pub async fn person_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    put,
    path = "/v1/service_account/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    patch,
    path = "/v1/person/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    // request_body=ProtoEntry, // TODO: can't deal with a HashMap in the attr
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn person_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    // Update a value / attrs
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_update",
    responses((status = 200),(status = 403),),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
pub async fn person_id_credential_update_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<(CUSessionToken, CUStatus)>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdate(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_update_intent/?ttl={ttl}",
    params(
        ("ttl" = u32, Query, description="The new TTL for the credential?") // TODO: this is a query param?
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
// TODO: this shouldn't be a get, we're making changes!
#[instrument(level = "trace", skip(state, kopid))]
pub async fn person_id_credential_update_intent_ttl_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Query(ttl): Query<u64>,
) -> Result<Json<CUIntentToken>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            kopid.uat,
            id,
            Some(Duration::from_secs(ttl)),
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_update_intent",
    params(
        path_schema::Id,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
#[instrument(level = "trace", skip(state, kopid))]
pub async fn person_id_credential_update_intent_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<CUIntentToken>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdateintent(kopid.uat, id, None, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_user_auth_token",
    params(
        path_schema::Id,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_id_user_auth_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<UatStatus>>, WebError> {
    state
        .qe_r_ref
        .handle_account_user_auth_token_get(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_user_auth_token/{token_id}",
    params(
        path_schema::Id,
        path_schema::TokenId,
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_user_auth_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_account_user_auth_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/credential/_exchange_intent",
    params(
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
pub async fn credential_update_exchange_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(intent_token): Json<CUIntentToken>,
) -> Result<Json<(CUSessionToken, CUStatus)>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialexchangeintent(intent_token, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/credential/_status",
    params(
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
pub async fn credential_update_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> Result<Json<CUStatus>, WebError> {
    state
        .qe_r_ref
        .handle_idmcredentialupdatestatus(session_token, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

// #[derive(Deserialize, Debug, Clone)]
// struct CUBody {
//     pub session_token: CUSessionToken,
//     pub scr: CURequest,
// }

#[utoipa::path(
    post,
    path = "/v1/credential/_update",
    params(
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
#[instrument(level = "debug", skip(state, kopid))]
pub async fn credential_update_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(cubody): Json<Vec<serde_json::Value>>,
) -> Result<Json<CUStatus>, WebError> {
    let scr: CURequest = match serde_json::from_value(cubody[0].clone()) {
        Ok(val) => val,
        Err(err) => {
            let errmsg = format!("Failed to deserialize CURequest: {:?}", err);
            error!("{}", errmsg);
            return Err(WebError::InternalServerError(errmsg));
        }
    };
    let session_token = match serde_json::from_value(cubody[1].clone()) {
        Ok(val) => val,
        Err(err) => {
            let errmsg = format!("Failed to deserialize session token: {:?}", err);
            error!("{}", errmsg);
            return Err(WebError::InternalServerError(errmsg));
        }
    };
    debug!("session_token: {:?}", session_token);
    debug!("scr: {:?}", scr);
    state
        .qe_r_ref
        .handle_idmcredentialupdate(session_token, scr, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

// /v1/credential/_commit

#[utoipa::path(
    post,
    path = "/v1/credential/_commit",
    params(
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
pub async fn credential_update_commit(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdatecommit(session_token, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/credential/_cancel",
    params(
    ),

    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
pub async fn credential_update_cancel(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdatecancel(session_token, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_credential/_status",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_credential_status_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<CredentialStatus>, WebError> {
    state
        .qe_r_ref
        .handle_idmcredentialstatus(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_credential/_status",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
pub async fn person_get_id_credential_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<CredentialStatus>, WebError> {
    state
        .qe_r_ref
        .handle_idmcredentialstatus(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_ssh_pubkeys",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
)]
pub async fn person_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}
#[utoipa::path(
    get,
    path = "/v1/account/{id}/_ssh_pubkeys",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
#[deprecated]
pub async fn account_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_ssh_pubkeys",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_ssh_pubkeys",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
)]
pub async fn person_id_ssh_pubkeys_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    // Add a msg here
    state
        .qe_w_ref
        .handle_sshkeycreate(kopid.uat, id, tag, key, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_ssh_pubkeys",
    request_body = (String, String),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_ssh_pubkeys_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    // Add a msg here
    state
        .qe_w_ref
        .handle_sshkeycreate(kopid.uat, id, tag, key, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_ssh_pubkeys/{tag}",
    params(
        // TODO: this is totes wrong
        ("id" = String, description="The ID of the account, a uuid?"),
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys/tag",
)]
pub async fn person_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(kopid.uat, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}
#[utoipa::path(
    get,
    path = "/v1/account/{id}/_ssh_pubkeys/{tag}",
    params(
        // TODO: this is totes wrong
        ("id" = String, description="The ID of the account, a uuid?"),
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(kopid.uat, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_ssh_pubkeys/{tag}",
    params(
        // TODO: this is totes wrong
        ("id" = String, description="The ID of the account, a uuid?"),
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(kopid.uat, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_ssh_pubkeys/{tag}",
    params(
        // TODO: this is totes wrong
        ("id" = String, description="The ID of the account, a uuid?"),
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys/tag",
)]
pub async fn person_id_ssh_pubkeys_tag_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let values = vec![tag];
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    state
        .qe_w_ref
        .handle_removeattributevalues(
            kopid.uat,
            id,
            Attribute::SshPublicKey.to_string(),
            values,
            filter,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}/_ssh_pubkeys/{tag}",
    params(
        // TODO: this is totes wrong
        ("id" = String, description="The ID of the account, a uuid?"),
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn service_account_id_ssh_pubkeys_tag_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let values = vec![tag];
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    state
        .qe_w_ref
        .handle_removeattributevalues(
            kopid.uat,
            id,
            Attribute::SshPublicKey.to_string(),
            values,
            filter,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

// // Get and return a single str
#[utoipa::path(
    get,
    path = "/v1/person/{id}/_radius",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
)]
pub async fn person_id_radius_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Option<String>>, WebError> {
    // TODO: string
    state
        .qe_r_ref
        .handle_internalradiusread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_radius",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
)]
// TODO: what body do we take here?
pub async fn person_id_radius_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<String>, WebError> {
    // Need to to send the regen msg
    state
        .qe_w_ref
        .handle_regenerateradius(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_radius",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)]
pub async fn person_id_radius_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

// /v1/person/:id/_radius/_token
#[utoipa::path(
    get,
    path = "/v1/person/{id}/_radius/_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
)]
pub async fn person_id_radius_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid).await
}

// /v1/account/:id/_radius/_token
#[utoipa::path(
    get,
    path = "/v1/account/{id}/_radius/_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_id_radius_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/account/{id}/_radius/_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)] // TODO: what body do we expect here?
pub async fn account_id_radius_token_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid).await
}

async fn person_id_radius_handler(
    state: ServerState,
    id: String,
    kopid: KOpId,
) -> Result<Json<RadiusAuthToken>, WebError> {
    state
        .qe_r_ref
        .handle_internalradiustokenread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_unix",
    request_body=Jaon<AccountUnixExtend>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
)]
#[instrument(name = "account_post_id_unix", level = "INFO", skip(id, state, kopid))]
pub async fn person_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AccountUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixextend(kopid.uat, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_unix",
    request_body = AccountUnixExtend,
    responses(
        (status = 200),
        (status = 400),
        (status = 403),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)] // TODO: what body do we expect here?
///
#[instrument(, level = "INFO", skip(id, state, kopid))]
pub async fn service_account_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AccountUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixextend(kopid.uat, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/account/{id}/_unix",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)] // TODO: what body do we expect here?
/// Expects an `AccountUnixExtend` object
#[instrument(, level = "INFO", skip(id, state, kopid))]
pub async fn account_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AccountUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixextend(kopid.uat, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,post,
    path = "/v1/account/{id}/_unix/_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)] // TODO: what body do we expect here?
#[instrument(level = "INFO", skip_all)]
pub async fn account_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<UnixUserToken>, WebError> {
    // no point asking for an empty id
    if id.is_empty() {
        return Err(OperationError::EmptyRequest.into());
    }

    let res = state
        .qe_r_ref
        .handle_internalunixusertokenread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from);

    if let Err(OperationError::InvalidAccountState(val)) = &res {
        // if they're not a posix user we should just hide them
        if *val == format!("Missing class: {}", "posixaccount") {
            return Err(OperationError::NoMatchingEntries.into());
        }
    };
    // the was returning a 500 error which wasn't right
    if let Err(OperationError::InvalidValueState) = &res {
        return Err(OperationError::NoMatchingEntries.into());
    };
    res.map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/account/{id}/_unix/_auth",
    params(
        ("id" = String, Path, description="The ID of the account, a username/UUID"),
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)] // TODO: what body do we expect here?
pub async fn account_id_unix_auth_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> Result<Json<Option<UnixUserToken>>, WebError> {
    state
        .qe_r_ref
        .handle_idmaccountunixauth(kopid.uat, id, obj.value, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_unix/_credential",
    request_body = SingleStringRequest,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
)] // TODO: what body do we expect here?
pub async fn person_id_unix_credential_put(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixsetcred(kopid.uat, id, obj.value, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_unix/_credential",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
)]
pub async fn person_id_unix_credential_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::PosixAccount.into()));
    state
        .qe_w_ref
        .handle_purgeattribute(
            kopid.uat,
            id,
            "unix_password".to_string(),
            filter,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_identify/_user",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
)] // TODO: what body do we expect here?
pub async fn person_identify_user_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(user_request): Json<IdentifyUserRequest>,
) -> Result<Json<IdentifyUserResponse>, WebError> {
    state
        .qe_r_ref
        .handle_user_identity_verification(kopid.uat, kopid.eventid, user_request, id)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/group",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
)]
/// Returns all groups visible  to the user
pub async fn group_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/group/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
)] // TODO: post body
pub async fn group_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(state, classes, obj, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
)]
pub async fn group_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/group/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
)]
pub async fn group_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}/_attr/{attr}",
    params(
        path_schema::Id,
        path_schema::Attr,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
)]
pub async fn group_id_attr_get(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/group/{id}/_attr/{attr}",
    params(
        path_schema::Id,
        path_schema::Attr,
    ),
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
)]
pub async fn group_id_attr_post(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    delete,
    path = "/v1/group/{id}/_attr/{attr}",
    params(
        path_schema::Id,
        path_schema::Attr,
    ),
    request_body=Option<Json<Vec<String>>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
)]
pub async fn group_id_attr_delete(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    values: Option<Json<Vec<String>>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    let values = values.map(|v| v.0);
    json_rest_event_delete_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    put,
    path = "/v1/group/{id}/_attr/{attr}",
    params(
        path_schema::Id,
        path_schema::Attr,
    ),
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
)]
pub async fn group_id_attr_put(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_put_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    put,
    path = "/v1/group/{id}/_unix",
    request_body = GroupUnixExtend,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/unix",
)]
pub async fn group_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<GroupUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmgroupunixextend(kopid.uat, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}/_unix/_token",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/unix",
)]
pub async fn group_id_unix_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> Result<Json<UnixGroupToken>, WebError> {
    state
        .qe_r_ref
        .handle_internalunixgrouptokenread(kopid.uat, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/domain",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
)]
pub async fn domain_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO)));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/domain/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
)]
pub async fn domain_attr_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::DomainInfo.into()));
    json_rest_event_get_attr(state, STR_UUID_DOMAIN_INFO, attr, filter, kopid).await
}

#[utoipa::path(
    put,
    path = "/v1/domain/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
)]
pub async fn domain_attr_put(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::DomainInfo.into()));
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

#[utoipa::path(
    delete,
    path = "/v1/domain/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    request_body=Json<Option<Vec<String>>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
)]
pub async fn domain_attr_delete(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::DomainInfo.into()));
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

#[utoipa::path(
    get,
    path = "/v1/system",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
)]
pub async fn system_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Uuid,
        PartialValue::Uuid(UUID_SYSTEM_CONFIG)
    ));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/system/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
)]
pub async fn system_attr_get(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()));
    json_rest_event_get_attr(state, STR_UUID_SYSTEM_CONFIG, attr, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/system/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
)]
pub async fn system_attr_post(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()));
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

#[utoipa::path(
    delete,
    path = "/v1/system/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    request_body=Json<Option<Vec<String>>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
)]
pub async fn system_attr_delete(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()));
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

#[utoipa::path(
    put,
    path = "/v1/system/_attr/{attr}",
    params(
        path_schema::Attr,
    ),
    request_body=Json<Vec<String>>,
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
)]
pub async fn system_attr_put(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()));
    json_rest_event_put_attr(
        state,
        STR_UUID_SYSTEM_CONFIG.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/recycle_bin",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
)]
pub async fn recycle_bin_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_pres(Attribute::Class));
    let attrs = None;
    state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/recycle_bin/{id}",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
)]
pub async fn recycle_bin_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/recycle_bin/{id}/_revive",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
)]
pub async fn recycle_bin_revive_id_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_id(id.as_str()));
    state
        .qe_w_ref
        .handle_reviverecycled(kopid.uat, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self/_applinks",
    params(
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/self",
)]
/// Returns your OAuth2 app links for the Web UI
pub async fn applinks_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Vec<AppLink>>, WebError> {
    state
        .qe_r_ref
        .handle_list_applinks(kopid.uat, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/reauth",
    responses(
        (status = 200, body=Json<AuthResponse>, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    request_body = AuthIssueSession,
    security(("token_jwt" = [])),
    tag = "v1/auth",
)] // TODO: post body stuff
pub async fn reauth(
    State(state): State<ServerState>,
    TrustedClientIp(ip_addr): TrustedClientIp,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthIssueSession>,
) -> Result<Response, WebError> {
    // This may change in the future ...
    let inter = state
        .qe_r_ref
        .handle_reauth(kopid.uat, obj, kopid.eventid, ip_addr)
        .await;
    debug!("ReAuth result: {:?}", inter);
    auth_session_state_management(state, inter)
}

#[utoipa::path(
    post,
    path = "/v1/auth",
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    request_body = AuthRequest,
    security(("token_jwt" = [])),
    tag = "v1/auth",
)]
pub async fn auth(
    State(state): State<ServerState>,
    TrustedClientIp(ip_addr): TrustedClientIp,
    headers: HeaderMap,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthRequest>,
) -> Result<Response, WebError> {
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    let maybe_sessionid = state.get_current_auth_session_id(&headers);
    debug!("Session ID: {:?}", maybe_sessionid);
    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, kopid.eventid, ip_addr)
        .await;
    debug!("Auth result: {:?}", inter);
    auth_session_state_management(state, inter)
}

#[instrument(skip(state))]
fn auth_session_state_management(
    state: ServerState,
    inter: Result<AuthResult, OperationError>,
) -> Result<Response, WebError> {
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
                        .map(|_| ProtoAuthState::Choose(allowed))
                }
                AuthState::Continue(allowed) => {
                    debug!("🧩 -> AuthState::Continue");
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
                        .map(|_| ProtoAuthState::Continue(allowed))
                }
                AuthState::Success(token, issue) => {
                    debug!("🧩 -> AuthState::Success");

                    match issue {
                        AuthIssueSession::Token => Ok(ProtoAuthState::Success(token)),
                    }
                }
                AuthState::Denied(reason) => {
                    debug!("🧩 -> AuthState::Denied");
                    Ok(ProtoAuthState::Denied(reason))
                }
            }
            .map(|state| AuthResponse { sessionid, state })
        }
        Err(e) => Err(e),
    };

    // if the sessionid was injected into our cookie, set it in the header too.
    res.map(|response| {
        let mut res = Json::from(response).into_response();
        match auth_session_id_tok {
            Some(tok) => {
                #[allow(clippy::unwrap_used)]
                res.headers_mut()
                    .insert(KSESSIONID, HeaderValue::from_str(&tok).unwrap());
                res
            }
            None => res,
        }
    })
    .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/auth/valid",
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/auth",
)]
pub async fn auth_valid(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<()>, WebError> {
    state
        .qe_r_ref
        .handle_auth_valid(kopid.uat, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/debug/ipinfo",
    responses(
        (status = 200, description = "Ok"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/debug",
)]
pub async fn debug_ipinfo(
    State(_state): State<ServerState>,
    TrustedClientIp(ip_addr): TrustedClientIp,
) -> Result<Json<Vec<IpAddr>>, ()> {
    Ok(Json::from(vec![ip_addr]))
}

fn cacheable_routes(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route(
            "/v1/person/:id/_radius/_token",
            get(person_id_radius_token_get),
        )
        .route("/v1/account/:id/_unix/_token", get(account_id_unix_token))
        .route(
            "/v1/account/:id/_radius/_token",
            get(account_id_radius_token_get),
        )
        .layer(from_fn(cache_me))
        .with_state(state)
}

#[instrument(skip(state))]
pub(crate) fn route_setup(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route("/v1/oauth2", get(super::v1_oauth2::oauth2_get))
        .route(
            "/v1/oauth2/_basic",
            post(super::v1_oauth2::oauth2_basic_post),
        )
        .route(
            "/v1/oauth2/_public",
            post(super::v1_oauth2::oauth2_public_post),
        )
        .route(
            "/v1/oauth2/:rs_name",
            get(super::v1_oauth2::oauth2_id_get)
                .patch(super::v1_oauth2::oauth2_id_patch)
                .delete(super::v1_oauth2::oauth2_id_delete),
        )
        .route(
            "/v1/oauth2/:rs_name/_image",
            post(super::v1_oauth2::oauth2_id_image_post)
                .delete(super::v1_oauth2::oauth2_id_image_delete),
        )
        .route(
            "/v1/oauth2/:rs_name/_basic_secret",
            get(super::v1_oauth2::oauth2_id_get_basic_secret),
        )
        .route(
            "/v1/oauth2/:rs_name/_scopemap/:group",
            post(super::v1_oauth2::oauth2_id_scopemap_post)
                .delete(super::v1_oauth2::oauth2_id_scopemap_delete),
        )
        .route(
            "/v1/oauth2/:rs_name/_sup_scopemap/:group",
            post(super::v1_oauth2::oauth2_id_sup_scopemap_post)
                .delete(super::v1_oauth2::oauth2_id_sup_scopemap_delete),
        )
        .route("/v1/raw/create", post(raw_create)) // skip_route_check
        .route("/v1/raw/modify", post(raw_modify)) // skip_route_check
        .route("/v1/raw/delete", post(raw_delete)) // skip_route_check
        .route("/v1/raw/search", post(raw_search)) // skip_route_check
        .route("/v1/schema", get(schema_get))
        .route(
            "/v1/schema/attributetype",
            get(schema_attributetype_get), // post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/attributetype/:id",
            get(schema_attributetype_get_id),
        )
        // .route("/schema/attributetype/:id", put(|| async { "TODO" }).patch(|| async { "TODO" }))
        .route(
            "/v1/schema/classtype",
            get(schema_classtype_get), // .post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/classtype/:id",
            get(schema_classtype_get_id), //         .put(|| async { "TODO" })
                                          //         .patch(|| async { "TODO" }),
        )
        .route("/v1/self", get(whoami))
        .route("/v1/self/_uat", get(whoami_uat))
        // .route("/v1/self/_attr/:attr", get(|| async { "TODO" }))
        // .route("/v1/self/_credential", get(|| async { "TODO" }))
        // .route("/v1/self/_credential/:cid/_lock", get(|| async { "TODO" }))
        // .route(
        //     "/v1/self/_radius",
        //     get(|| async { "TODO" })
        //         .delete(|| async { "TODO" })
        //         .post(|| async { "TODO" }),
        // )
        // .route("/v1/self/_radius/_config", post(|| async { "TODO" }))
        // .route("/v1/self/_radius/_config/:token", get(|| async { "TODO" }))
        // .route(
        //     "/v1/self/_radius/_config/:token/apple",
        //     get(|| async { "TODO" }),
        // )
        // Applinks are the list of apps this account can access.
        .route("/v1/self/_applinks", get(applinks_get))
        // Person routes
        .route("/v1/person", get(person_get).post(person_post))
        .route(
            "/v1/person/:id",
            get(person_id_get)
                .patch(person_id_patch)
                .delete(person_id_delete),
        )
        .route(
            "/v1/person/:id/_attr/:attr",
            get(person_id_get_attr)
                .put(person_id_put_attr)
                .post(person_id_post_attr)
                .delete(person_id_delete_attr),
        )
        // .route("/v1/person/:id/_lock", get(|| async { "TODO" }))
        // .route("/v1/person/:id/_credential", get(|| async { "TODO" }))
        .route(
            "/v1/person/:id/_credential/_status",
            get(person_get_id_credential_status),
        )
        // .route(
        //     "/v1/person/:id/_credential/:cid/_lock",
        //     get(|| async { "TODO" }),
        // )
        .route(
            "/v1/person/:id/_credential/_update",
            get(person_id_credential_update_get),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent/:ttl", // TODO: I'm pretty sure this route is wrong, because we match the query not the path
            get(person_id_credential_update_intent_ttl_get),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent",
            get(person_id_credential_update_intent_get),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys",
            get(person_id_ssh_pubkeys_get).post(person_id_ssh_pubkeys_post),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys/:tag",
            get(person_id_ssh_pubkeys_tag_get).delete(person_id_ssh_pubkeys_tag_delete),
        )
        .route(
            "/v1/person/:id/_radius",
            get(person_id_radius_get)
                .post(person_id_radius_post)
                .delete(person_id_radius_delete),
        )
        .route("/v1/person/:id/_unix", post(service_account_id_unix_post))
        .route(
            "/v1/person/:id/_unix/_credential",
            put(person_id_unix_credential_put).delete(person_id_unix_credential_delete),
        )
        .route(
            "/v1/person/:id/_identify_user",
            post(person_identify_user_post),
        )
        // Service accounts
        .route(
            "/v1/service_account",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/v1/service_account/",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/v1/service_account/:id",
            get(service_account_id_get).delete(service_account_id_delete),
        )
        .route(
            "/v1/service_account/:id/_attr/:attr",
            get(service_account_id_get_attr)
                .put(service_account_id_put_attr)
                .post(service_account_id_post_attr)
                .delete(service_account_id_delete_attr),
        )
        // .route("/v1/service_account/:id/_lock", get(|| async { "TODO" }))
        .route(
            "/v1/service_account/:id/_into_person",
            #[allow(deprecated)]
            post(service_account_into_person),
        )
        .route(
            "/v1/service_account/:id/_api_token",
            post(service_account_api_token_post).get(service_account_api_token_get),
        )
        .route(
            "/v1/service_account/:id/_api_token/:token_id",
            delete(service_account_api_token_delete),
        )
        // .route(
        //     "/v1/service_account/:id/_credential",
        //     get(|| async { "TODO" }),
        // )
        .route(
            "/v1/service_account/:id/_credential/_generate",
            get(service_account_credential_generate),
        )
        .route(
            "/v1/service_account/:id/_credential/_status",
            get(service_account_id_credential_status_get),
        )
        // .route(
        //     "/v1/service_account/:id/_credential/:cid/_lock",
        //     get(|| async { "TODO" }),
        // )
        .route(
            "/v1/service_account/:id/_ssh_pubkeys",
            get(service_account_id_ssh_pubkeys_get).post(service_account_id_ssh_pubkeys_post),
        )
        .route(
            "/v1/service_account/:id/_ssh_pubkeys/:tag",
            get(service_account_id_ssh_pubkeys_tag_get)
                .delete(service_account_id_ssh_pubkeys_tag_delete),
        )
        .route(
            "/v1/service_account/:id/_unix",
            post(service_account_id_unix_post),
        )
        .route(
            "/v1/account/:id/_unix/_auth",
            post(account_id_unix_auth_post),
        )
        .route("/v1/account/:id/_unix/_token", post(account_id_unix_token))
        .route(
            "/v1/account/:id/_radius/_token",
            post(account_id_radius_token_post),
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys",
            #[allow(deprecated)]
            get(account_id_ssh_pubkeys_get),
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys/:tag",
            get(account_id_ssh_pubkeys_tag_get),
        )
        .route(
            "/v1/account/:id/_user_auth_token",
            get(account_id_user_auth_token_get),
        )
        .route(
            "/v1/account/:id/_user_auth_token/:token_id",
            delete(account_user_auth_token_delete),
        )
        .route(
            "/v1/credential/_exchange_intent",
            post(credential_update_exchange_intent),
        )
        .route("/v1/credential/_status", post(credential_update_status))
        .route("/v1/credential/_update", post(credential_update_update))
        .route("/v1/credential/_commit", post(credential_update_commit))
        .route("/v1/credential/_cancel", post(credential_update_cancel))
        // domain-things
        .route("/v1/domain", get(domain_get))
        .route(
            "/v1/domain/_attr/:attr",
            get(domain_attr_get)
                .put(domain_attr_put)
                .delete(domain_attr_delete),
        )
        .route("/v1/group/:id/_unix/_token", get(group_id_unix_token_get))
        .route("/v1/group/:id/_unix", post(group_id_unix_post))
        .route("/v1/group", get(group_get).post(group_post))
        .route("/v1/group/:id", get(group_id_get).delete(group_id_delete))
        .route(
            "/v1/group/:id/_attr/:attr",
            delete(group_id_attr_delete)
                .get(group_id_attr_get)
                .put(group_id_attr_put)
                .post(group_id_attr_post),
        )
        .with_state(state.clone())
        .route("/v1/system", get(system_get))
        .route(
            "/v1/system/_attr/:attr",
            get(system_attr_get)
                .post(system_attr_post)
                .put(system_attr_put)
                .delete(system_attr_delete),
        )
        .route("/v1/recycle_bin", get(recycle_bin_get))
        .route("/v1/recycle_bin/:id", get(recycle_bin_id_get))
        .route(
            "/v1/recycle_bin/:id/_revive",
            post(recycle_bin_revive_id_post),
        )
        // .route("/v1/access_profile", get(|| async { "TODO" }))
        // .route("/v1/access_profile/:id", get(|| async { "TODO" }))
        // .route(
        //     "/v1/access_profile/:id/_attr/:attr",
        //     get(|| async { "TODO" }),
        // )
        .route("/v1/auth", post(auth))
        .route("/v1/auth/valid", get(auth_valid))
        .route("/v1/logout", get(logout))
        .route("/v1/reauth", post(reauth))
        .with_state(state.clone())
        .layer(from_fn(dont_cache_me))
        .merge(cacheable_routes(state))
        .route("/v1/debug/ipinfo", get(debug_ipinfo))
}
