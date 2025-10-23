//! The V1 API things!

use super::errors::WebError;
use super::middleware::caching::{cache_me_short, dont_cache_me};
use super::middleware::KOpId;
use super::ServerState;
use crate::https::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use crate::https::extractors::{ClientConnInfo, VerifiedClientInformation};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use compact_jwt::{Jwk, Jws, JwsSigner};
use kanidm_proto::constants::uri::V1_AUTH_VALID;
use kanidm_proto::internal::{
    ApiToken, AppLink, CUIntentToken, CURequest, CUSessionToken, CUStatus, CreateRequest,
    CredentialStatus, DeleteRequest, IdentifyUserRequest, IdentifyUserResponse, ModifyRequest,
    RadiusAuthToken, SearchRequest, SearchResponse, UserAuthToken, COOKIE_AUTH_SESSION_ID,
    COOKIE_BEARER_TOKEN,
};
use kanidm_proto::v1::{
    AccountUnixExtend, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, Entry as ProtoEntry, GroupUnixExtend, SingleStringRequest,
    UatStatus, UnixGroupToken, UnixUserToken, WhoamiResponse,
};
use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::value::PartialValue;
use std::net::IpAddr;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/v1/raw/create",
    responses(
        DefaultApiResponse,
    ),
    request_body=CreateRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
    operation_id="raw_create"
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_create(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(msg): Json<CreateRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_create(client_auth_info, msg, kopid.eventid)
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
    operation_id="raw_modify"
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_modify(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(msg): Json<ModifyRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_modify(client_auth_info, msg, kopid.eventid)
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
    operation_id = "raw_delete"
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(msg): Json<DeleteRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_delete(client_auth_info, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/raw/search",
    responses(
        (status = 200, body=SearchResponse, content_type="application/json"),
        ApiResponseWithout200,
    ),
    request_body=SearchRequest,
    security(("token_jwt" = [])),
    tag = "v1/raw",
    operation_id="raw_search"
)]
/// Raw request to the system, be warned this can be dangerous!
pub async fn raw_search(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(msg): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, WebError> {
    state
        .qe_r_ref
        .handle_search(client_auth_info, msg, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self",
    responses(
        (status = 200, body=WhoamiResponse, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/self",
    operation_id="whoami"
)]
// Whoami?
pub async fn whoami(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<WhoamiResponse>, WebError> {
    // New event, feed current auth data from the token to it.
    state
        .qe_r_ref
        .handle_whoami(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self/_uat",
    responses(
        (status = 200, description = "Ok", body=UserAuthToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/self",
    operation_id="whoami_uat"
)]
pub async fn whoami_uat(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<UserAuthToken>, WebError> {
    state
        .qe_r_ref
        .handle_whoami_uat(&client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/logout",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/auth",
    operation_id="logout"
)]
pub async fn logout(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> Result<Response, WebError> {
    state
        .qe_w_ref
        .handle_logout(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map(|json| (jar, json).into_response())
        .map_err(WebError::from)
}

// // =============== REST generics ========================

#[instrument(level = "trace", skip(state, kopid))]
pub async fn json_rest_event_get(
    state: ServerState,
    attrs: Option<Vec<String>>,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, attrs, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

/// Common event handler to search and retrieve entries with a name or id
/// and return the result as json proto entries
pub async fn json_rest_event_get_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

/// Common event handler to search and retrieve entries that reference another
/// entry by the value of name or id and return the result as json proto entries
pub async fn json_rest_event_get_refers_id(
    state: ServerState,
    refers_id: String,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    state
        .qe_r_ref
        .handle_search_refers(client_auth_info, filter, refers_id, attrs, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_delete_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internaldelete(client_auth_info, filter, kopid.eventid)
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
    client_auth_info: ClientAuthInfo,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));
    let attrs = Some(vec![attr.clone()]);
    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, attrs, kopid.eventid)
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
    client_auth_info: ClientAuthInfo,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid, client_auth_info).await
}

pub async fn json_rest_event_post(
    state: ServerState,
    classes: Vec<String>,
    obj: ProtoEntry,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    debug_assert!(!classes.is_empty());

    let mut obj = obj;
    obj.attrs.insert(Attribute::Class.to_string(), classes);
    let msg = CreateRequest {
        entries: vec![obj.to_owned()],
    };

    state
        .qe_w_ref
        .handle_create(client_auth_info, msg, kopid.eventid)
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
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_appendattribute(client_auth_info, id, attr, values, filter, kopid.eventid)
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
pub async fn json_rest_event_put_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_setattribute(client_auth_info, id, attr, values, filter, kopid.eventid)
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
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_appendattribute(client_auth_info, id, attr, values, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

pub async fn json_rest_event_delete_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    json_rest_event_delete_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

pub async fn json_rest_event_delete_attr(
    state: ServerState,
    uuid_or_name: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<()>, WebError> {
    let values = values.unwrap_or_default();

    if values.is_empty() {
        state
            .qe_w_ref
            .handle_purgeattribute(client_auth_info, uuid_or_name, attr, filter, kopid.eventid)
            .await
    } else {
        state
            .qe_w_ref
            .handle_removeattributevalues(
                client_auth_info,
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
        (status=200, content_type="application/json", body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
    operation_id = "schema_get",
)]
// Whoami?
pub async fn schema_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq(Attribute::Class, EntryClass::AttributeType.into()),
        f_eq(Attribute::Class, EntryClass::ClassType.into())
    ]));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/attributetype",
    responses(
        (status=200, content_type="application/json", body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
    operation_id = "schema_attributetype_get",
)]
pub async fn schema_attributetype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::AttributeType.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/attributetype/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
    operation_id = "schema_attributetype_get_id",
)]
pub async fn schema_attributetype_get_id(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        .handle_internalsearch(client_auth_info, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/schema/classtype",
    responses(
        (status=200, body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
    operation_id="schema_classtype_get",
)]
pub async fn schema_classtype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ClassType.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/schema/classtype/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/schema",
    operation_id="schema_classtype_get_id",
)]
pub async fn schema_classtype_get_id(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::ClassType.into()),
        f_eq(Attribute::ClassName, PartialValue::new_iutf8(id.as_str()))
    ]));
    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person",
    responses(
        (status=200, body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_get",
)]
pub async fn person_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/person",
    responses(
        DefaultApiResponse,
    ),
    request_body=ProtoEntry,
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_post",
)]
/// Expects the following fields in the attrs field of the req: [name, displayname]
pub async fn person_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![
        EntryClass::Person.into(),
        EntryClass::Account.into(),
        EntryClass::Object.into(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/person/_search/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_search_id",
)]
pub async fn person_search_id(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::Person.into()),
        f_sub(Attribute::Name, PartialValue::new_iname(&id))
    ]));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_id_get",
)]
pub async fn person_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_get_id(state, id, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_id_delete",
)]
pub async fn person_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    json_rest_event_delete_id(state, id, filter, kopid, client_auth_info).await
}

// == person -> certificates

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_certificate",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/certificate",
    operation_id = "person_get_id_certificate",
)]
pub async fn person_get_id_certificate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ClientCertificate.into()));
    json_rest_event_get_refers_id(state, id, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_certificate",
    responses(
        DefaultApiResponse,
    ),
    request_body=ProtoEntry,
    security(("token_jwt" = [])),
    tag = "v1/person/certificate",
    operation_id = "person_post_id_certificate",
)]
/// Expects the following fields in the attrs field of the req: [certificate]
///
/// The person's id will be added implicitly as a reference.
pub async fn person_post_id_certificate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(mut obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![
        EntryClass::ClientCertificate.into(),
        EntryClass::Object.into(),
    ];
    obj.attrs.insert(Attribute::Refers.to_string(), vec![id]);

    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

// // == account ==

#[utoipa::path(
    get,
    path = "/v1/service_account",
    responses(
        (status=200, body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_get",
)]
pub async fn service_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/service_account",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_post",
)]
pub async fn service_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![
        EntryClass::ServiceAccount.into(),
        EntryClass::Account.into(),
        EntryClass::Object.into(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    patch,
    path = "/v1/service_account/{id}",
    responses(
        DefaultApiResponse,
    ),
    request_body=ProtoEntry,
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_patch",
)]
pub async fn service_account_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    // Update a value / attrs
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_get",
)]
pub async fn service_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_get_id(state, id, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::ServiceAccount.into()));
    json_rest_event_delete_id(state, id, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_credential/_generate",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_credential_generate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<String>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_credential_generate(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_into_person",
    responses(
        DefaultApiResponse,
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
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_into_person(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_api_token",
    responses(
        (status=200, body=Vec<ApiToken>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_api_token_get",
)]
pub async fn service_account_api_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Vec<ApiToken>>, WebError> {
    state
        .qe_r_ref
        .handle_service_account_api_token_get(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_api_token",
    request_body = ApiTokenGenerate,
    responses(
        (status=200, body=String, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_api_token_post",
)]
pub async fn service_account_api_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<ApiTokenGenerate>,
) -> Result<Json<String>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_api_token_generate(
            client_auth_info,
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
    path = "/v1/service_account/{id}/_api_token/{token_id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_api_token_delete",
)]
pub async fn service_account_api_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_service_account_api_token_destroy(client_auth_info, id, token_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        (status=200, body=Option<Vec<String>>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
    operation_id = "person_id_get_attr",
)]
pub async fn person_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_attr/{attr}",
    responses(
        (status=200, body=Option<Vec<String>>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_get_attr",
)]
pub async fn service_account_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_attr/{attr}",
    request_body= Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
    operation_id = "person_id_post_attr",
)]
pub async fn person_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_post_attr",
)]
pub async fn service_account_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
    operation_id = "person_id_delete_attr",
)]
pub async fn person_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/service_account/{id}/_attr/{attr}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_delete_attr",
)]
pub async fn service_account_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    put,
    path = "/v1/person/{id}/_attr/{attr}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/attr",
    operation_id = "person_id_put_attr",
)]
pub async fn person_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    put,
    path = "/v1/service_account/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_put_attr",
)]
pub async fn service_account_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    patch,
    path = "/v1/person/{id}",
    responses(
        DefaultApiResponse,
    ),
    request_body=ProtoEntry,
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_id_patch",
)]
pub async fn person_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    // Update a value / attrs
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_update",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
pub async fn person_id_credential_update_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<(CUSessionToken, CUStatus)>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdate(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_update_intent/{ttl}",
    params(
        ("ttl" = u64, description="The new TTL for the credential?")
    ),
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
// TODO: this shouldn't be a get, we're making changes!
#[instrument(level = "trace", skip(state, kopid))]
pub async fn person_id_credential_update_intent_ttl_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, ttl)): Path<(String, u64)>,
) -> Result<Json<CUIntentToken>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            client_auth_info,
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
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
#[instrument(level = "trace", skip(state, kopid))]
pub async fn person_id_credential_update_intent_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<CUIntentToken>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialupdateintent(client_auth_info, id, None, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_user_auth_token",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_id_user_auth_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<UatStatus>>, WebError> {
    state
        .qe_r_ref
        .handle_account_user_auth_token_get(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_user_auth_token/{token_id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
)]
pub async fn account_user_auth_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_account_user_auth_token_destroy(client_auth_info, id, token_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/credential/_exchange_intent",
    params(
    ),
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)] // TODO: post body
pub async fn credential_update_exchange_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(intent_token): Json<String>,
) -> Result<Json<(CUSessionToken, CUStatus)>, WebError> {
    state
        .qe_w_ref
        .handle_idmcredentialexchangeintent(intent_token, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/credential/_status",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
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

#[utoipa::path(
    post,
    path = "/v1/credential/_update",
    responses(
        (status=200, body=CUStatus), // TODO: define response
        ApiResponseWithout200,
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
            let errmsg = format!("Failed to deserialize CURequest: {err:?}");
            error!("{}", errmsg);
            return Err(WebError::InternalServerError(errmsg));
        }
    };

    let session_token = match serde_json::from_value(cubody[1].clone()) {
        Ok(val) => val,
        Err(err) => {
            let errmsg = format!("Failed to deserialize session token: {err:?}");
            error!("{}", errmsg);
            return Err(WebError::InternalServerError(errmsg));
        }
    };
    trace!("session_token: {:?}", session_token);
    debug!("scr: {:?}", scr);

    state
        .qe_r_ref
        .handle_idmcredentialupdate(session_token, scr, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/credential/_commit",
    responses(
        DefaultApiResponse,
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
    request_body=CUSessionToken,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/credential",
)]
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
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
pub async fn service_account_id_credential_status_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<CredentialStatus>, WebError> {
    match state
        .qe_r_ref
        .handle_idmcredentialstatus(client_auth_info, id.clone(), kopid.eventid)
        .await
        .map(Json::from)
    {
        Ok(val) => Ok(val),
        Err(err) => {
            if let OperationError::NoMatchingAttributes = err {
                debug!("No credentials set on account {}, returning empty list", id);
                Ok(Json(CredentialStatus { creds: Vec::new() }))
            } else {
                Err(WebError::from(err))
            }
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_credential/_status",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/credential",
)]
pub async fn person_get_id_credential_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<CredentialStatus>, WebError> {
    match state
        .qe_r_ref
        .handle_idmcredentialstatus(client_auth_info, id.clone(), kopid.eventid)
        .await
        .map(Json::from)
    {
        Ok(val) => Ok(val),
        Err(err) => {
            if let OperationError::NoMatchingAttributes = err {
                debug!("No credentials set on person {}, returning empty list", id);
                Ok(Json(CredentialStatus { creds: Vec::new() }))
            } else {
                Err(WebError::from(err))
            }
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_ssh_pubkeys",
    responses(
        (status=200, body=Vec<String>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
    operation_id = "person_id_ssh_pubkeys_get",
)]
pub async fn person_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_ssh_pubkeys",
    responses(
        (status=200, body=Vec<String>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_ssh_pubkeys_get",
)]
#[deprecated]
pub async fn account_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_ssh_pubkeys",
    responses(
        (status=200, body=Vec<String>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_ssh_pubkeys_get",
)]
pub async fn service_account_id_ssh_pubkeys_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeyread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_ssh_pubkeys",
    responses(
        DefaultApiResponse,
        (status=422, description="Unprocessable Entity", body=String, content_type="text/plain"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
    operation_id = "person_id_ssh_pubkeys_post",
)]
pub async fn person_id_ssh_pubkeys_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    // Add a msg here
    state
        .qe_w_ref
        .handle_sshkeycreate(client_auth_info, id, &tag, &key, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_ssh_pubkeys",
    request_body = (String, String),
    responses(
        DefaultApiResponse,
        (status=422, description="Unprocessable Entity", body=String, content_type="text/plain"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_ssh_pubkeys_post",
)]
pub async fn service_account_id_ssh_pubkeys_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    // Add a msg here
    state
        .qe_w_ref
        .handle_sshkeycreate(client_auth_info, id, &tag, &key, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_ssh_pubkeys/{tag}",
    responses(
        (status=200, body=String, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
    operation_id = "person_id_ssh_pubkeys_tag_get",
)]
pub async fn person_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(client_auth_info, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}
#[utoipa::path(
    get,
    path = "/v1/account/{id}/_ssh_pubkeys/{tag}",
    responses(
        (status=200, body=String, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_ssh_pubkeys_tag_get",
)]
pub async fn account_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(client_auth_info, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/service_account/{id}/_ssh_pubkeys/{tag}",
    responses(
        (status=200, body=String, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_ssh_pubkeys_tag_get",
)]
pub async fn service_account_id_ssh_pubkeys_tag_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<Option<String>>, WebError> {
    state
        .qe_r_ref
        .handle_internalsshkeytagread(client_auth_info, id, tag, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_ssh_pubkeys/{tag}",
    params(
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/ssh_pubkeys",
    operation_id = "person_id_ssh_pubkeys_tag_delete",
)]
pub async fn person_id_ssh_pubkeys_tag_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let values = vec![tag];
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info,
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
        ("tag" = String, description="The tag of the SSH key"),
    ),
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
    operation_id = "service_account_id_ssh_pubkeys_tag_delete",
)]
pub async fn service_account_id_ssh_pubkeys_tag_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, tag)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let values = vec![tag];
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info,
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
    get,
    path = "/v1/person/{id}/_radius",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
    operation_id = "person_id_radius_get"
)]
/// Get and return a single str
pub async fn person_id_radius_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Option<String>>, WebError> {
    // TODO: string
    state
        .qe_r_ref
        .handle_internalradiusread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_radius",
    responses(
        (status=200), // TODO: define response
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
    operation_id = "person_id_radius_post"
)]
pub async fn person_id_radius_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<String>, WebError> {
    // Need to to send the regen msg
    state
        .qe_w_ref
        .handle_regenerateradius(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_radius",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
    operation_id = "person_id_radius_delete"
)]
pub async fn person_id_radius_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/person/{id}/_radius/_token",
    responses(
        (status=200, body=RadiusAuthToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/radius",
    operation_id = "person_id_radius_token_get"
)]
pub async fn person_id_radius_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/account/{id}/_radius/_token",
    responses(
        (status=200, body=RadiusAuthToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_radius_token_get"
)]
pub async fn account_id_radius_token_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/account/{id}/_radius/_token",
    responses(
        (status=200, body=RadiusAuthToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_radius_token_post"
)]
pub async fn account_id_radius_token_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<RadiusAuthToken>, WebError> {
    person_id_radius_handler(state, id, kopid, client_auth_info).await
}

async fn person_id_radius_handler(
    state: ServerState,
    id: String,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<Json<RadiusAuthToken>, WebError> {
    state
        .qe_r_ref
        .handle_internalradiustokenread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/person/{id}/_unix",
    request_body=AccountUnixExtend,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
)]
#[instrument(name = "account_post_id_unix", level = "INFO", skip(id, state, kopid))]
pub async fn person_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<AccountUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixextend(client_auth_info, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/service_account/{id}/_unix",
    request_body = AccountUnixExtend,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/service_account",
)]
#[instrument(, level = "INFO", skip(id, state, kopid))]
pub async fn service_account_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<AccountUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixextend(client_auth_info, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,post,
    path = "/v1/account/{id}/_unix/_token",
    responses(
        (status=200, body=UnixUserToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_unix_token"
)]
#[instrument(level = "INFO", skip_all)]
pub async fn account_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<UnixUserToken>, WebError> {
    // no point asking for an empty id
    if id.is_empty() {
        return Err(OperationError::EmptyRequest.into());
    }

    let res = state
        .qe_r_ref
        .handle_internalunixusertokenread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from);

    // if they're not a posix user we should just hide them
    if let Err(OperationError::MissingClass(class)) = &res {
        if class == ENTRYCLASS_POSIX_ACCOUNT {
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
    responses(
        (status=200, body=Option<UnixUserToken>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/account",
    operation_id = "account_id_unix_auth_post"
)]
pub async fn account_id_unix_auth_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> Result<Json<Option<UnixUserToken>>, WebError> {
    state
        .qe_r_ref
        .handle_idmaccountunixauth(client_auth_info, id, obj.value, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    put,
    path = "/v1/person/{id}/_unix/_credential",
    request_body = SingleStringRequest,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
    operation_id = "person_id_unix_credential_put"
)]
pub async fn person_id_unix_credential_put(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmaccountunixsetcred(client_auth_info, id, obj.value, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/person/{id}/_unix/_credential",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person/unix",
    operation_id = "person_id_unix_credential_delete"
)]
pub async fn person_id_unix_credential_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::PosixAccount.into()));
    state
        .qe_w_ref
        .handle_purgeattribute(
            client_auth_info,
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
        (status=200, body=IdentifyUserResponse, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/person",
    operation_id = "person_identify_user_post"
)]
pub async fn person_identify_user_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(user_request): Json<IdentifyUserRequest>,
) -> Result<Json<IdentifyUserResponse>, WebError> {
    state
        .qe_r_ref
        .handle_user_identity_verification(client_auth_info, kopid.eventid, user_request, id)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/group",
    responses(
        (status=200,body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_get",
)]
/// Returns all groups visible  to the user
pub async fn group_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/group/_search/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_search_id",
)]
pub async fn group_search_id(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::Group.into()),
        f_sub(Attribute::Name, PartialValue::new_iname(&id))
    ]));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/group",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_post",
)]
pub async fn group_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_id_get",
)]
pub async fn group_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get_id(state, id, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    patch,
    path = "/v1/group/{id}",
    responses(
        DefaultApiResponse,
    ),
    request_body=ProtoEntry,
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_id_patch",
)]
pub async fn group_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    // Update a value / attrs
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/group/{id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group",
    operation_id = "group_id_delete",
)]
pub async fn group_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_delete_id(state, id, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}/_attr/{attr}",
    responses(
        (status=200, body=Vec<String>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
    operation_id = "group_id_attr_get",
)]
pub async fn group_id_attr_get(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/group/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
    operation_id = "group_id_attr_post",
)]
pub async fn group_id_attr_post(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/group/{id}/_attr/{attr}",
    request_body=Option<Vec<String>>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
    operation_id = "group_id_attr_delete",
)]
pub async fn group_id_attr_delete(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    values: Option<Json<Vec<String>>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    let values = values.map(|v| v.0);
    json_rest_event_delete_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    put,
    path = "/v1/group/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/attr",
    operation_id = "group_id_attr_put",
)]
pub async fn group_id_attr_put(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/group/{id}/_unix",
    request_body = GroupUnixExtend,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/unix",
    operation_id = "group_id_unix_post",
)]
pub async fn group_id_unix_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<GroupUnixExtend>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_idmgroupunixextend(client_auth_info, id, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/group/{id}/_unix/_token",
    responses(
        (status=200, body=UnixGroupToken, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/group/unix",
    operation_id = "group_id_unix_token_get",
)]
pub async fn group_id_unix_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(id): Path<String>,
) -> Result<Json<UnixGroupToken>, WebError> {
    state
        .qe_r_ref
        .handle_internalunixgrouptokenread(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/domain",
    responses(
        (status=200, body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_get",
)]
pub async fn domain_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO)));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/domain/_attr/{attr}",
    responses(
        (status=200, body=Option<Vec<String>>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_attr_get",
)]
pub async fn domain_attr_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(attr): Path<String>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::DomainInfo.into()));
    json_rest_event_get_attr(
        state,
        STR_UUID_DOMAIN_INFO,
        attr,
        filter,
        kopid,
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    put,
    path = "/v1/domain/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_attr_put",
)]
pub async fn domain_attr_put(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/v1/domain/_attr/{attr}",
    request_body=Option<Vec<String>>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_attr_delete",
)]
pub async fn domain_attr_delete(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    get,
    path = "/v1/system",
    responses(
        (status=200,body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
    operation_id = "system_get",
)]
pub async fn system_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Uuid,
        PartialValue::Uuid(UUID_SYSTEM_CONFIG)
    ));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/system/_attr/{attr}",
    responses(
        (status=200, body=Option<Vec<String>>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
    operation_id = "system_attr_get",
)]
pub async fn system_attr_get(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()));
    json_rest_event_get_attr(
        state,
        STR_UUID_SYSTEM_CONFIG,
        attr,
        filter,
        kopid,
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/system/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
    operation_id = "system_attr_post",
)]
pub async fn system_attr_post(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    delete,
    path = "/v1/system/_attr/{attr}",
    request_body=Option<Vec<String>>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
    operation_id = "system_attr_delete",
)]
pub async fn system_attr_delete(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    put,
    path = "/v1/system/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/system",
    operation_id = "system_attr_put",
)]
pub async fn system_attr_put(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
        client_auth_info,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/v1/recycle_bin",
    responses(
        (status=200,body=Vec<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
    operation_id="recycle_bin_get",
)]
pub async fn recycle_bin_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_pres(Attribute::Class));
    let attrs = None;
    state
        .qe_r_ref
        .handle_internalsearchrecycled(client_auth_info, filter, attrs, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/recycle_bin/{id}",
    responses(
        (status=200, body=Option<ProtoEntry>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
    operation_id = "recycle_bin_id_get",
)]
pub async fn recycle_bin_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    state
        .qe_r_ref
        .handle_internalsearchrecycled(client_auth_info, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/recycle_bin/{id}/_revive",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/recycle_bin",
    operation_id = "recycle_bin_revive_id_post",
)]
pub async fn recycle_bin_revive_id_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_id(id.as_str()));
    state
        .qe_w_ref
        .handle_reviverecycled(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/self/_applinks",
    responses(
        (status=200, body=Vec<AppLink>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/self",
    operation_id = "self_applinks_get",
)]
/// Returns your OAuth2 app links for the Web UI
pub async fn applinks_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<AppLink>>, WebError> {
    state
        .qe_r_ref
        .handle_list_applinks(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/reauth",
    responses(
        (status=200, content_type="application/json"), // TODO: define response
        ApiResponseWithout200,
    ),
    request_body = AuthIssueSession,
    security(("token_jwt" = [])),
    tag = "v1/auth",
    operation_id = "reauth_post",
)] // TODO: post body stuff
pub async fn reauth(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthIssueSession>,
) -> Result<Response, WebError> {
    // This may change in the future ...
    let inter = state
        .qe_r_ref
        .handle_reauth(client_auth_info, obj, kopid.eventid)
        .await;
    debug!("ReAuth result: {:?}", inter);
    auth_session_state_management(&state, jar, inter)
}

#[utoipa::path(
    post,
    path = "/v1/auth",
    responses(
        (status=200, content_type="application/json"), // TODO: define response
        ApiResponseWithout200,
    ),
    request_body = AuthRequest,
    security(("token_jwt" = [])),
    tag = "v1/auth",
    operation_id = "auth_post",
)]
pub async fn auth(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    headers: HeaderMap,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthRequest>,
) -> Result<Response, WebError> {
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    let maybe_sessionid = state.get_current_auth_session_id(&headers, &jar);
    debug!("Session ID: {:?}", maybe_sessionid);

    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, kopid.eventid, client_auth_info)
        .await;
    debug!("Auth result: {:?}", inter);
    auth_session_state_management(&state, jar, inter)
}

// Disable on any level except trace to stop leaking tokens
#[instrument(level = "trace", skip_all)]
fn auth_session_state_management(
    state: &ServerState,
    mut jar: CookieJar,
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
                    debug!("🧩 -> AuthState::Choose");
                    let kref = &state.jws_signer;
                    let jws = Jws::into_json(&sessionid).map_err(|e| {
                        error!(?e);
                        OperationError::InvalidSessionState
                    })?;

                    // Get the header token ready.
                    kref.sign(&jws)
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
                    let jws = Jws::into_json(&sessionid).map_err(|e| {
                        error!(?e);
                        OperationError::InvalidSessionState
                    })?;
                    kref.sign(&jws)
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
                        AuthIssueSession::Token => Ok(ProtoAuthState::Success(token.to_string())),
                        AuthIssueSession::Cookie => {
                            // Update jar
                            let token_str = token.to_string();
                            let mut bearer_cookie =
                                Cookie::new(COOKIE_BEARER_TOKEN, token_str.clone());
                            bearer_cookie.set_secure(state.secure_cookies);
                            bearer_cookie.set_same_site(SameSite::Lax);
                            bearer_cookie.set_http_only(true);
                            // We set a domain here because it allows subdomains
                            // of the idm to share the cookie. If domain was incorrect
                            // then webauthn won't work anyway!
                            bearer_cookie.set_domain(state.domain.clone());
                            bearer_cookie.set_path("/");
                            jar = jar
                                .add(bearer_cookie)
                                .remove(Cookie::from(COOKIE_AUTH_SESSION_ID));
                            Ok(ProtoAuthState::Success(token_str))
                        }
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
        jar = if let Some(token) = auth_session_id_tok.clone() {
            let mut token_cookie = Cookie::new(COOKIE_AUTH_SESSION_ID, token);
            token_cookie.set_secure(state.secure_cookies);
            token_cookie.set_same_site(SameSite::Strict);
            token_cookie.set_http_only(true);
            // Not setting domains limits the cookie to precisely this
            // url that was used.
            // token_cookie.set_domain(state.domain.clone());
            jar.add(token_cookie)
        } else {
            jar
        };

        trace!(?jar);

        let mut res = (jar, Json::from(response)).into_response();

        match auth_session_id_tok {
            Some(tok) => {
                match HeaderValue::from_str(&tok) {
                    Ok(val) => {
                        res.headers_mut().insert(KSESSIONID, val);
                    }
                    Err(err) => {
                        admin_error!(?err, "Failed to add sessionid {} to header", tok);
                    }
                }
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
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/auth",
    operation_id = "auth_valid",
)]
pub async fn auth_valid(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/debug/ipinfo",
    responses(
        (status = 200, description = "Ok", body=String, content_type="application/json"),
    ),
    security(("token_jwt" = [])),
    tag = "v1/debug",
    operation_id = "debug_ipinfo",
)]
pub async fn debug_ipinfo(
    State(_state): State<ServerState>,
    Extension(trusted_client_ip): Extension<ClientConnInfo>,
) -> Result<Json<IpAddr>, ()> {
    Ok(Json::from(trusted_client_ip.client_ip_addr))
}

#[derive(utoipa::ToSchema)]
#[schema [value_type=HashMap<String, String>]]
/// Used entirely to trick Utoipa into generating the correct schema for JWK
#[allow(dead_code)]
struct SchemaJwk(Jwk);

#[utoipa::path(
    get,
    path = "/v1/jwk/{key_id}",
    responses(
        (status=200, body=SchemaJwk, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/jwk",
    operation_id = "public_jwk_key_id_get"
)]
pub async fn public_jwk_key_id_get(
    State(state): State<ServerState>,
    Path(key_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Result<Json<Jwk>, WebError> {
    if key_id.len() > 64 {
        // Fast path to reject long KeyIDs
        return Err(WebError::from(OperationError::NoMatchingEntries));
    }
    state
        .qe_r_ref
        .handle_public_jwk_get(key_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

fn cacheable_routes(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route("/v1/jwk/{key_id}", get(public_jwk_key_id_get))
        .route(
            "/v1/person/{id}/_radius/_token",
            get(person_id_radius_token_get),
        )
        .route("/v1/account/{id}/_unix/_token", get(account_id_unix_token))
        .route(
            "/v1/account/{id}/_radius/_token",
            get(account_id_radius_token_get),
        )
        .layer(from_fn(cache_me_short))
        .with_state(state)
}

#[instrument(skip(state), name = "https_v1_route_setup")]
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
            "/v1/oauth2/{rs_name}",
            get(super::v1_oauth2::oauth2_id_get)
                .patch(super::v1_oauth2::oauth2_id_patch)
                .delete(super::v1_oauth2::oauth2_id_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_attr/{attr}",
            post(super::v1_oauth2::oauth2_id_attr_post)
                .delete(super::v1_oauth2::oauth2_id_attr_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_image",
            post(super::v1_oauth2::oauth2_id_image_post)
                .delete(super::v1_oauth2::oauth2_id_image_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_basic_secret",
            get(super::v1_oauth2::oauth2_id_get_basic_secret),
        )
        .route(
            "/v1/oauth2/{rs_name}/_scopemap/{group}",
            post(super::v1_oauth2::oauth2_id_scopemap_post)
                .delete(super::v1_oauth2::oauth2_id_scopemap_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
            post(super::v1_oauth2::oauth2_id_sup_scopemap_post)
                .delete(super::v1_oauth2::oauth2_id_sup_scopemap_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_claimmap/{claim_name}/{group}",
            post(super::v1_oauth2::oauth2_id_claimmap_post)
                .delete(super::v1_oauth2::oauth2_id_claimmap_delete),
        )
        .route(
            "/v1/oauth2/{rs_name}/_claimmap/{claim_name}",
            post(super::v1_oauth2::oauth2_id_claimmap_join_post),
        )
        .route("/v1/raw/create", post(raw_create))
        .route("/v1/raw/modify", post(raw_modify))
        .route("/v1/raw/delete", post(raw_delete))
        .route("/v1/raw/search", post(raw_search))
        .route("/v1/schema", get(schema_get))
        .route(
            "/v1/schema/attributetype",
            get(schema_attributetype_get), // post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/attributetype/{id}",
            get(schema_attributetype_get_id),
        )
        // .route("/schema/attributetype/{id}", put(|| async { "TODO" }).patch(|| async { "TODO" }))
        .route(
            "/v1/schema/classtype",
            get(schema_classtype_get), // .post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/classtype/{id}",
            get(schema_classtype_get_id), //         .put(|| async { "TODO" })
                                          //         .patch(|| async { "TODO" }),
        )
        .route("/v1/self", get(whoami))
        .route("/v1/self/_uat", get(whoami_uat))
        // .route("/v1/self/_attr/{attr}", get(|| async { "TODO" }))
        // .route("/v1/self/_credential", get(|| async { "TODO" }))
        // .route("/v1/self/_credential/{cid}/_lock", get(|| async { "TODO" }))
        // .route(
        //     "/v1/self/_radius",
        //     get(|| async { "TODO" })
        //         .delete(|| async { "TODO" })
        //         .post(|| async { "TODO" }),
        // )
        // .route("/v1/self/_radius/_config", post(|| async { "TODO" }))
        // .route("/v1/self/_radius/_config/{token}", get(|| async { "TODO" }))
        // .route(
        //     "/v1/self/_radius/_config/{token}/apple",
        //     get(|| async { "TODO" }),
        // )
        // Applinks are the list of apps this account can access.
        .route("/v1/self/_applinks", get(applinks_get))
        // Person routes
        .route("/v1/person", get(person_get).post(person_post))
        .route("/v1/person/_search/{id}", get(person_search_id))
        .route(
            "/v1/person/{id}",
            get(person_id_get)
                .patch(person_id_patch)
                .delete(person_id_delete),
        )
        .route(
            "/v1/person/{id}/_attr/{attr}",
            get(person_id_get_attr)
                .put(person_id_put_attr)
                .post(person_id_post_attr)
                .delete(person_id_delete_attr),
        )
        .route(
            "/v1/person/{id}/_certificate",
            get(person_get_id_certificate).post(person_post_id_certificate),
        )
        .route(
            "/v1/person/{id}/_credential/_status",
            get(person_get_id_credential_status),
        )
        .route(
            "/v1/person/{id}/_credential/_update",
            get(person_id_credential_update_get),
        )
        .route(
            "/v1/person/{id}/_credential/_update_intent/{ttl}",
            get(person_id_credential_update_intent_ttl_get),
        )
        .route(
            "/v1/person/{id}/_credential/_update_intent",
            get(person_id_credential_update_intent_get),
        )
        .route(
            "/v1/person/{id}/_ssh_pubkeys",
            get(person_id_ssh_pubkeys_get).post(person_id_ssh_pubkeys_post),
        )
        .route(
            "/v1/person/{id}/_ssh_pubkeys/{tag}",
            get(person_id_ssh_pubkeys_tag_get).delete(person_id_ssh_pubkeys_tag_delete),
        )
        .route(
            "/v1/person/{id}/_radius",
            get(person_id_radius_get)
                .post(person_id_radius_post)
                .delete(person_id_radius_delete),
        )
        .route("/v1/person/{id}/_unix", post(person_id_unix_post))
        .route(
            "/v1/person/{id}/_unix/_credential",
            put(person_id_unix_credential_put).delete(person_id_unix_credential_delete),
        )
        .route(
            "/v1/person/{id}/_identify_user",
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
            "/v1/service_account/{id}",
            get(service_account_id_get)
                .delete(service_account_id_delete)
                .patch(service_account_id_patch),
        )
        .route(
            "/v1/service_account/{id}/_attr/{attr}",
            get(service_account_id_get_attr)
                .put(service_account_id_put_attr)
                .post(service_account_id_post_attr)
                .delete(service_account_id_delete_attr),
        )
        // .route("/v1/service_account/{id}/_lock", get(|| async { "TODO" }))
        .route(
            "/v1/service_account/{id}/_into_person",
            #[allow(deprecated)]
            post(service_account_into_person),
        )
        .route(
            "/v1/service_account/{id}/_api_token",
            post(service_account_api_token_post).get(service_account_api_token_get),
        )
        .route(
            "/v1/service_account/{id}/_api_token/{token_id}",
            delete(service_account_api_token_delete),
        )
        // .route(
        //     "/v1/service_account/{id}/_credential",
        //     get(|| async { "TODO" }),
        // )
        .route(
            "/v1/service_account/{id}/_credential/_generate",
            get(service_account_credential_generate),
        )
        .route(
            "/v1/service_account/{id}/_credential/_status",
            get(service_account_id_credential_status_get),
        )
        // .route(
        //     "/v1/service_account/{id}/_credential/{cid}/_lock",
        //     get(|| async { "TODO" }),
        // )
        .route(
            "/v1/service_account/{id}/_ssh_pubkeys",
            get(service_account_id_ssh_pubkeys_get).post(service_account_id_ssh_pubkeys_post),
        )
        .route(
            "/v1/service_account/{id}/_ssh_pubkeys/{tag}",
            get(service_account_id_ssh_pubkeys_tag_get)
                .delete(service_account_id_ssh_pubkeys_tag_delete),
        )
        .route(
            "/v1/service_account/{id}/_unix",
            post(service_account_id_unix_post),
        )
        .route(
            "/v1/account/{id}/_unix/_auth",
            post(account_id_unix_auth_post),
        )
        .route("/v1/account/{id}/_unix/_token", post(account_id_unix_token))
        .route(
            "/v1/account/{id}/_radius/_token",
            post(account_id_radius_token_post),
        )
        .route(
            "/v1/account/{id}/_ssh_pubkeys",
            #[allow(deprecated)]
            get(account_id_ssh_pubkeys_get),
        )
        .route(
            "/v1/account/{id}/_ssh_pubkeys/{tag}",
            get(account_id_ssh_pubkeys_tag_get),
        )
        .route(
            "/v1/account/{id}/_user_auth_token",
            get(account_id_user_auth_token_get),
        )
        .route(
            "/v1/account/{id}/_user_auth_token/{token_id}",
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
            "/v1/domain/_image",
            post(super::v1_domain::image_post).delete(super::v1_domain::image_delete),
        )
        .route(
            "/v1/domain/_attr/{attr}",
            get(domain_attr_get)
                .put(domain_attr_put)
                .delete(domain_attr_delete),
        )
        .route("/v1/group/{id}/_unix/_token", get(group_id_unix_token_get))
        .route("/v1/group/{id}/_unix", post(group_id_unix_post))
        .route("/v1/group", get(group_get).post(group_post))
        .route("/v1/group/_search/{id}", get(group_search_id))
        .route(
            "/v1/group/{id}",
            get(group_id_get)
                .patch(group_id_patch)
                .delete(group_id_delete),
        )
        .route(
            "/v1/group/{id}/_attr/{attr}",
            delete(group_id_attr_delete)
                .get(group_id_attr_get)
                .put(group_id_attr_put)
                .post(group_id_attr_post),
        )
        .with_state(state.clone())
        .route("/v1/system", get(system_get))
        .route(
            "/v1/system/_attr/{attr}",
            get(system_attr_get)
                .post(system_attr_post)
                .put(system_attr_put)
                .delete(system_attr_delete),
        )
        .route("/v1/recycle_bin", get(recycle_bin_get))
        .route("/v1/recycle_bin/{id}", get(recycle_bin_id_get))
        .route(
            "/v1/recycle_bin/{id}/_revive",
            post(recycle_bin_revive_id_post),
        )
        // .route("/v1/access_profile", get(|| async { "TODO" }))
        // .route("/v1/access_profile/{id}", get(|| async { "TODO" }))
        // .route(
        //     "/v1/access_profile/{id}/_attr/{attr}",
        //     get(|| async { "TODO" }),
        // )
        .route("/v1/auth", post(auth))
        .route(V1_AUTH_VALID, get(auth_valid))
        .route("/v1/logout", get(logout))
        .route("/v1/reauth", post(reauth))
        .with_state(state.clone())
        .layer(from_fn(dont_cache_me))
        .merge(cacheable_routes(state))
        .route("/v1/debug/ipinfo", get(debug_ipinfo))
}
