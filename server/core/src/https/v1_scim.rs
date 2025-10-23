use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::v1::{
    json_rest_event_get, json_rest_event_get_id, json_rest_event_get_id_attr, json_rest_event_post,
    json_rest_event_put_attr,
};
use super::ServerState;
use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{rejection::JsonRejection, DefaultBodyLimit, Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use kanidm_proto::scim_v1::ScimEntry;
use kanidm_proto::scim_v1::{
    client::ScimEntryPostGeneric,
    server::{ScimEntryKanidm, ScimListResponse},
    ScimApplicationPassword, ScimApplicationPasswordCreate, ScimEntryGetQuery, ScimSyncRequest,
    ScimSyncState,
};
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::prelude::*;

const DEFAULT_SCIM_SYNC_BYTES: usize = 1024 * 1024 * 32;

#[utoipa::path(
    get,
    path = "/v1/sync_account",
    responses(
        (status = 200,content_type="application/json", body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_get"
)]
/// Get all? the sync accounts.
pub async fn sync_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/sync_account",
    // request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_post"
)]
pub async fn sync_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes: Vec<String> = vec![EntryClass::SyncAccount.into(), EntryClass::Object.into()];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/sync_account/{id}",
    responses(
        (status = 200,content_type="application/json", body=Option<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
)]
/// Get the details of a sync account
pub async fn sync_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get_id(state, id, filter, None, kopid, client_auth_info).await
}

#[utoipa::path(
    patch,
    path = "/v1/sync_account/{id}",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_id_patch"
)]
/// Modify a sync account in-place
pub async fn sync_account_id_patch(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
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
    path = "/v1/sync_account/{id}/_finalise",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_id_finalise_get"
)]
pub async fn sync_account_id_finalise_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_sync_account_finalise(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/sync_account/{id}/_terminate",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_id_terminate_get"
)]
pub async fn sync_account_id_terminate_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_sync_account_terminate(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/sync_account/{id}/_sync_token",
    responses(
        (status = 200, body=String, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_token_post"
)]
pub async fn sync_account_token_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(label): Json<String>,
) -> Result<Json<String>, WebError> {
    state
        .qe_w_ref
        .handle_sync_account_token_generate(client_auth_info, id, label, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/sync_account/{id}/_sync_token",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_token_delete"
)]
pub async fn sync_account_token_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_sync_account_token_destroy(client_auth_info, id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/sync_account/{id}/_attr/{attr}",
    responses(
        (status = 200, body=Option<Vec<String>>, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_id_attr_get"
)]
pub async fn sync_account_id_attr_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, attr)): Path<(String, String)>,
) -> Result<Json<Option<Vec<String>>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/sync_account/{id}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/sync_account",
    operation_id = "sync_account_id_attr_put"
)]
pub async fn sync_account_id_attr_put(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((id, attr)): Path<(String, String)>,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

/// When you want the kitchen Sink
async fn scim_sink_get() -> Html<&'static str> {
    Html::from(include_str!("scim/sink.html"))
}

#[utoipa::path(
    post,
    path = "/scim/v1/Sync",
    request_body = ScimSyncRequest,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_sync_post"
)]
async fn scim_sync_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    payload: Result<Json<ScimSyncRequest>, JsonRejection>,
) -> Response {
    match payload {
        Ok(Json(changes)) => {
            let res = state
                .qe_w_ref
                .handle_scim_sync_apply(client_auth_info, changes, kopid.eventid)
                .await;

            match res {
                Ok(data) => Json::from(data).into_response(),
                Err(err) => WebError::from(err).into_response(),
            }
        }
        Err(rejection) => {
            error!(?rejection, "Unable to process JSON");
            rejection.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/scim/v1/Sync",
    responses(
        (status = 200, content_type="application/json", body=ScimSyncState), // TODO: response content
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_sync_get"
)]
async fn scim_sync_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<ScimSyncState>, WebError> {
    // Given the token, what is it's connected sync state?
    state
        .qe_r_ref
        .handle_scim_sync_status(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Entry/{id}",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_entry_id_get"
)]
async fn scim_entry_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimEntryKanidm>, WebError> {
    state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info,
            kopid.eventid,
            id,
            EntryClass::Object,
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Person/{id}",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_person_id_get"
)]
async fn scim_person_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimEntryKanidm>, WebError> {
    state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info,
            kopid.eventid,
            id,
            EntryClass::Person,
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/scim/v1/Person/{id}/Application/_create_password",
    request_body = ScimApplicationPasswordCreate,
    responses(
        (status = 200, content_type="application/json", body=ScimApplicationPassword),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_person_id_application_create_password"
)]
async fn scim_person_id_application_create_password(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(request): Json<ScimApplicationPasswordCreate>,
) -> Result<Json<ScimApplicationPassword>, WebError> {
    state
        .qe_w_ref
        .scim_person_application_create_password(client_auth_info, kopid.eventid, id, request)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Person/{id}/Application/{apppwd_uuid}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_person_id_application_delete_password"
)]
async fn scim_person_id_application_delete_password(
    State(state): State<ServerState>,
    Path((id, apppwd_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .scim_person_application_delete_password(client_auth_info, kopid.eventid, id, apppwd_id)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Application",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_application_get"
)]
async fn scim_application_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimListResponse>, WebError> {
    state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info,
            kopid.eventid,
            EntryClass::Application.into(),
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/scim/v1/Application",
    request_body = ScimEntryPostGeneric,
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_application_post"
)]
async fn scim_application_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(entry_post): Json<ScimEntryPostGeneric>,
) -> Result<Json<ScimEntryKanidm>, WebError> {
    state
        .qe_w_ref
        .scim_entry_create(
            client_auth_info,
            kopid.eventid,
            &[
                EntryClass::Account,
                EntryClass::ServiceAccount,
                EntryClass::Application,
            ],
            entry_post,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/scim/v1/Application/{id}",
    responses(
        (status = 200, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_application_id_get"
)]
async fn scim_application_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<ScimEntryKanidm>, WebError> {
    state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info,
            kopid.eventid,
            id,
            EntryClass::Application,
            ScimEntryGetQuery::default(),
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/scim/v1/Application/{id}",
    responses(
        (status = 200, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_application_id_delete"
)]
async fn scim_application_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .scim_entry_id_delete(client_auth_info, kopid.eventid, id, EntryClass::Application)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Class",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_schema_class_get"
)]
async fn scim_schema_class_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimListResponse>, WebError> {
    state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info,
            kopid.eventid,
            EntryClass::ClassType.into(),
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Attribute",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_schema_attribute_get"
)]
async fn scim_schema_attribute_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimListResponse>, WebError> {
    state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info,
            kopid.eventid,
            EntryClass::AttributeType.into(),
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Message",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_message_get"
)]
async fn scim_message_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimListResponse>, WebError> {
    state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info,
            kopid.eventid,
            EntryClass::OutboundMessage.into(),
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Message/{id}",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_message_id_get"
)]
async fn scim_message_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(scim_entry_get_query): Query<ScimEntryGetQuery>,
) -> Result<Json<ScimEntryKanidm>, WebError> {
    state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info,
            kopid.eventid,
            id,
            EntryClass::OutboundMessage,
            scim_entry_get_query,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Message/_ready",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_message_ready_get"
)]
async fn scim_message_ready_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<ScimListResponse>, WebError> {
    //
    state
        .qe_r_ref
        .scim_message_ready_search(client_auth_info, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/scim/v1/Message/{id}/_sent",
    responses(
        (status = 200, content_type="application/json"),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_message_id_sent_post"
)]
async fn scim_message_id_sent_post(
    State(state): State<ServerState>,
    Path(message_id): Path<Uuid>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .scim_message_id_sent(client_auth_info, kopid.eventid, message_id)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Person/{id}/_messages/_send_test",
    responses(
        (status = 200, content_type="application/json", body=ScimEntry),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "scim",
    operation_id = "scim_person_id_message_send_test_get"
)]
async fn scim_person_id_message_send_test_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .scim_person_message_send_test(client_auth_info, kopid.eventid, id)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[instrument(level = "debug", skip_all, name = "https_v1_scim_route_setup")]
pub fn route_setup() -> Router<ServerState> {
    Router::new()
        .route(
            "/v1/sync_account",
            get(sync_account_get).post(sync_account_post),
        )
        .route(
            "/v1/sync_account/{id}",
            get(sync_account_id_get).patch(sync_account_id_patch),
        )
        .route(
            "/v1/sync_account/{id}/_attr/{attr}",
            get(sync_account_id_attr_get).put(sync_account_id_attr_put),
        )
        .route(
            "/v1/sync_account/{id}/_finalise",
            get(sync_account_id_finalise_get),
        )
        .route(
            "/v1/sync_account/{id}/_terminate",
            get(sync_account_id_terminate_get),
        )
        .route(
            "/v1/sync_account/{id}/_sync_token",
            post(sync_account_token_post).delete(sync_account_token_delete),
        )
        // https://datatracker.ietf.org/doc/html/rfc7644#section-3.2
        //
        //  HTTP   SCIM Usage
        //  Method
        //  ------ --------------------------------------------------------------
        //  GET    Retrieves one or more complete or partial resources.
        //
        //  POST   Depending on the endpoint, creates new resources, creates a
        //         search request, or MAY be used to bulk-modify resources.
        //
        //  PUT    Modifies a resource by replacing existing attributes with a
        //         specified set of replacement attributes (replace).  PUT
        //         MUST NOT be used to create new resources.
        //
        //  PATCH  Modifies a resource with a set of client-specified changes
        //         (partial update).
        //
        //  DELETE Deletes a resource.
        //
        //  Resource Endpoint         Operations             Description
        //  -------- ---------------- ---------------------- --------------------
        //  User     /Users           GET (Section 3.4.1),   Retrieve, add,
        //                            POST (Section 3.3),    modify Users.
        //                            PUT (Section 3.5.1),
        //                            PATCH (Section 3.5.2),
        //                            DELETE (Section 3.6)
        //
        //  Group    /Groups          GET (Section 3.4.1),   Retrieve, add,
        //                            POST (Section 3.3),    modify Groups.
        //                            PUT (Section 3.5.1),
        //                            PATCH (Section 3.5.2),
        //                            DELETE (Section 3.6)
        //
        //  Self     /Me              GET, POST, PUT, PATCH, Alias for operations
        //                            DELETE (Section 3.11)  against a resource
        //                                                   mapped to an
        //                                                   authenticated
        //                                                   subject (e.g.,
        //                                                   User).
        //
        //  Service  /ServiceProvider GET (Section 4)        Retrieve service
        //  provider Config                                  provider's
        //  config.                                          configuration.
        //
        //  Resource /ResourceTypes   GET (Section 4)        Retrieve supported
        //  type                                             resource types.
        //
        //  Schema   /Schemas         GET (Section 4)        Retrieve one or more
        //                                                   supported schemas.
        //
        //  Bulk     /Bulk            POST (Section 3.7)     Bulk updates to one
        //                                                   or more resources.
        //
        //  Search   [prefix]/.search POST (Section 3.4.3)   Search from system
        //                                                   root or within a
        //                                                   resource endpoint
        //                                                   for one or more
        //                                                   resource types using
        //                                                   POST.
        //  -- Kanidm Resources
        //
        //  Entry    /Entry/{id}      GET                    Retrieve a generic entry
        //                                                   of any kind from the database.
        //                                                   {id} is any unique id.
        .route("/scim/v1/Entry/{id}", get(scim_entry_id_get))
        //  Person   /Person/{id}     GET                    Retrieve a a person from the
        //                                                   database.
        //                                                   {id} is any unique id.
        .route("/scim/v1/Person/{id}", get(scim_person_id_get))
        .route(
            "/scim/v1/Person/{id}/Application/_create_password",
            post(scim_person_id_application_create_password),
        )
        .route(
            "/scim/v1/Person/{id}/Application/{apppwd_id}",
            delete(scim_person_id_application_delete_password),
        )
        //  Person   /Person/{id}/_messages/_send_test
        .route(
            "/scim/v1/Person/{id}/_message/_send_test",
            get(scim_person_id_message_send_test_get),
        )
        //
        //  Sync     /Sync            GET                    Retrieve the current
        //                                                   sync state associated
        //                                                   with the authenticated
        //                                                   session
        //
        //                            POST                   Send a sync update
        //
        //
        //  Application   /Application     Post              Create a new application
        //
        .route(
            "/scim/v1/Application",
            get(scim_application_get).post(scim_application_post),
        )
        //  Application   /Application/{id}     Delete      Delete the application identified by id
        //
        .route(
            "/scim/v1/Application/{id}",
            get(scim_application_id_get).delete(scim_application_id_delete),
        )
        //  Class      /Class          GET                  List or query Schema Classes
        //
        .route("/scim/v1/Class", get(scim_schema_class_get))
        //  Attribute /Attribute          GET               List or query Schema Attributes
        //
        .route("/scim/v1/Attribute", get(scim_schema_attribute_get))
        //  Message    /Message          GET               List or query queued Messages
        //                               POST              Create a new message for sending.
        .route("/scim/v1/Message", get(scim_message_get))
        //  Message    /Message/_ready   GET               List Messages that are ready to be sent
        .route("/scim/v1/Message/_ready", get(scim_message_ready_get))
        //  Message    /Message/{id}    GET                Fetch message by id
        .route("/scim/v1/Message/{id}", get(scim_message_id_get))
        //  Message    /Message/{id}/_sent     POST         Mark this message as having been processed and sent
        .route(
            "/scim/v1/Message/{id}/_sent",
            post(scim_message_id_sent_post),
        )
        // Synchronisation routes.
        .route(
            "/scim/v1/Sync",
            post(scim_sync_post)
                .layer(DefaultBodyLimit::max(DEFAULT_SCIM_SYNC_BYTES))
                .get(scim_sync_get),
        )
        .route("/scim/v1/Sink", get(scim_sink_get)) // skip_route_check
}
