use super::middleware::KOpId;
use super::{to_axum_response, ServerState};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_auth::AuthBearer;
use kanidm_proto::scim_v1::ScimSyncRequest;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::prelude::*;

use super::v1::{
    json_rest_event_get, json_rest_event_get_id, json_rest_event_get_id_attr, json_rest_event_post,
    json_rest_event_put_id_attr,
};

pub async fn sync_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn sync_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes: Vec<String> = vec![EntryClass::SyncAccount.into(), EntryClass::Object.into()];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn sync_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn sync_account_id_patch(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let res = state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn sync_account_id_get_finalise(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_sync_account_finalise(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn sync_account_id_get_terminate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_sync_account_terminate(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn sync_account_token_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(label): Json<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_sync_account_token_generate(kopid.uat, id, label, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn sync_account_token_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_sync_account_token_destroy(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    post,
    path = "/scim/v1/Sync",
    params(
        // TODO: params
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "scim",
)]
async fn scim_sync_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthBearer(bearer): AuthBearer,
    Json(changes): Json<ScimSyncRequest>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_scim_sync_apply(Some(bearer), changes, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    get,
    path = "/scim/v1/Sync",
    params(
        // TODO: params
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "scim",
)]
async fn scim_sync_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthBearer(bearer): AuthBearer,
) -> impl IntoResponse {
    // Given the token, what is it's connected sync state?
    trace!(?bearer);
    let res = state
        .qe_r_ref
        .handle_scim_sync_status(Some(bearer), kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn sync_account_id_get_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, attr)): Path<(String, String)>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid).await
}

pub async fn sync_account_id_put_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, attr)): Path<(String, String)>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));
    json_rest_event_put_id_attr(state, id, attr, filter, values, kopid).await
}

#[utoipa::path(
    get,
    path = "/scim/v1/Sink",
    params(
        // TODO: params
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "scim",
)]
/// When you want the kitchen Sink
async fn scim_sink_get() -> impl IntoResponse {
    r#"
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="utf-8"/>
            <meta name="theme-color" content="white" />
            <meta name="viewport" content="width=device-width" />
            <title>Sink!</title>
            <link rel="icon" href="/pkg/img/favicon.png" />
            <link rel="manifest" href="/manifest.webmanifest" />
        </head>
        <body>
            <pre>
                        ___
                      .' _ '.
                     / /` `\ \
                     | |   [__]
                     | |    {{
                     | |    }}
                  _  | |  _ {{
      ___________<_>_| |_<_>}}________
          .=======^=(___)=^={{====.
         / .----------------}}---. \
        / /                 {{    \ \
       / /                  }}     \ \
      (  '========================='  )
       '-----------------------------'
            </pre>
        </body>
    </html>"#
}

pub fn scim_route_setup() -> Router<ServerState> {
    Router::new()
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
        //  Sync     /Sync            GET                    Retrieve the current
        //                                                   sync state associated
        //                                                   with the authenticated
        //                                                   session
        //
        //                            POST                   Send a sync update
        //
        .route("/scim/v1/Sync", post(scim_sync_post).get(scim_sync_get))
        .route("/scim/v1/Sink", get(scim_sink_get))
}
