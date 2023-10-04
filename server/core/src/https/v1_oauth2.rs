use super::middleware::KOpId;
use super::oauth2::oauth2_id;
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::ServerState;
use crate::https::to_axum_response;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use hyper::Body;
use kanidm_proto::internal::{ImageType, ImageValue};
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::prelude::*;
use kanidmd_lib::valueset::image::ImageValueThings;
use sketching::admin_error;

#[utoipa::path(
    get,
    path = "/v1/oauth2",
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
    tag = "api/v1/oauth2",
)]
/// Lists all the OAuth2 Resource Servers
pub(crate) async fn oauth2_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    json_rest_event_get(state, None, filter, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/basic",
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
    tag = "api/v1/oauth2",
)]
// TODO: what does this actually do? :D
pub(crate) async fn oauth2_basic_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerBasic.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_public",
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
    tag = "api/v1/oauth2",
)]
// TODO: what does this actually do? :D
pub(crate) async fn oauth2_public_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerPublic.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

#[utoipa::path(
    get,
    path = "/v1/oauth2/{rs_name}",
    params(
        ("rs_name" = String, description="The ID of the OAuth2 resource server you wish to query")
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Get the details of a given OAuth2 Resource Server.
pub(crate) async fn oauth2_id_get(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

#[utoipa::path(
    get,
    path = "/v1/oauth2/{rs_name}/_basic_secret",
    params(
        ("rs_name" = String, description="The ID of the OAuth2 resource server you wish to query")
    ),
    responses(
        (status = 200, description = "Ok"),
        // (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Get the basic secret for a given OAuth2 Resource Server. This is used for authentication.
#[instrument(level = "info", skip(state))]
pub(crate) async fn oauth2_id_get_basic_secret(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_r_ref
        .handle_oauth2_basic_secret_read(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}",
    params(
        // TODO: params
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, check the field format/values."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Modify an OAuth2 Resource Server
pub(crate) async fn oauth2_id_patch(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);

    let res = state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    params(
        ( "rs_name" = String, description="The ID of the OAuth2 resource server you wish to query"),
        ( "group" = String, description=""),
        // TODO: scopes params
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, check the field format/values."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Modify the scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_scopemap_update(kopid.uat, group, scopes, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    params(
        ( "rs_name" = String, description="The ID of the OAuth2 resource server you wish to query"),
        ( "group" = String, description="Group to remove"),
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, check the field format/values."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
// Delete a scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_scopemap_delete(kopid.uat, group, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    params(
        ( "rs_name" = String, description="The ID of the OAuth2 resource server you wish to modify"),
        ( "group" = String, description="Group to modify"),
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, check the field format/values."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Create a supplemental scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_sup_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_update(kopid.uat, group, scopes, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    params(
        ( "rs_name" = String, description="The ID of the OAuth2 resource server you wish to modify"),
        ( "group" = String, description="Group to modify"),
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, check the field format/values."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
// Delete a supplemental scope map configuration.
pub(crate) async fn oauth2_id_sup_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((rs_name, group)): Path<(String, String)>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_delete(kopid.uat, group, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}",
    params(
        ( "rs_name" = String, description="The ID of the OAuth2 resource server you wish to modify"),
    ),
    responses(
        (status = 200),
        (status = 403),
        (status = 404),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
/// Delete an OAuth2 Resource Server
pub(crate) async fn oauth2_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
) -> Response<Body> {
    let filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_internaldelete(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_image",
    params(
        ("rs_name" = String,Path, description="The ID of the OAuth2 resource server to get the image for")
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
// API endpoint for deleting the image associated with an OAuth2 Resource Server.
pub(crate) async fn oauth2_id_image_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
) -> Response<Body> {
    let rs_filter = oauth2_id(&rs_name);
    let res = state
        .qe_w_ref
        .handle_oauth2_rs_image_delete(kopid.uat, rs_filter)
        .await;

    to_axum_response(res)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_image",
    params(
        ("rs_name" = String,Path, description="The ID of the OAuth2 resource server to get the image for")
        // TODO identify this takes a multipart form for file uploads?
    ),
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Invalid request, things like invalid image size/format etc."),
        (status = 403, description = "Authorzation refused"),
    ),
    security(
        ("token_jwt" = [])
    ),
    tag = "api/v1/oauth2",
)]
// API endpoint for creating/replacing the image associated with an OAuth2 Resource Server.
pub(crate) async fn oauth2_id_image_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(rs_name): Path<String>,
    mut multipart: axum::extract::Multipart,
) -> Response<Body> {
    // because we might not get an image
    let mut image: Option<ImageValue> = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let filename = field.file_name().map(|f| f.to_string()).clone();
        if let Some(filename) = filename {
            let content_type = field.content_type().map(|f| f.to_string()).clone();

            let content_type = match content_type {
                Some(val) => {
                    if VALID_IMAGE_UPLOAD_CONTENT_TYPES.contains(&val.as_str()) {
                        val
                    } else {
                        debug!("Invalid content type: {}", val);
                        let res =
                            to_axum_response::<String>(Err(OperationError::InvalidRequestState));
                        return res;
                    }
                }
                None => {
                    debug!("No content type header provided");
                    let res = to_axum_response::<String>(Err(OperationError::InvalidRequestState));
                    return res;
                }
            };
            let data = match field.bytes().await {
                Ok(val) => val,
                Err(_e) => {
                    let res = to_axum_response::<String>(Err(OperationError::InvalidRequestState));
                    return res;
                }
            };

            let filetype = match ImageType::try_from_content_type(&content_type) {
                Ok(val) => val,
                Err(_err) => {
                    let res = to_axum_response::<String>(Err(OperationError::InvalidRequestState));
                    return res;
                }
            };

            image = Some(ImageValue {
                filetype,
                filename: filename.to_string(),
                contents: data.to_vec(),
            });
        };
    }

    let res = match image {
        Some(image) => {
            let image_validation_result = image.validate_image();
            if let Err(err) = image_validation_result {
                admin_error!("Invalid image uploaded: {:?}", err);
                return to_axum_response::<String>(Err(OperationError::InvalidRequestState));
            }

            let rs_name = oauth2_id(&rs_name);
            state
                .qe_w_ref
                .handle_oauth2_rs_image_update(kopid.uat, rs_name, image)
                .await
        }
        None => Err(OperationError::InvalidAttribute(
            "No image included, did you mean to use the DELETE method?".to_string(),
        )),
    };
    to_axum_response(res)
}
