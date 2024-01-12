use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::oauth2::oauth2_id;
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::ServerState;

use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use kanidm_proto::internal::{ImageType, ImageValue, Oauth2ClaimMapJoin};
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::prelude::*;
use kanidmd_lib::valueset::image::ImageValueThings;
use sketching::admin_error;

#[utoipa::path(
    get,
    path = "/v1/oauth2",
    responses(
        (status = 200,content_type="application/json", body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Lists all the OAuth2 Resource Servers
pub(crate) async fn oauth2_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/basic",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// TODO: what does this actually do? :D
pub(crate) async fn oauth2_basic_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerBasic.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_public",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// TODO: what does this actually do? :D
pub(crate) async fn oauth2_public_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerPublic.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/oauth2/{rs_name}",
    responses(
        (status = 200, /* TODO response=Option<ProtoEntry>*/),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Get the details of a given OAuth2 Resource Server.
pub(crate) async fn oauth2_id_get(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = oauth2_id(&rs_name);
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
    path = "/v1/oauth2/{rs_name}/_basic_secret",
    responses(
        (status = 200,content_type="application/json", body=Option<String>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Get the basic secret for a given OAuth2 Resource Server. This is used for authentication.
#[instrument(level = "info", skip(state))]
pub(crate) async fn oauth2_id_get_basic_secret(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<Option<String>>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_r_ref
        .handle_oauth2_basic_secret_read(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Modify an OAuth2 Resource Server
pub(crate) async fn oauth2_id_patch(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);

    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Modify the scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_scopemap_update(client_auth_info, group, scopes, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// Delete a scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_scopemap_delete(client_auth_info, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}/{group}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Modify the scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name, group)): Path<(String, String, String)>,
    Json(claims): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_clapmmap_update(client_auth_info, claim_name, group, values, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}",
    request_body=Oauth2ClaimMapJoin,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Modify the scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_join_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name)): Path<(String, String)>,
    Json(claims): Json<Oauth2ClaimMapJoin>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_clapmmap_update_join(client_auth_info, claim_name, join, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// Delete a scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name, group)): Path<(String, String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_claimmap_delete(client_auth_info, claim_name, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Create a supplemental scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_sup_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_update(client_auth_info, group, scopes, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// Delete a supplemental scope map configuration.
pub(crate) async fn oauth2_id_sup_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_delete(client_auth_info, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}",
    responses(
        DefaultApiResponse,
        (status = 404),
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// Delete an OAuth2 Resource Server
pub(crate) async fn oauth2_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_internaldelete(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
// API endpoint for deleting the image associated with an OAuth2 Resource Server.
pub(crate) async fn oauth2_id_image_delete(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_rs_image_delete(client_auth_info, oauth2_id(&rs_name))
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/oauth2",
)]
/// API endpoint for creating/replacing the image associated with an OAuth2 Resource Server.
///
/// It requires a multipart form with the image file, and the content type must be one of the
/// [VALID_IMAGE_UPLOAD_CONTENT_TYPES].
pub(crate) async fn oauth2_id_image_post(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<()>, WebError> {
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
                        return Err(OperationError::InvalidRequestState.into());
                    }
                }
                None => {
                    debug!("No content type header provided");
                    return Err(OperationError::InvalidRequestState.into());
                }
            };
            let data = match field.bytes().await {
                Ok(val) => val,
                Err(_e) => return Err(OperationError::InvalidRequestState.into()),
            };

            let filetype = match ImageType::try_from_content_type(&content_type) {
                Ok(val) => val,
                Err(_err) => return Err(OperationError::InvalidRequestState.into()),
            };

            image = Some(ImageValue {
                filetype,
                filename: filename.to_string(),
                contents: data.to_vec(),
            });
        };
    }

    match image {
        Some(image) => {
            let image_validation_result = image.validate_image();
            match image_validation_result {
                Err(err) => {
                    admin_error!("Invalid image uploaded: {:?}", err);
                    Err(WebError::from(OperationError::InvalidRequestState))
                }
                Ok(_) => {
                    let rs_name = oauth2_id(&rs_name);
                    state
                        .qe_w_ref
                        .handle_oauth2_rs_image_update(client_auth_info, rs_name, image)
                        .await
                        .map(Json::from)
                        .map_err(WebError::from)
                }
            }
        }
        None => Err(WebError::from(OperationError::InvalidAttribute(
            "No image included, did you mean to use the DELETE method?".to_string(),
        ))),
    }
}
