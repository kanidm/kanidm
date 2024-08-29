use super::apidocs::response_schema::DefaultApiResponse;
use super::errors::WebError;
use super::ServerState;
use crate::https::extractors::DomainInfo;
use crate::https::extractors::VerifiedClientInformation;
use axum::extract::State;
use axum::Json;
use axum::{
    http::header::CONTENT_TYPE,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kanidm_proto::internal::{ImageType, ImageValue};
use kanidmd_lib::prelude::*;
use kanidmd_lib::valueset::image::ImageValueThings;
use sketching::admin_error;

pub(crate) async fn image_get(DomainInfo(domain_info): DomainInfo) -> Response {
    match domain_info.image() {
        Some(image) => (
            StatusCode::OK,
            [(CONTENT_TYPE, image.filetype.as_content_type_str())],
            image.contents.clone(),
        )
            .into_response(),
        None => {
            warn!("No image set for domain");
            (StatusCode::NOT_FOUND, "").into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/domain/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_image_delete"
)]
pub(crate) async fn image_delete(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let f_uuid = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO)));

    state
        .qe_w_ref
        .handle_image_update(client_auth_info, f_uuid, None)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/domain/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "v1/domain",
    operation_id = "domain_image_post"
)]
/// API endpoint for creating/replacing the image associated with an OAuth2 Resource Server.
///
/// It requires a multipart form with the image file, and the content type must be one of the
/// [VALID_IMAGE_UPLOAD_CONTENT_TYPES].
pub(crate) async fn image_post(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
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
                    let f_uuid =
                        filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO)));
                    state
                        .qe_w_ref
                        .handle_image_update(client_auth_info, f_uuid, Some(image))
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
