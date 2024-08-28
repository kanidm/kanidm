use super::ServerState;
use axum::{
    extract::State,
    http::header::{
        CONTENT_TYPE
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};


pub(crate) async fn image_get(
    State(state): State<ServerState>,
    // VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Response {
    let res = state
        .qe_r_ref
        .handle_domain_get_image(
            // client_auth_info
        )
        .await;

    match res {
        Ok(Some(image)) => (
            StatusCode::OK,
            [(CONTENT_TYPE, image.filetype.as_content_type_str())],
            image.contents,
        )
            .into_response(),
        Ok(None) => {
            warn!("No image set for domain");
            (StatusCode::NOT_FOUND, "").into_response()
        }
        Err(err) => {
            error!(?err,
                "Unable to get image for domain"
            );
            // TODO: a 404 probably isn't perfect but it's not the worst
            (StatusCode::INTERNAL_SERVER_ERROR, "").into_response()
        }
    }
}
