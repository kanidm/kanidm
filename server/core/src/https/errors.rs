//! Where we hide the error handling widgets
//!

use axum::response::{IntoResponse, Response};
use kanidm_proto::v1::OperationError;
use utoipa::ToSchema;

use super::to_axum_response;

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub enum WebError {
    /// Something went wrong when doing things.
    OperationError(OperationError),
}

impl From<OperationError> for WebError {
    fn from(inner: OperationError) -> Self {
        WebError::OperationError(inner)
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let res = match self {
            // TODO: rip out to_axum_response
            WebError::OperationError(inner) => to_axum_response::<String>(Err(inner)),
        };

        res.into_response()
    }
}
