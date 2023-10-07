//! Where we hide the error handling widgets
//!

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use kanidm_proto::v1::OperationError;
use utoipa::ToSchema;

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub enum WebError {
    /// Something went wrong when doing things.
    OperationError(OperationError),
    InternalServerError(String),
}

impl From<OperationError> for WebError {
    fn from(inner: OperationError) -> Self {
        WebError::OperationError(inner)
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        match self {
            WebError::InternalServerError(inner) => {
                (StatusCode::INTERNAL_SERVER_ERROR, inner).into_response()
            }
            WebError::OperationError(inner) => {
                let (response_code, headers) = match &inner {
                    OperationError::NotAuthenticated | OperationError::SessionExpired => {
                        // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                        (
                            StatusCode::UNAUTHORIZED,
                            // Some([("WWW-Authenticate", "Bearer")]),
                            Some([("WWW-Authenticate", "Bearer"); 1]),
                        )
                    }
                    OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                        (StatusCode::FORBIDDEN, None)
                    }
                    OperationError::NoMatchingEntries => (StatusCode::NOT_FOUND, None),
                    OperationError::PasswordQuality(_)
                    | OperationError::EmptyRequest
                    | OperationError::SchemaViolation(_) => (StatusCode::BAD_REQUEST, None),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
                };
                let body =
                    serde_json::to_string(&inner).unwrap_or_else(|_err| format!("{:?}", inner));
                match headers {
                    Some(headers) => (response_code, headers, body).into_response(),
                    None => (response_code, body).into_response(),
                }
            }
        }
    }
}
