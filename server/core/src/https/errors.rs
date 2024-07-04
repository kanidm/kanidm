//! Where we hide the error handling widgets
//!

use axum::http::{HeaderValue, StatusCode};
use axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use axum::response::{IntoResponse, Response};
use axum_htmx::{HxReswap, HxRetarget, SwapOption};
use utoipa::ToSchema;
use uuid::Uuid;

use kanidm_proto::internal::OperationError;

use crate::https::middleware::KOpId;
use crate::https::views::errors::ErrorPartialView;
use crate::https::views::HtmlTemplate;

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub enum HtmxError {
    /// Something went wrong when doing things.
    OperationError(Uuid, OperationError),
    // InternalServerError(Uuid, String),
}

impl From<(&KOpId, OperationError)> for HtmxError {
    fn from((kopid, err): (&KOpId, OperationError)) -> Self {
        HtmxError::OperationError(kopid.eventid, err)
    }
}

impl IntoResponse for HtmxError {
    fn into_response(self) -> Response {
        match self {
            // HtmxError::InternalServerError(_kopid, inner) => {
            //     (StatusCode::INTERNAL_SERVER_ERROR, inner).into_response()
            // }
            HtmxError::OperationError(kopid, inner) => {
                let body = serde_json::to_string(&inner).unwrap_or(inner.to_string());
                let response = match &inner {
                    OperationError::NotAuthenticated | OperationError::SessionExpired => {
                        (
                            HxRetarget("body".to_string()),
                            HxReswap(SwapOption::BeforeEnd),
                            HtmlTemplate(ErrorPartialView {
                                operation_id: kopid,
                                error_message: body,
                                recovery_path: "/".into(),
                                recovery_boosted: false,
                            }),
                        ).into_response()
                    }
                    OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                        (StatusCode::FORBIDDEN, body).into_response()
                    }
                    OperationError::NoMatchingEntries => (StatusCode::NOT_FOUND, body).into_response(),
                    OperationError::PasswordQuality(_)
                    | OperationError::EmptyRequest
                    | OperationError::SchemaViolation(_)
                    | OperationError::CU0003WebauthnUserNotVerified => {
                        (StatusCode::BAD_REQUEST, body).into_response()
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, body).into_response(),
                };
                response
            }
        }
    }
}


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

impl WebError {
    pub(crate) fn response_with_access_control_origin_header(self) -> Response {
        let mut res = self.into_response();
        res.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            #[allow(clippy::expect_used)]
            HeaderValue::from_str("*").expect("Header generation failed, this is weird."),
        );
        res
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        match self {
            WebError::InternalServerError(inner) => {
                (StatusCode::INTERNAL_SERVER_ERROR, inner).into_response()
            }
            WebError::OperationError(inner) => {
                let (code, headers) = match &inner {
                    OperationError::NotAuthenticated | OperationError::SessionExpired => {
                        // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                        (
                            StatusCode::UNAUTHORIZED,
                            Some([("WWW-Authenticate", "Bearer"); 1]),
                        )
                    }
                    OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                        (StatusCode::FORBIDDEN, None)
                    }
                    OperationError::NoMatchingEntries => (StatusCode::NOT_FOUND, None),
                    OperationError::PasswordQuality(_)
                    | OperationError::EmptyRequest
                    | OperationError::SchemaViolation(_)
                    | OperationError::CU0003WebauthnUserNotVerified => {
                        (StatusCode::BAD_REQUEST, None)
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
                };
                let body = serde_json::to_string(&inner).unwrap_or(inner.to_string());

                match headers {
                    Some(headers) => (code, headers, body).into_response(),
                    None => (code, body).into_response(),
                }
            }
        }
    }
}
