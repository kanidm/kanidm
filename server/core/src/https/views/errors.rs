use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_htmx::{HxReswap, HxRetarget, SwapOption};
use utoipa::ToSchema;
use uuid::Uuid;

use kanidm_proto::internal::OperationError;

use crate::https::middleware::KOpId;
use crate::https::views::UnrecoverableErrorView;
// #[derive(Template)]
// #[template(path = "recoverable_error_partial.html")]
// struct ErrorPartialView {
//     error_message: String,
//     operation_id: Uuid,
//     recovery_path: String,
//     recovery_boosted: bool,
// }

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub(crate) enum HtmxError {
    /// Something went wrong when doing things.
    OperationError(Uuid, OperationError),
}

impl HtmxError {
    pub(crate) fn new(kopid: &KOpId, operr: OperationError) -> Self {
        HtmxError::OperationError(kopid.eventid, operr)
    }
}

impl IntoResponse for HtmxError {
    fn into_response(self) -> Response {
        match self {
            HtmxError::OperationError(kopid, inner) => {
                let body = serde_json::to_string(&inner).unwrap_or(inner.to_string());
                match &inner {
                    OperationError::NotAuthenticated
                    | OperationError::SessionExpired
                    | OperationError::InvalidSessionState => Redirect::to("/ui").into_response(),
                    OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                        (StatusCode::FORBIDDEN, body).into_response()
                    }
                    OperationError::NoMatchingEntries => {
                        (StatusCode::NOT_FOUND, body).into_response()
                    }
                    OperationError::PasswordQuality(_)
                    | OperationError::EmptyRequest
                    | OperationError::SchemaViolation(_)
                    | OperationError::CU0003WebauthnUserNotVerified => {
                        (StatusCode::BAD_REQUEST, body).into_response()
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        HxRetarget("body".to_string()),
                        HxReswap(SwapOption::OuterHtml),
                        UnrecoverableErrorView {
                            err_code: inner,
                            operation_id: kopid,
                        },
                    )
                        .into_response(),
                }
            }
        }
    }
}
