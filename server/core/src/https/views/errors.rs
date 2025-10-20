use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_htmx::{HxEvent, HxResponseTrigger, HxReswap, HxRetarget, SwapOption};
use kanidmd_lib::idm::server::DomainInfoRead;
use utoipa::ToSchema;
use uuid::Uuid;

use kanidm_proto::internal::OperationError;

use crate::https::middleware::KOpId;
use crate::https::views::{ErrorToastPartial, KanidmHxEventName, UnrecoverableErrorView};

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub(crate) enum HtmxError {
    /// Something went wrong when doing things.
    OperationError(Uuid, OperationError, DomainInfoRead),
}

impl HtmxError {
    pub(crate) fn new(kopid: &KOpId, operr: OperationError, domain_info: DomainInfoRead) -> Self {
        HtmxError::OperationError(kopid.eventid, operr, domain_info)
    }
}

impl IntoResponse for HtmxError {
    fn into_response(self) -> Response {
        match self {
            HtmxError::OperationError(kopid, inner, domain_info) => {
                let body = serde_json::to_string(&inner).unwrap_or(inner.to_string());
                match &inner {
                    OperationError::NotAuthenticated
                    | OperationError::SessionExpired
                    | OperationError::InvalidSessionState => Redirect::to("/ui").into_response(),
                    OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                        let trigger = HxResponseTrigger::after_swap([HxEvent::from(
                            KanidmHxEventName::PermissionDenied,
                        )]);
                        (
                            trigger,
                            HxRetarget("main".to_string()),
                            HxReswap(SwapOption::BeforeEnd),
                            (
                                StatusCode::FORBIDDEN,
                                ErrorToastPartial {
                                    err_code: inner,
                                    operation_id: kopid,
                                },
                            )
                                .into_response(),
                        )
                            .into_response()
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
                            domain_info,
                        },
                    )
                        .into_response(),
                }
            }
        }
    }
}
