//! Where we hide the error handling widgets
//!

use axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use hyper::header::WWW_AUTHENTICATE;
use kanidm_proto::oauth2::ErrorResponse;
use kanidmd_lib::idm::oauth2::Oauth2Error;
use utoipa::ToSchema;

use kanidm_proto::internal::OperationError;

/// The web app's top level error type, this takes an `OperationError` and converts it into a HTTP response.
#[derive(Debug, ToSchema)]
pub enum WebError {
    /// Something went wrong when doing things.
    OperationError(OperationError),
    InternalServerError(String),
    #[schema(value_type=Object)]
    OAuth2(Oauth2Error),
}

impl From<OperationError> for WebError {
    fn from(inner: OperationError) -> Self {
        WebError::OperationError(inner)
    }
}

impl From<Oauth2Error> for WebError {
    fn from(inner: Oauth2Error) -> Self {
        WebError::OAuth2(inner)
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
            WebError::OAuth2(error) => {
                if let Oauth2Error::AuthenticationRequired = error {
                    (
                        StatusCode::UNAUTHORIZED,
                        [
                            (WWW_AUTHENTICATE, "Bearer"),
                            (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                        ],
                    )
                        .into_response()
                } else {
                    let err = ErrorResponse {
                        error: error.to_string(),
                        ..Default::default()
                    };

                    let body = match serde_json::to_string(&err) {
                        Ok(val) => val,
                        Err(e) => {
                            warn!("Failed to serialize error response: original_error=\"{:?}\" serialization_error=\"{:?}\"", err, e);
                            format!("{err:?}")
                        }
                    };

                    (
                        StatusCode::BAD_REQUEST,
                        [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                        body,
                    )
                        .into_response()
                }
            }
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
                    OperationError::AttributeUniqueness(_) => (StatusCode::CONFLICT, None),
                    OperationError::NoMatchingEntries => (StatusCode::NOT_FOUND, None),
                    OperationError::PasswordQuality(_)
                    | OperationError::EmptyRequest
                    | OperationError::InvalidAttribute(_)
                    | OperationError::InvalidAttributeName(_)
                    | OperationError::SchemaViolation(_)
                    | OperationError::CU0003WebauthnUserNotVerified
                    | OperationError::VL0001ValueSshPublicKeyString => {
                        (StatusCode::BAD_REQUEST, None)
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, None),
                };
                let body = serde_json::to_string(&inner).unwrap_or(inner.to_string());
                debug!(?body);

                match headers {
                    Some(headers) => (code, headers, body).into_response(),
                    None => (code, body).into_response(),
                }
            }
        }
    }
}
