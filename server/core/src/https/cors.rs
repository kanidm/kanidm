use axum::{
    http::{header::ACCESS_CONTROL_ALLOW_ORIGIN, request::Parts as RequestParts, HeaderValue},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use super::ServerState;

pub trait Cors {
    fn cors(self, cors_allowed_origins: Option<Vec<HeaderValue>>) -> Self;
}

impl Cors for Router<ServerState> {
    fn cors(self, cors_allowed_origins: Option<Vec<HeaderValue>>) -> Self {
        if let Some(origins) = cors_allowed_origins {
            self.layer(CorsLayer::new().allow_origin(AllowOrigin::predicate(
                move |origin: &HeaderValue, request_parts: &RequestParts| {
                    let existing = request_parts.headers.get_all(ACCESS_CONTROL_ALLOW_ORIGIN);
                    origins.contains(origin) || existing.into_iter().any(|o| origins.contains(o))
                },
            )))
        } else {
            self
        }
    }
}
