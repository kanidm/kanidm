use axum::{http::HeaderValue, Router};
use tower_http::cors::CorsLayer;

use super::ServerState;

pub trait Cors {
    fn cors(self, cors_allowed_origins: Option<Vec<HeaderValue>>) -> Self;
}

impl Cors for Router<ServerState> {
    fn cors(self, cors_allowed_origins: Option<Vec<HeaderValue>>) -> Self {
        if let Some(origins) = cors_allowed_origins {
            self.layer(CorsLayer::new().allow_origin(origins))
        } else {
            self
        }
    }
}
