//! Reimplementation of [`tower-http`]'s [`DefaultMakeSpan`] that only runs at "INFO" level for our own needs.

use http::Request;
use tracing::{Level, Span};

/// The default way [`Span`]s will be created for [`Trace`].
///
/// [`Span`]: tracing::Span
/// [`Trace`]: super::Trace
#[derive(Debug, Clone)]
pub struct DefaultMakeSpanKanidmd {}

impl DefaultMakeSpanKanidmd {
    /// Create a new `DefaultMakeSpanKanidmd`.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DefaultMakeSpanKanidmd {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> tower_http::trace::MakeSpan<B> for DefaultMakeSpanKanidmd {
    #[instrument(name = "handle_request", skip_all)]
    fn make_span(&mut self, request: &Request<B>) -> Span {
        tracing::span!(
            Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
        )
    }
}
