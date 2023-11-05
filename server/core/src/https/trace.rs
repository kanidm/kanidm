//! Reimplementation of tower-http's DefaultMakeSpan that only runs at "INFO" level for our own needs.

use http::Request;
use kanidm_proto::constants::KOPID;
use sketching::event_dynamic_lvl;
use tower_http::LatencyUnit;
use tracing::{Level, Span};

/// The default way Spans will be created for Trace.
///
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
    #[instrument(name = "handle_request", skip_all, fields(latency, status_code))]
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

#[derive(Clone, Debug)]
pub(crate) struct DefaultOnResponseKanidmd {
    #[allow(dead_code)]
    level: Level,
    #[allow(dead_code)]
    latency_unit: LatencyUnit,
    #[allow(dead_code)]
    include_headers: bool,
}

impl DefaultOnResponseKanidmd {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for DefaultOnResponseKanidmd {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            latency_unit: LatencyUnit::Millis,
            include_headers: false,
        }
    }
}

impl<B> tower_http::trace::OnResponse<B> for DefaultOnResponseKanidmd {
    fn on_response(
        self,
        response: &axum::response::Response<B>,
        latency: std::time::Duration,
        _span: &Span,
    ) {
        let kopid = match response.headers().get(KOPID) {
            Some(val) => val.to_str().unwrap_or("<invalid kopid>"),
            None => "<unknown>",
        };
        let (level, msg) =
            match response.status().is_success() || response.status().is_informational() {
                true => (Level::INFO, "response sent"),
                false => {
                    if response.status().is_redirection() {
                        (Level::INFO, "client redirection sent")
                    } else if response.status().is_client_error() {
                        (Level::WARN, "client error") // it worked, but there was an input error
                    } else {
                        (Level::ERROR, "error handling request") // oh no the server failed
                    }
                }
            };
        event_dynamic_lvl!(
            level,
            ?latency,
            status_code = response.status().as_u16(),
            kopid = kopid,
            msg
        );
    }
}
