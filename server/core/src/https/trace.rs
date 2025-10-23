//! Reimplementation of tower-http's DefaultMakeSpan that only runs at "INFO" level for our own needs.

use axum::http::{Request, StatusCode};
use kanidm_proto::constants::KOPID;
use sketching::event_dynamic_lvl;
use tower_http::trace::OnRequest;
use tracing::{Level, Span};

/// The default way Spans will be created for Trace.
///
#[derive(Debug, Clone)]
pub struct DefaultMakeSpanKanidmd {}

impl<B> tower_http::trace::MakeSpan<B> for DefaultMakeSpanKanidmd {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        // Needs to be at info to ensure that there is always a span for each
        // tracing event to hook into.
        tracing::span!(
            Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            kopid = tracing::field::Empty, // filled in later
            connection_addr = tracing::field::Empty, // filled in later
            client_ip_addr = tracing::field::Empty, // filled in later
            status_code = tracing::field::Empty, // filled in later
            latency = tracing::field::Empty, // filled in later
            // Defer logging this span until there is child information attached.
            defer = true,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DefaultOnRequestKanidmd {}

impl<B> OnRequest<B> for DefaultOnRequestKanidmd {
    fn on_request(&mut self, _request: &axum::http::Request<B>, _span: &Span) {}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DefaultOnResponseKanidmd {}

impl<B> tower_http::trace::OnResponse<B> for DefaultOnResponseKanidmd {
    fn on_response(
        self,
        response: &axum::response::Response<B>,
        latency: std::time::Duration,
        span: &Span,
    ) {
        if let Some(client_conn_info) = response.extensions().get::<crate::https::ClientConnInfo>()
        {
            span.record(
                "connection_addr",
                client_conn_info.connection_addr.to_string(),
            );
            span.record(
                "client_ip_addr",
                client_conn_info.client_ip_addr.to_string(),
            );
        };
        let kopid = match response.headers().get(KOPID) {
            Some(val) => val.to_str().unwrap_or("<invalid kopid>"),
            None => "<unknown>",
        };
        let (level, msg) =
            match response.status().is_success() || response.status().is_informational() {
                true => (Level::DEBUG, "response sent"),
                false => {
                    if response.status().is_redirection() {
                        (Level::INFO, "client redirection sent")
                    } else if response.status().is_client_error() {
                        if response.status() == StatusCode::NOT_FOUND {
                            (Level::INFO, "client error")
                        } else {
                            (Level::WARN, "client error") // it worked, but there was an input error
                        }
                    } else {
                        (Level::ERROR, "error handling request") // oh no the server failed
                    }
                }
            };
        span.record("latency", latency.as_millis());
        span.record("kopid", kopid);
        span.record("status_code", response.status().as_u16());
        event_dynamic_lvl!(
            level, // ?latency,
            msg
        );
    }
}
