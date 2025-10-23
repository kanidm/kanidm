//! Reimplementation of tower-http's DefaultMakeSpan that only runs at "INFO" level for our own needs.

use axum::http::Request;
use kanidm_proto::constants::KOPID;
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
            client_address = tracing::field::Empty, // filled in later
            status_code = tracing::field::Empty, // filled in later
            latency = tracing::field::Empty, // filled in later
        )
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DefaultOnRequestKanidmd {}

impl<B> OnRequest<B> for DefaultOnRequestKanidmd {
    fn on_request(&mut self, request: &axum::http::Request<B>, span: &Span) {
        if let Some(client_conn_info) = request.extensions().get::<crate::https::ClientConnInfo>() {
            span.record(
                "client_address",
                client_conn_info.connection_addr.to_string(),
            );
        };
    }
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

        span.record("latency", latency.as_millis());
        span.record("kopid", kopid);
        span.record("status_code", response.status().as_u16());
    }
}
