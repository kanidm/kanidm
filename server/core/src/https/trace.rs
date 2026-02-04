//! Reimplementation of tower-http's DefaultMakeSpan that only runs at "INFO" level for our own needs.

use crate::https::LoggerType;
use axum::http::Request;
use kanidm_proto::constants::KOPID;
use tower_http::trace::OnRequest;
use tracing::{Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
/// The default way Spans will be created for Trace.
///
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SpanCreator {
    pub(crate) log_engine: LoggerType,
}

impl<B> tower_http::trace::MakeSpan<B> for SpanCreator {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        // Needs to be at info to ensure that there is always a span for each
        // tracing event to hook into.
        //
        // NOTE: There is a directive in the logging pipeline setup to force this
        // span to always be at the info level. If this is not done, then there
        // will not be an event uuid available which causes TONS of problems. Like
        // crashing.
        tracing::span!(
            Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            kopid = tracing::field::Empty, // filled in later
            connection_address = tracing::field::Empty, // filled in later
            client_address = tracing::field::Empty, // filled in later
            status_code = tracing::field::Empty, // filled in later, used by tracing forest
            http.response.status_code = tracing::field::Empty, // filled in later, used by otel
            latency = tracing::field::Empty, // filled in later
        )
    }
}

impl<B> OnRequest<B> for SpanCreator {
    fn on_request(&mut self, request: &axum::http::Request<B>, span: &Span) {
        if let Some(client_conn_info) = request.extensions().get::<crate::https::ClientConnInfo>() {
            span.record(
                "connection_address",
                client_conn_info.connection_addr.to_string(),
            );
            span.record(
                "client_address",
                client_conn_info.client_ip_addr.to_string(),
            );
        };
    }
}

impl<B> tower_http::trace::OnResponse<B> for SpanCreator {
    fn on_response(
        self,
        response: &axum::response::Response<B>,
        latency: std::time::Duration,
        span: &Span,
    ) {
        if let Some(client_conn_info) = response.extensions().get::<crate::https::ClientConnInfo>()
        {
            span.record(
                "connection_address",
                client_conn_info.connection_addr.to_string(),
            );
            span.record(
                "client_address",
                client_conn_info.client_ip_addr.to_string(),
            );
        };

        let kopid = match response.headers().get(KOPID) {
            Some(val) => val.to_str().unwrap_or("<invalid kopid>"),
            None => "<unknown>",
        };

        if self.log_engine == LoggerType::OpenTelemetry {
            span.record(
                self.log_engine.status_code_field(),
                response.status().as_u16(),
            );
            match response.status().is_success() {
                true => span.set_status(opentelemetry::trace::Status::Ok),
                false => span.set_status(opentelemetry::trace::Status::error(format!(
                    "HTTP {}",
                    response.status().as_u16()
                ))),
            }
        } else {
            span.record(
                self.log_engine.status_code_field(),
                response.status().as_u16() as u64,
            );
            // don't need these in otel because they're alreayd in th
            span.record("latency", latency.as_millis());
        }
        span.record("kopid", kopid);
    }
}
