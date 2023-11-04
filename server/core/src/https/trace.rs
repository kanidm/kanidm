//! Reimplementation of tower-http's DefaultMakeSpan that only runs at "INFO" level for our own needs.

use http::Request;
// use tower_http::trace::OnResponse;
use tower_http::LatencyUnit;
use tracing::{Level, Span};

// use http::Response;
// use std::time::Duration;
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
        span: &Span,
    ) {
        // if let Some(meta) = span.metadata() {
        //     meta.fields().iter().for_each(|f| {
        //         println!("meta field: {:?}", f);
        //     })
        // };
        // let latency = Latency {
        //     unit: self.latency_unit,
        //     duration: latency,
        // };
        let _response_headers = self
            .include_headers
            .then(|| tracing::field::debug(response.headers()));
        span.record("latency_micros", latency.as_micros());
        span.record("http.status_code", response.status().as_u16());

        // span.record(
        //     "status",
        //     if response.status().is_success() {
        //         "OK"
        //     } else {
        //         "ERROR"
        //     },
        // );

        // let response_status = response.status();
        // span.record(field, value)
        // opentelemetry_api::trace::get_active_span(|otel_span| {
        //     otel_span.set_status(if response.status().is_success() {
        //         opentelemetry_api::trace::Status::Ok
        //     } else {
        //         opentelemetry_api::trace::Status::Error {
        //             description: format!("{}", response_status).into(),
        //         }
        //     });
        //     // span.set_attribute(attribute::http::METHOD.string(request.method().as_str()));
        // })
        match response.status().is_success() {
            true => {
                tracing::event!(
                    target: "response",
                    Level::INFO,
                    ?latency,
                    status = response.status().as_u16(),
                    "finished processing request"
                );
            }
            false => {
                if response.status().as_u16() < 500 {
                    tracing::event!(
                        target: "response",
                        Level::WARN, // this forces the tracing pipeline to recognize it as an error
                        ?latency,
                        status = response.status().as_u16(),
                        "finished processing request"
                    );
                } else {
                    tracing::event!(
                        target: "response",
                        Level::ERROR, // this forces the tracing pipeline to recognize it as an error
                        ?latency,
                        status = response.status().as_u16(),
                        "finished processing request"
                    );
                };
            }
        }
    }
}

// // fn status<B>(res: &Response<B>) -> Option<i32> {
// // use crate::classify::grpc_errors_as_failures::ParsedGrpcStatus;

// // gRPC-over-HTTP2 uses the "application/grpc[+format]" content type, and gRPC-Web uses
// // "application/grpc-web[+format]" or "application/grpc-web-text[+format]", where "format" is
// // the message format, e.g. +proto, +json.
// //
// // So, valid grpc content types include (but are not limited to):
// //  - application/grpc
// //  - application/grpc+proto
// //  - application/grpc-web+proto
// //  - application/grpc-web-text+proto
// //
// // For simplicity, we simply check that the content type starts with "application/grpc".
// // let is_grpc = res
// //     .headers()
// //     .get(http::header::CONTENT_TYPE)
// //     .map_or(false, |value| {
// //         value.as_bytes().starts_with("application/grpc".as_bytes())
// //     });

// // if is_grpc {
// //     match crate::classify::grpc_errors_as_failures::classify_grpc_metadata(
// //         res.headers(),
// //         crate::classify::GrpcCode::Ok.into_bitmask(),
// //     ) {
// //         ParsedGrpcStatus::Success
// //         | ParsedGrpcStatus::HeaderNotString
// //         | ParsedGrpcStatus::HeaderNotInt => Some(0),
// //         ParsedGrpcStatus::NonSuccess(status) => Some(status.get()),
// //         // if `grpc-status` is missing then its a streaming response and there is no status
// //         // _yet_, so its neither success nor error
// //         ParsedGrpcStatus::GrpcStatusHeaderMissing => None,
// //     }
// // } else {
// //     Some(res.status().as_u16().into())
// // }
// // }
