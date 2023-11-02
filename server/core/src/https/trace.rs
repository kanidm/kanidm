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
    #[instrument(name = "handle_request", skip_all, fields(hhhhhh = "hmmmmmm"))]
    fn make_span(&mut self, request: &Request<B>) -> Span {
        tracing::span!(
            Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            "http.status_code" = None::<u16>,
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

impl Default for DefaultOnResponseKanidmd {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            latency_unit: LatencyUnit::Millis,
            include_headers: false,
        }
    }
}

// struct Latency {
//     unit: LatencyUnit,
//     duration: Duration,
// }

// impl DefaultOnResponseKanidmd {
//     pub fn new() -> Self {
//         Self::default()
//     }
//     /// Set the [`Level`] used for [tracing events].
//     ///
//     /// Please note that while this will set the level for the tracing events
//     /// themselves, it might cause them to lack expected information, like
//     /// request method or path. You can address this using
//     /// [`DefaultMakeSpan::level`].
//     ///
//     /// Defaults to [`Level::DEBUG`].
//     ///
//     /// [tracing events]: https://docs.rs/tracing/latest/tracing/#events
//     /// [`DefaultMakeSpan::level`]: crate::trace::DefaultMakeSpan::level
//     #[allow(dead_code)]
//     pub fn level(mut self, level: Level) -> Self {
//         self.level = level;
//         self
//     }

//     /// Set the [`LatencyUnit`] latencies will be reported in.
//     ///
//     /// Defaults to [`LatencyUnit::Millis`].
//     #[allow(dead_code)]
//     pub fn latency_unit(mut self, latency_unit: LatencyUnit) -> Self {
//         self.latency_unit = latency_unit;
//         self
//     }

//     /// Include response headers on the [`Event`].
//     ///
//     /// By default headers are not included.
//     ///
//     /// [`Event`]: tracing::Event
//     #[allow(dead_code)]
//     pub fn include_headers(mut self, include_headers: bool) -> Self {
//         self.include_headers = include_headers;
//         self
//     }
// }

// // use tower_http::trace::{Latency, DEFAULT_MESSAGE_LEVEL};

// // impl<B> OnResponse<B> for DefaultOnResponseKanidmd {
// //     fn on_response(self, response: &Response<B>, latency: Duration, _: &Span) {
// //         let latency = Latency {
// //             unit: self.latency_unit,
// //             duration: latency,
// //         };
// //         let _response_headers = self
// //             .include_headers
// //             .then(|| tracing::field::debug(response.headers()));

// //         tracing::event!(
// //             // $(target: $target,)?
// //             // $(parent: $parent,)?
// //             // self.level,
// //             // $($tt)*
// //             // );
// //             // event_dynamic_lvl!(
// //             self.level,
// //             // ?latency,
// //             status = status(response),
// //             response_headers,
// //             "finished processing request"
// //         );
// //     }
// // }

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
