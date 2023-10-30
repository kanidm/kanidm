#![deny(warnings)]
#![warn(unused_extern_crates)]
#![allow(non_snake_case)]
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tracing_forest::printer::TestCapturePrinter;
use tracing_forest::tag::NoTag;
use tracing_forest::util::*;
use tracing_forest::Tag;
use tracing_subscriber::prelude::*;

pub mod macros;

pub use {tracing, tracing_forest, tracing_subscriber};

/// Start up the logging for test mode.
pub fn test_init() {
    let filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::TRACE.into())
        // escargot builds cargo packages while we integration test and is SUPER noisy.
        .add_directive(
            "escargot=ERROR"
                .parse()
                .expect("failed to generate log filter"),
        )
        // hyper's very noisy in debug mode with connectivity-related things that we only need in extreme cases.
        .add_directive("hyper=INFO".parse().expect("failed to generate log filter"));

    // start the logging!
    let _ = tracing_subscriber::Registry::default()
        .with(ForestLayer::new(TestCapturePrinter::new(), NoTag).with_filter(filter))
        .try_init();
}

/// This is for tagging events. Currently not wired in.
pub fn event_tagger(_event: &Event) -> Option<Tag> {
    None
}

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum EventTag {
    AdminDebug,
    AdminError,
    AdminWarn,
    AdminInfo,
    RequestError,
    RequestWarn,
    RequestInfo,
    RequestTrace,
    SecurityCritical,
    SecurityDebug,
    SecurityInfo,
    SecurityAccess,
    SecurityError,
    FilterError,
    FilterWarn,
    FilterInfo,
    FilterTrace,
    PerfTrace,
}

impl EventTag {
    pub fn pretty(self) -> &'static str {
        match self {
            EventTag::AdminDebug => "admin.debug",
            EventTag::AdminError => "admin.error",
            EventTag::AdminWarn => "admin.warn",
            EventTag::AdminInfo => "admin.info",
            EventTag::RequestError => "request.error",
            EventTag::RequestWarn => "request.warn",
            EventTag::RequestInfo => "request.info",
            EventTag::RequestTrace => "request.trace",
            EventTag::SecurityCritical => "security.critical",
            EventTag::SecurityDebug => "security.debug",
            EventTag::SecurityInfo => "security.info",
            EventTag::SecurityAccess => "security.access",
            EventTag::SecurityError => "security.error",
            EventTag::FilterError => "filter.error",
            EventTag::FilterWarn => "filter.warn",
            EventTag::FilterInfo => "filter.info",
            EventTag::FilterTrace => "filter.trace",
            EventTag::PerfTrace => "perf.trace",
        }
    }

    pub fn emoji(self) -> &'static str {
        use EventTag::*;
        match self {
            AdminDebug | SecurityDebug => "🐛",
            AdminError | FilterError | RequestError | SecurityError => "🚨",
            AdminWarn | FilterWarn | RequestWarn => "⚠️",
            AdminInfo | FilterInfo | RequestInfo | SecurityInfo => "ℹ️",
            RequestTrace | FilterTrace | PerfTrace => "📍",
            SecurityCritical => "🔐",
            SecurityAccess => "🔓",
        }
    }
}
