use num_enum::{IntoPrimitive, TryFromPrimitive};
use tracing_forest::ForestLayer;
use tracing_forest::tag::NoTag;
use tracing_forest::printer::{Printer, MakeStdout};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::util::SubscriberInitExt;

pub mod macros;
pub mod middleware;

pub use tracing;
pub use tracing_forest;
pub use tracing_subscriber;


pub fn test_init() -> () {
    // tracing_subscriber::fmt::try_init()
    let _ = Registry::default().with(ForestLayer::new(
        Printer::new()
            .writer(MakeStdout),
        NoTag,
    )).try_init();
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
            AdminDebug => "🐛",
            AdminError | FilterError | RequestError | SecurityError => "🚨",
            AdminWarn | FilterWarn | RequestWarn => "⚠️",
            AdminInfo | FilterInfo | RequestInfo | SecurityInfo => "  ",
            RequestTrace | FilterTrace | PerfTrace => "📍",
            SecurityCritical => "🔐",
            SecurityAccess => "🔓",
        }
    }
}
