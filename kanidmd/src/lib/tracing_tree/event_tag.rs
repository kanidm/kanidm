use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum EventTag {
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
    FilterError,
    FilterWarn,
    FilterInfo,
    FilterTrace,
    PerfTrace,
}

impl EventTag {
    pub fn pretty(self) -> &'static str {
        match self {
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
            AdminError | RequestError | FilterError => "🚨",
            AdminWarn | RequestWarn | FilterWarn => "🚧",
            AdminInfo | RequestInfo | SecurityInfo | FilterInfo => "💬",
            RequestTrace | FilterTrace | PerfTrace => "📍",
            SecurityCritical => "🔐",
            SecurityAccess => "🔓",
        }
    }
}
