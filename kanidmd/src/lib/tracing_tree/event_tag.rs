use std::convert::TryFrom;

#[derive(Debug, Clone, Copy)]
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

impl From<EventTag> for u64 {
    fn from(tag: EventTag) -> Self {
        use EventTag::*;
        match tag {
            AdminError => 0,
            AdminWarn => 1,
            AdminInfo => 2,
            RequestError => 3,
            RequestWarn => 4,
            RequestInfo => 5,
            RequestTrace => 6,
            SecurityCritical => 7,
            SecurityInfo => 8,
            SecurityAccess => 9,
            FilterError => 10,
            FilterWarn => 11,
            FilterInfo => 12,
            FilterTrace => 13,
            PerfTrace => 14,
        }
    }
}

impl TryFrom<u64> for EventTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        use EventTag::*;
        match value {
            0 => Ok(AdminError),
            1 => Ok(AdminWarn),
            2 => Ok(AdminInfo),
            3 => Ok(RequestError),
            4 => Ok(RequestWarn),
            5 => Ok(RequestInfo),
            6 => Ok(RequestTrace),
            7 => Ok(SecurityCritical),
            8 => Ok(SecurityInfo),
            9 => Ok(SecurityAccess),
            10 => Ok(FilterError),
            11 => Ok(FilterWarn),
            12 => Ok(FilterInfo),
            13 => Ok(FilterTrace),
            14 => Ok(PerfTrace),
            _ => Err(()),
        }
    }
}
