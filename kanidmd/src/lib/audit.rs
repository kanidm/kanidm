use std::fmt;
// use std::ptr;
use std::cmp::Ordering;
use std::time::Duration;
use std::time::SystemTime;

use chrono::offset::Utc;
use chrono::DateTime;
use uuid::Uuid;

include!("./audit_loglevel.rs");

pub const AUDIT_LINE_SIZE: usize = 512;

#[derive(Debug, Serialize, Deserialize)]
#[repr(u32)]
pub enum LogTag {
    AdminError = 0x0000_0001,
    AdminWarning = 0x0000_0002,
    AdminInfo = 0x0000_0004,
    //          0x0000_0008,
    RequestError = 0x0000_0010,
    RequestWarning = 0x0000_0020,
    RequestInfo = 0x0000_0040,
    RequestTrace = 0x0000_0080,
    SecurityCritical = 0x0000_0100,
    SecurityInfo = 0x0000_0200,
    SecurityAccess = 0x0000_0400,
    //               0x0000_0800
    FilterError = 0x0000_1000,
    FilterWarning = 0x0000_2000,
    FilterInfo = 0x0000_4000,
    FilterTrace = 0x0000_8000,
    // 0x0001_0000 -> 0x0800_0000
    PerfOp = 0x1000_0000,
    PerfCoarse = 0x2000_0000,
    PerfTrace = 0x4000_0000,
    Trace = 0x8000_0000,
}

impl fmt::Display for LogTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LogTag::AdminError => write!(f, "admin::error 🚨"),
            LogTag::AdminWarning => write!(f, "admin::warning 🚧"),
            LogTag::AdminInfo => write!(f, "admin::info"),
            LogTag::RequestError => write!(f, "request::error 🚨"),
            LogTag::RequestWarning => write!(f, "request::warning"),
            LogTag::RequestInfo => write!(f, "request::info"),
            LogTag::RequestTrace => write!(f, "request::trace"),
            LogTag::SecurityCritical => write!(f, "security::critical 🐟"),
            LogTag::SecurityInfo => write!(f, "security::info 🔐"),
            LogTag::SecurityAccess => write!(f, "security::access 🔓"),
            LogTag::FilterError => write!(f, "filter::error 🚨"),
            LogTag::FilterWarning => write!(f, "filter::warning 🚧"),
            LogTag::FilterInfo => write!(f, "filter::info"),
            LogTag::FilterTrace => write!(f, "filter::trace"),
            LogTag::PerfOp | LogTag::PerfCoarse | LogTag::PerfTrace => write!(f, "perf::trace "),
            LogTag::Trace => write!(f, "trace::⌦"),
        }
    }
}

macro_rules! limmediate_warning {
    ($audit:expr, $($arg:tt)*) => ({
        use crate::audit::LogTag;
        if ($audit.level & LogTag::AdminWarning as u32) == LogTag::AdminWarning as u32 {
            eprint!($($arg)*)
        }
    })
}

/// This structure tracks and event lifecycle, and is eventually sent to the logging system where it's structured and written out to the current logging BE.
#[derive(Serialize)]
pub struct AuditScope {
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?
    #[serde(skip_serializing)]
    pub level: u32,
    pub uuid: Uuid,
}

impl AuditScope {
    pub fn new(name: &str, eventid: Uuid, level: Option<u32>) -> Self {
        let level = if cfg!(test) {
            LogLevel::FullTrace as u32
        } else {
            level.unwrap_or(LogLevel::Default as u32)
        };

        AuditScope {
            level,
            uuid: eventid,
        }
    }
}
