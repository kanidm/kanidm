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

macro_rules! lqueue {
    ($au:expr, $tag:expr, $($arg:tt)*) => ({
        use crate::audit::{LogTag, AUDIT_LINE_SIZE};
        if cfg!(test) {
            println!($($arg)*)
        }
        if ($au.level & $tag as u32) == $tag as u32 {
            use std::fmt;
            // We have to buffer the string to over-alloc it.
            let mut output = String::with_capacity(AUDIT_LINE_SIZE);
            match fmt::write(&mut output, format_args!($($arg)*)) {
                Ok(_) => $au.log_event($tag, output),
                Err(e) => {
                    $au.log_event(
                        LogTag::AdminError,
                        format!("CRITICAL UNABLE TO WRITE LOG EVENT - {:?}", e)
                    )
                }
            }
        }
    })
}

macro_rules! ltrace {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::Trace, $($arg)*)
    })
}

macro_rules! lfilter {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::FilterTrace, $($arg)*)
    })
}

macro_rules! lfilter_info {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::FilterInfo, $($arg)*)
    })
}

/*
macro_rules! lfilter_warning {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::FilterWarning, $($arg)*)
    })
}
*/

macro_rules! lfilter_error {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::FilterError, $($arg)*)
    })
}

macro_rules! ladmin_error {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::AdminError, $($arg)*)
    })
}

macro_rules! ladmin_warning {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::AdminWarning, $($arg)*)
    })
}

macro_rules! ladmin_info {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::AdminInfo, $($arg)*)
    })
}

macro_rules! lrequest_error {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::RequestError, $($arg)*)
    })
}

macro_rules! lsecurity {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::SecurityInfo, $($arg)*)
    })
}

macro_rules! lsecurity_critical {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::SecurityCritical, $($arg)*)
    })
}

macro_rules! lsecurity_access {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::SecurityAccess, $($arg)*)
    })
}

macro_rules! lperf_op_segment {
    ($au:expr, $id:expr, $fun:expr) => {{
        use crate::audit::LogTag;
        lperf_tag_segment!($au, $id, LogTag::PerfOp, $fun)
    }};
}

macro_rules! lperf_trace_segment {
    ($au:expr, $id:expr, $fun:expr) => {{
        use crate::audit::LogTag;
        lperf_tag_segment!($au, $id, LogTag::PerfTrace, $fun)
    }};
}

macro_rules! lperf_segment {
    ($au:expr, $id:expr, $fun:expr) => {{
        use crate::audit::LogTag;
        lperf_tag_segment!($au, $id, LogTag::PerfCoarse, $fun)
    }};
}

macro_rules! lperf_tag_segment {
    ($au:expr, $id:expr, $tag:expr, $fun:expr) => {{
        if ($au.level & $tag as u32) == $tag as u32 {
            use std::time::Instant;

            // start timer.
            let start = Instant::now();

            // Create a new perf event - this sets
            // us as the current active, and the parent
            // correctly.
            let pe = unsafe { $au.new_perfevent($id) };

            // fun run time
            let r = $fun();
            // end timer, and diff
            let end = Instant::now();
            let diff = end.duration_since(start);

            // Now we are done, we put our parent back as
            // the active.
            unsafe { $au.end_perfevent(pe, diff) };

            // Return the result. Hope this works!
            r
        } else {
            $fun()
        }
    }};
}

/*
macro_rules! limmediate_error {
    ($au:expr, $($arg:tt)*) => ({
        use crate::audit::LogTag;
        if ($au.level & LogTag::AdminError as u32) == LogTag::AdminError as u32 {
            eprintln!($($arg)*)
        }
    })
}
*/

macro_rules! limmediate_warning {
    ($au:expr, $($arg:tt)*) => ({
        use crate::audit::LogTag;
        if ($au.level & LogTag::AdminWarning as u32) == LogTag::AdminWarning as u32 {
            eprint!($($arg)*)
        }
    })
}

/*
macro_rules! try_audit {
    ($audit:ident, $result:expr, $logFormat:expr, $errorType:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                ladmin_error!($audit, $logFormat, e);

                return Err($errorType);
            }
        }
    };
    ($audit:ident, $result:expr, $logFormat:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                ladmin_error!($audit, $logFormat, e);
                return Err(e);
            }
        }
    };
    ($audit:ident, $result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                ladmin_error!($audit, "error @ {} {} -> {:?}", file!(), line!(), e);
                return Err(e);
            }
        }
    };
}
*/

#[derive(Debug, Serialize, Deserialize)]
struct AuditLog {
    tag: LogTag,
    data: String,
}

#[derive(Debug, Serialize)]
pub struct PerfEvent {
    id: String,
    duration: Option<Duration>,
    #[allow(clippy::vec_box)]
    contains: Vec<Box<PerfEvent>>,
    #[serde(skip_serializing)]
    parent: Option<&'static mut PerfEvent>,
}

impl PerfEvent {
    fn process_inner(&self, opd: &Duration) -> PerfProcessed {
        let mut contains: Vec<_> = self
            .contains
            .iter()
            .map(|pe| pe.process_inner(opd))
            .collect();
        contains.sort_unstable();
        let duration = self
            .duration
            .as_ref()
            .copied()
            .unwrap_or_else(|| Duration::new(0, 0));
        let percent = (duration.as_secs_f64() / opd.as_secs_f64()) * 100.0;
        PerfProcessed {
            duration,
            id: self.id.clone(),
            percent,
            contains,
        }
    }

    fn process(&self) -> PerfProcessed {
        let duration = self
            .duration
            .as_ref()
            .copied()
            .unwrap_or_else(|| Duration::new(0, 0));
        let mut contains: Vec<_> = self
            .contains
            .iter()
            .map(|pe| pe.process_inner(&duration))
            .collect();
        contains.sort_unstable();
        PerfProcessed {
            duration,
            id: self.id.clone(),
            percent: 100.0,
            contains,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PerfProcessed {
    duration: Duration,
    id: String,
    percent: f64,
    contains: Vec<PerfProcessed>,
}

impl Ord for PerfProcessed {
    fn cmp(&self, other: &Self) -> Ordering {
        other.duration.cmp(&self.duration)
    }
}

impl PartialOrd for PerfProcessed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PerfProcessed {}

impl PartialEq for PerfProcessed {
    fn eq(&self, other: &Self) -> bool {
        self.duration == other.duration
    }
}

/*
 *     event
 *     |--> another_event
 *     |--> another_event
 *     |    |--> another layer
 *     |    |--> another layer
 *     |    |    |-->  the abyss layer
 *     |    |--> another layer
 */
impl PerfProcessed {
    fn int_write_fmt(&self, parents: usize, header: &str) {
        eprint!("{}", header);
        // let mut prefix = header.to_string();
        let d = &self.duration;
        let df = d.as_secs() as f64 + d.subsec_nanos() as f64 * 1e-9;
        if parents > 0 {
            for _i in 0..parents {
                // prefix.push_str("|   ");
                eprint!("|   ");
            }
        };
        eprintln!("|--> {} {1:.9} {2:.3}%", self.id, df, self.percent);
        /*
        eprintln!(
            "{}|--> {} {2:.9} {3:.3}%",
            prefix, self.id, df, self.percent
        );
        */
        self.contains
            .iter()
            .for_each(|pe| pe.int_write_fmt(parents + 1, header))
    }
}

// This structure tracks and event lifecycle, and is eventually
// sent to the logging system where it's structured and written
// out to the current logging BE.
#[derive(Serialize)]
pub struct AuditScope {
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?
    #[serde(skip_serializing)]
    pub level: u32,
    uuid: Uuid,
    events: Vec<AuditLog>,
    #[allow(clippy::vec_box)]
    perf: Vec<Box<PerfEvent>>,
    // active perf event
    #[serde(skip_serializing)]
    active_perf: Option<&'static mut PerfEvent>,
}

impl AuditScope {
    pub fn new(name: &str, eventid: Uuid, level: Option<u32>) -> Self {
        let level = if cfg!(test) {
            LogLevel::FullTrace as u32
        } else {
            level.unwrap_or(LogLevel::Default as u32)
        };

        // Try to reduce re-allocs by pre-allocating the amount we will likely need.
        let mut events = if level == LogLevel::FullTrace as u32 {
            Vec::with_capacity(512)
        } else if (level & LogLevel::PerfFull as u32) == LogLevel::PerfFull as u32 {
            Vec::with_capacity(256)
        } else if (level & LogLevel::PerfBasic as u32) == LogLevel::PerfBasic as u32
            || (level & LogLevel::Verbose as u32) == LogLevel::Verbose as u32
        {
            Vec::with_capacity(64)
        } else if level == LogLevel::Quiet as u32 {
            Vec::with_capacity(0)
        } else {
            // (level & LogTag::Filter as u32) == LogTag::Filter as u32
            // (level & LogTag::Default as u32) == LogTag::Default as u32
            Vec::with_capacity(16)
        };

        if (level & LogTag::AdminInfo as u32) == LogTag::AdminInfo as u32 {
            let t_now = SystemTime::now();
            let datetime: DateTime<Utc> = t_now.into();
            events.push(AuditLog {
                tag: LogTag::AdminInfo,
                data: format!("{} {}", name, datetime.to_rfc3339()),
            })
        }

        AuditScope {
            level,
            uuid: eventid,
            events,
            perf: vec![],
            active_perf: None,
        }
    }

    pub fn write_log(self) {
        let uuid_ref = self.uuid.to_hyphenated_ref();
        self.events
            .iter()
            .for_each(|e| eprintln!("[{} {}] {}", uuid_ref, e.tag, e.data));

        // First, we pre-process all the perf events to order them
        let mut proc_perf: Vec<_> = self.perf.iter().map(|pe| pe.process()).collect();

        // We still sort them by duration.
        proc_perf.sort_unstable();

        let header = format!("[{} perf::trace] ", uuid_ref);
        // Now write the perf events
        proc_perf
            .iter()
            .for_each(|pe| pe.int_write_fmt(0, header.as_str()));
        if log_enabled!(log::Level::Debug) {
            eprintln!("[{} perf::trace] -", uuid_ref);
        }
    }

    pub fn log_event(&mut self, tag: LogTag, data: String) {
        // let t_now = SystemTime::now();
        // let datetime: DateTime<Utc> = t_now.into();

        self.events.push(AuditLog {
            // time: datetime.to_rfc3339(),
            tag,
            data,
        })
    }

    pub(crate) unsafe fn new_perfevent(&mut self, id: &str) -> &'static mut PerfEvent {
        // Does an active event currently exist?
        if self.active_perf.is_none() {
            // No, we are a new event.
            self.perf.push(Box::new(PerfEvent {
                id: id.to_string(),
                duration: None,
                contains: vec![],
                parent: None,
            }));
            // Get a our ptr, we are now the active.
            let idx = self.perf.len() - 1;
            let xref = self
                .perf
                // Get the box
                .get_unchecked_mut(idx)
                // Now the mut ptr to the inner of hte box
                .as_mut() as *mut PerfEvent;
            let mref = &mut (*xref);
            self.active_perf = Some(mref);
            // return the mut ptr.
            &mut (*xref)
        } else {
            // Yes, there is an active event.
            // get the currennt active ptr
            let xref = if let Some(ref mut iparent) = self.active_perf {
                iparent.contains.push(Box::new(PerfEvent {
                    id: id.to_string(),
                    duration: None,
                    contains: vec![],
                    parent: None,
                }));

                let idx = iparent.contains.len() - 1;
                iparent.contains.get_unchecked_mut(idx).as_mut() as *mut PerfEvent
            } else {
                #[allow(clippy::unreachable)]
                unreachable!("Invalid parent state");
            };
            // Alloc in the vec, set parnt to active, then get a mut pointer
            // to ourself, then set ourself as the active.
            (*xref).parent = Some(&mut (*xref));
            std::mem::swap(&mut (*xref).parent, &mut self.active_perf);
            // return the mut ptr.
            &mut (*xref)
        }
    }

    pub(crate) unsafe fn end_perfevent(&mut self, pe: &'static mut PerfEvent, diff: Duration) {
        // assert that we are the current active, else we have active children
        // that are unclosed!
        // ???

        // We are done, put the duration into the pe.
        pe.duration = Some(diff);
        // put parent back as the active.
        std::mem::swap(&mut pe.parent, &mut self.active_perf);
        // And none the PE
        pe.parent = None;
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;

    // Create and remove. Perhaps add some core details?
    #[test]
    fn test_audit_simple() {
        let au = AuditScope::new("au", uuid::Uuid::new_v4(), None);
        let d = serde_json::to_string_pretty(&au).expect("Json serialise failure");
        debug!("{}", d);
    }
}
