use actix::prelude::*;
use std::fmt;
// use std::ptr;
use std::cmp::Ordering;
use std::time::Duration;
use std::time::SystemTime;

use chrono::offset::Utc;
use chrono::DateTime;
use uuid::adapter::HyphenatedRef;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub enum LogTag {
    AdminError,
    AdminWarning,
    AdminInfo,
    RequestError,
    Security,
    SecurityAccess,
    Filter,
    FilterError,
    FilterWarning,
    Trace,
}

impl fmt::Display for LogTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LogTag::AdminError => write!(f, "admin::error 🚨"),
            LogTag::AdminWarning => write!(f, "admin::warning 🚧"),
            LogTag::AdminInfo => write!(f, "admin::info"),
            LogTag::RequestError => write!(f, "request::error 🚨"),
            LogTag::Security => write!(f, "security 🔐"),
            LogTag::SecurityAccess => write!(f, "security::access 🔓"),
            LogTag::Filter => write!(f, "filter"),
            LogTag::FilterWarning => write!(f, "filter::warning 🚧"),
            LogTag::FilterError => write!(f, "filter::error 🚨"),
            LogTag::Trace => write!(f, "trace ⌦"),
        }
    }
}

macro_rules! audit_log {
    ($audit:expr, $($arg:tt)*) => ({
        use std::fmt;
        use crate::audit::LogTag;
        /*
        if cfg!(test) || cfg!(debug_assertions) {
            error!($($arg)*)
        }
        */
        $audit.log_event(
            LogTag::AdminError,
            fmt::format(
                format_args!($($arg)*)
            )
        )
    })
}

macro_rules! lqueue {
    ($au:expr, $tag:expr, $($arg:tt)*) => ({
        /*
        if cfg!(test) || cfg!(debug_assertions) {
            error!($($arg)*)
        }
        */
        use std::fmt;
        use crate::audit::LogTag;
        $au.log_event(
            $tag,
            fmt::format(
                format_args!($($arg)*)
            )
        )
    })
}

macro_rules! ltrace {
    ($au:expr, $($arg:tt)*) => ({
        if log_enabled!(log::Level::Debug) {
            lqueue!($au, LogTag::Trace, $($arg)*)
        }
    })
}

macro_rules! lfilter {
    ($au:expr, $($arg:tt)*) => ({
        if log_enabled!(log::Level::Info) {
            lqueue!($au, LogTag::Filter, $($arg)*)
        }
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
        if log_enabled!(log::Level::Warn) {
        lqueue!($au, LogTag::AdminWarning, $($arg)*)
        }
    })
}

macro_rules! ladmin_info {
    ($au:expr, $($arg:tt)*) => ({
        if log_enabled!(log::Level::Info) {
            lqueue!($au, LogTag::AdminInfo, $($arg)*)
        }
    })
}

macro_rules! lrequest_error {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::RequestError, $($arg)*)
    })
}

macro_rules! lsecurity {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::Security, $($arg)*)
    })
}

macro_rules! lsecurity_access {
    ($au:expr, $($arg:tt)*) => ({
        lqueue!($au, LogTag::SecurityAccess, $($arg)*)
    })
}

macro_rules! lperf_segment {
    ($au:expr, $id:expr, $fun:expr) => {{
        if log_enabled!(log::Level::Debug) {
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

macro_rules! try_audit {
    ($audit:ident, $result:expr, $logFormat:expr, $errorType:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                audit_log!($audit, $logFormat, e);
                return Err($errorType);
            }
        }
    };
    ($audit:ident, $result:expr, $logFormat:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                audit_log!($audit, $logFormat, e);
                return Err(e);
            }
        }
    };
    ($audit:ident, $result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                audit_log!($audit, "error @ {} {} -> {:?}", file!(), line!(), e);
                return Err(e);
            }
        }
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditLog {
    time: String,
    tag: LogTag,
    data: String,
}

#[derive(Debug, Serialize)]
pub struct PerfEvent {
    id: String,
    duration: Option<Duration>,
    contains: Vec<PerfEvent>,
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
            .expect("corrupted perf event")
            .clone();
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
            .expect("corrupted perf event")
            .clone();
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
    fn int_write_fmt(&self, parents: usize, uuid: &HyphenatedRef) {
        let mut prefix = String::new();
        prefix.push_str("[- perf::trace] ");
        let d = &self.duration;
        let df = d.as_secs() as f64 + d.subsec_nanos() as f64 * 1e-9;
        if parents > 0 {
            for _i in 0..parents {
                prefix.push_str("|   ");
            }
        };
        debug!(
            "{}|--> {} {2:.9} {3:.3}%",
            prefix, self.id, df, self.percent
        );
        self.contains
            .iter()
            .for_each(|pe| pe.int_write_fmt(parents + 1, uuid))
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
    uuid: Uuid,
    events: Vec<AuditLog>,
    perf: Vec<PerfEvent>,
    // active perf event
    #[serde(skip_serializing)]
    active_perf: Option<&'static mut PerfEvent>,
}

// unsafe impl Sync for AuditScope {}

// Allow us to be sent to the log subsystem
impl Message for AuditScope {
    type Result = ();
}

impl AuditScope {
    pub fn new(name: &str, eventid: Uuid) -> Self {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        AuditScope {
            uuid: eventid,
            events: vec![AuditLog {
                time: datetime.to_rfc3339(),
                tag: LogTag::AdminInfo,
                data: format!("start {}", name),
            }],
            perf: vec![],
            active_perf: None,
        }
    }

    pub fn write_log(self) {
        let uuid_ref = self.uuid.to_hyphenated_ref();
        error!("[- event::start] {}", uuid_ref);
        self.events.iter().for_each(|e| match e.tag {
            LogTag::AdminError | LogTag::RequestError | LogTag::FilterError => {
                error!("[{} {}] {}", e.time, e.tag, e.data)
            }
            LogTag::AdminWarning
            | LogTag::Security
            | LogTag::SecurityAccess
            | LogTag::FilterWarning => warn!("[{} {}] {}", e.time, e.tag, e.data),
            LogTag::AdminInfo | LogTag::Filter => info!("[{} {}] {}", e.time, e.tag, e.data),
            LogTag::Trace => debug!("[{} {}] {}", e.time, e.tag, e.data),
        });
        error!("[- event::end] {}", uuid_ref);
        // First, we pre-process all the perf events to order them
        let mut proc_perf: Vec<_> = self.perf.iter().map(|pe| pe.process()).collect();

        // We still sort them by duration.
        proc_perf.sort_unstable();

        // Now write the perf events
        proc_perf
            .iter()
            .for_each(|pe| pe.int_write_fmt(0, &uuid_ref));
        error!("[- perf::end] {}", uuid_ref);
    }

    pub fn log_event(&mut self, tag: LogTag, data: String) {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        self.events.push(AuditLog {
            time: datetime.to_rfc3339(),
            tag,
            data: data,
        })
    }

    pub(crate) unsafe fn new_perfevent(&mut self, id: &str) -> &'static mut PerfEvent {
        // Does an active event currently exist?
        if self.active_perf.is_none() {
            // No, we are a new event.
            self.perf.push(PerfEvent {
                id: id.to_string(),
                duration: None,
                contains: vec![],
                parent: None,
            });
            // Get a put ptr, we are now the active.
            let xref = self.perf.last_mut().expect("perf alloc failure?") as *mut PerfEvent;
            let mref = &mut (*xref);
            self.active_perf = Some(mref);
            // return the mut ptr.
            &mut (*xref)
        } else {
            // Yes, there is an active event.
            // get the currennt active ptr
            let xref = if let Some(ref mut iparent) = self.active_perf {
                iparent.contains.push(PerfEvent {
                    id: id.to_string(),
                    duration: None,
                    contains: vec![],
                    parent: None,
                });
                iparent.contains.last_mut().expect("perf alloc failure?") as *mut PerfEvent
            } else {
                panic!("Invalid parent state");
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
        let au = AuditScope::new("au", uuid::Uuid::new_v4());
        let d = serde_json::to_string_pretty(&au).expect("Json serialise failure");
        debug!("{}", d);
    }
}
