use actix::prelude::*;
use std::fmt;
// use std::ptr;
use std::time::Duration;
use std::time::SystemTime;

use chrono::offset::Utc;
use chrono::DateTime;
use uuid::Uuid;

#[macro_export]
macro_rules! audit_log {
    ($audit:expr, $($arg:tt)*) => ({
        use std::fmt;
        if cfg!(test) || cfg!(debug_assertions) {
            debug!($($arg)*)
            // } else {
        }
        $audit.log_event(
            fmt::format(
                format_args!($($arg)*)
            )
        )
    })
}

/*
 * This should be used as:
 * audit_segment(|au| {
 *     // au is the inner audit
 *     do your work
 *     audit_log!(au, ...?)
 *     nested_caller(&mut au, ...)
 * })
 */

macro_rules! lperf_segment {
    ($au:expr, $id:expr, $fun:expr) => {{
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

// Allow us to be sent to the log subsystem
impl Message for AuditScope {
    type Result = ();
}

impl fmt::Display for AuditScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut _depth = 0;
        // write!(f, "{}: begin -> {}", self.time, self.name);
        let d = serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", d)
    }
}

impl AuditScope {
    pub fn new(name: &str) -> Self {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        AuditScope {
            uuid: Uuid::new_v4(),
            events: vec![AuditLog {
                time: datetime.to_rfc3339(),
                data: format!("start {}", name),
            }],
            perf: vec![],
            active_perf: None,
        }
    }

    pub fn get_uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn log_event(&mut self, data: String) {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        self.events.push(AuditLog {
            time: datetime.to_rfc3339(),
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
        let au = AuditScope::new("au");
        let d = serde_json::to_string_pretty(&au).expect("Json serialise failure");
        println!("{}", d);
    }
}
