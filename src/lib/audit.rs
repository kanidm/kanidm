use actix::prelude::*;
use std::fmt;
use std::time::Duration;
use std::time::SystemTime;

use chrono::offset::Utc;
use chrono::DateTime;
use serde_json;

#[macro_export]
macro_rules! audit_log {
    ($audit:expr, $($arg:tt)*) => ({
        use std::fmt;
        if cfg!(test) || cfg!(debug_assertions) {
            print!("DEBUG AUDIT ({})-> ", $audit.id());
            println!($($arg)*)
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

macro_rules! audit_segment {
    ($au:expr, $fun:expr) => {{
        use std::time::Instant;

        let start = Instant::now();
        // start timer.
        // run fun with our derived audit event.
        let r = $fun();
        // end timer, and diff
        let end = Instant::now();
        let diff = end.duration_since(start);

        $au.set_duration(diff);

        // Return the result. Hope this works!
        r
    }};
}

#[derive(Serialize, Deserialize)]
enum AuditEvent {
    Log(AuditLog),
    Scope(AuditScope),
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditLog {
    time: String,
    name: String,
}

// This structure tracks and event lifecycle, and is eventually
// sent to the logging system where it's structured and written
// out to the current logging BE.
#[derive(Serialize, Deserialize)]
pub struct AuditScope {
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?
    time: String,
    name: String,
    duration: Option<Duration>,
    events: Vec<AuditEvent>,
}

// Allow us to be sent to the log subsystem
impl Message for AuditScope {
    type Result = ();
}

impl fmt::Display for AuditScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut _depth = 0;
        // write!(f, "{}: begin -> {}", self.time, self.name);
        let d = serde_json::to_string_pretty(self).unwrap();
        write!(f, "{}", d)
    }
}

impl AuditScope {
    pub fn new(name: &str) -> Self {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        AuditScope {
            time: datetime.to_rfc3339(),
            name: String::from(name),
            duration: None,
            events: Vec::new(),
        }
    }

    pub fn id(&self) -> &str {
        self.name.as_str()
    }

    pub fn set_duration(&mut self, diff: Duration) {
        self.duration = Some(diff);
    }

    // Given a new audit event, append it in.
    pub fn append_scope(&mut self, scope: AuditScope) {
        self.events.push(AuditEvent::Scope(scope))
    }

    pub fn log_event(&mut self, data: String) {
        let t_now = SystemTime::now();
        let datetime: DateTime<Utc> = t_now.into();

        self.events.push(AuditEvent::Log(AuditLog {
            time: datetime.to_rfc3339(),
            name: data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::AuditScope;

    // Create and remove. Perhaps add some core details?
    #[test]
    fn test_audit_simple() {
        let au = AuditScope::new("au");
        let d = serde_json::to_string_pretty(&au).unwrap();
        println!("{}", d);
    }

}
