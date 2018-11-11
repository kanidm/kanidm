use actix::prelude::*;
use std::time::SystemTime;

#[macro_export]
macro_rules! audit_log {
    ($audit:expr, $($arg:tt)*) => ({
        use std::fmt;
        if cfg!(test) || cfg!(debug_assertions) {
            print!("DEBUG AUDIT -> ");
            println!($($arg)*)
        }
        $audit.raw_event(
            fmt::format(
                format_args!($($arg)*)
            )
        )
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditInner {
    name: String,
    time: SystemTime,
}

// This structure tracks and event lifecycle, and is eventually
// sent to the logging system where it's structured and written
// out to the current logging BE.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?
    events: Vec<AuditInner>,
}

// Allow us to be sent to the log subsystem
impl Message for AuditEvent {
    type Result = ();
}

impl AuditEvent {
    pub fn new() -> Self {
        AuditEvent { events: Vec::new() }
    }

    pub fn start_event(&mut self, name: &str) {
        self.events.push(AuditInner {
            name: String::from(name),
            time: SystemTime::now(),
        })
    }

    pub fn raw_event(&mut self, data: String) {
        self.events.push(AuditInner {
            name: data,
            time: SystemTime::now(),
        })
    }

    pub fn end_event(&mut self, name: &str) {
        self.events.push(AuditInner {
            name: String::from(name),
            time: SystemTime::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AuditEvent;

    // Create and remove. Perhaps add some core details?
    #[test]
    fn test_audit_simple() {
        let mut au = AuditEvent::new();
        au.start_event("test");
        au.end_event("test");
        let d = serde_json::to_string_pretty(&au).unwrap();
        println!("{}", d);
    }

    fn test_audit_nested_inner(au: &mut AuditEvent) {
        au.start_event("inner");
        au.end_event("inner");
    }

    // Test calling nested functions and getting the details added correctly?
    #[test]
    fn test_audit_nested() {
        let mut au = AuditEvent::new();
        au.start_event("test");
        test_audit_nested_inner(&mut au);
        au.end_event("test");
        let d = serde_json::to_string_pretty(&au).unwrap();
        println!("{}", d);
    }

    // Test failing to close an event
    #[test]
    fn test_audit_no_close() {
        let mut au = AuditEvent::new();
        au.start_event("test");
        au.start_event("inner");
        let d = serde_json::to_string_pretty(&au).unwrap();
        println!("{}", d);
    }

    // Test logging
    // specifically, logs should be sent to this struct and posted post-op
    // rather that "during" the operation. They should be structured!
    //
    // IMO these should be structured as json?
    #[test]
    fn test_audit_logging() {}
}
