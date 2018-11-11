use actix::prelude::*;
use serde_json;

use super::audit::AuditEvent;

// Helper for internal logging.
#[macro_export]
macro_rules! log_event {
    ($log_addr:expr, $($arg:tt)*) => ({
        use log::LogEvent;
        use std::fmt;
        $log_addr.do_send(
            LogEvent {
                msg: fmt::format(
                    format_args!($($arg)*)
                )
            }
        )
    })
}

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code

// We need to pass in config for this later
// Or we need to pass in the settings for it IE level and dest?
// Is there an efficent way to set a log level filter in the macros
// so that we don't msg unless it's the correct level?
// Do we need config in the log macro?

pub fn start() -> actix::Addr<EventLog> {
    SyncArbiter::start(1, move || EventLog {})
}

pub struct EventLog {}

impl Actor for EventLog {
    type Context = SyncContext<Self>;
}

// What messages can we be sent. Basically this is all the possible
// inputs we *could* recieve.

// Add a macro for easy msg write

pub struct LogEvent {
    pub msg: String,
}

impl Message for LogEvent {
    type Result = ();
}

impl Handler<LogEvent> for EventLog {
    type Result = ();

    fn handle(&mut self, event: LogEvent, _: &mut SyncContext<Self>) -> Self::Result {
        println!("LOGEVENT: {}", event.msg);
    }
}

impl Handler<AuditEvent> for EventLog {
    type Result = ();

    fn handle(&mut self, event: AuditEvent, _: &mut SyncContext<Self>) -> Self::Result {
        let d = serde_json::to_string_pretty(&event).unwrap();
        println!("AUDIT: {}", d);
    }
}

/*
impl Handler<Event> for EventLog {
    type Result = ();

    fn handle(&mut self, event: Event, _: &mut SyncContext<Self>) -> Self::Result {
        println!("EVENT: {:?}", event)
    }
}
*/
