use actix::prelude::*;

use crate::audit::AuditScope;

// Helper for internal logging.
// Should only be used at startup/shutdown
#[macro_export]
macro_rules! log_event {
    ($log_addr:expr, $($arg:tt)*) => ({
        use crate::async_log::LogEvent;
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

    /*
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(1 << 31);
    }
    */
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
        info!("logevent: {}", event.msg);
    }
}

impl Handler<AuditScope> for EventLog {
    type Result = ();

    fn handle(&mut self, event: AuditScope, _: &mut SyncContext<Self>) -> Self::Result {
        info!("audit: {}", event);
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
