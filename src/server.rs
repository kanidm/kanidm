use actix::prelude::*;

use be::BackendActor;
use log::EventLog;
use entry::Entry;

// HACK HACK HACK remove duplicate code
// Helper for internal logging.
macro_rules! log_event {
    ($log_addr:expr, $($arg:tt)*) => ({
        use std::fmt;
        use log::LogEvent;
        $log_addr.do_send(
            LogEvent {
                msg: fmt::format(
                    format_args!($($arg)*)
                )
            }
        )
    })
}

pub fn start(
    log: actix::Addr<EventLog>,
    be: actix::Addr<BackendActor>
) -> actix::Addr<QueryServer>
{
    SyncArbiter::start(8, move || {
        QueryServer::new(log.clone(), be.clone())
    })
}

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code


pub struct QueryServer {
    log: actix::Addr<EventLog>,
    be: actix::Addr<BackendActor>,
}

impl QueryServer {
    pub fn new (log: actix::Addr<EventLog>, be: actix::Addr<BackendActor>) -> Self {
        log_event!(log, "Starting query worker ...");
        QueryServer {
            log: log,
            be: be,
        }
    }

    // Actually conduct a search request
    // This is the core of the server, as it processes the entire event
    // applies all parts required in order and more.
    pub fn search() -> Result<Vec<Entry>, ()> {
        Err(())
    }
}

impl Actor for QueryServer {
    type Context = SyncContext<Self>;
}

// What messages can we be sent. Basically this is all the possible
// inputs we *could* recieve.

// List All objects of type

pub struct ListClass {
    pub class_name: String,
}

impl Message for ListClass {
    type Result = Result<Vec<Entry>, ()>;
}

impl Handler<ListClass> for QueryServer {
    type Result = Result<Vec<Entry>, ()>;

    fn handle(&mut self, msg: ListClass, _: &mut Self::Context) -> Self::Result {
        log_event!(self.log, "Class list for: {}", msg.class_name.as_str());
        Err(())
    }
}

// Get objects by filter

// Auth requests? How do we structure these ...


