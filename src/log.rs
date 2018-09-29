use actix::prelude::*;

use super::event::Event;

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code

// We need to pass in config for this later

pub fn start() -> actix::Addr<EventLog> {
    SyncArbiter::start(1, move || {
        EventLog{}
    })
}


pub struct EventLog {
}

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
        println!("LOGEVENT: {}", event.msg );
    }
}

impl Handler<Event> for EventLog {
    type Result = ();

    fn handle(&mut self, event: Event, _: &mut SyncContext<Self>) -> Self::Result {
        println!("EVENT: {:?}", event)
    }
}



