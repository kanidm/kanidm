use actix::prelude::*;
use entry::Entry;

// Should the event Result have the log items?
#[derive(Debug)]
pub enum EventResult {
    Search { entries: Vec<Entry> },
    Modify,
    Delete,
    Create,
}

// At the top we get "event types" and they contain the needed
// actions, and a generic event component.

#[derive(Debug)]
pub struct SearchEvent {
    filter: (),
    class: (), // String
    // It could be better to box this later ...
    event: AuditEvent,
}

impl Message for SearchEvent {
    type Result = Result<EventResult, ()>;
}

impl SearchEvent {
    pub fn new() -> Self {
        SearchEvent {
            filter: (),
            class: (),
            event: AuditEvent {
                time_start: (),
                time_end: (),
            },
        }
    }
    // We need event -> some kind of json event string for logging
    // Could we turn the event from json back to an event for testing later?
}

#[derive(Debug)]
pub struct CreateEvent {
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    entries: Vec<Entry>,
    // It could be better to box this later ...
    event: AuditEvent,
}

impl Message for CreateEvent {
    type Result = Result<EventResult, ()>;
}

impl CreateEvent {
    pub fn new() -> Self {
        CreateEvent {
            entries: Vec::new(),
            event: AuditEvent {
                time_start: (),
                time_end: (),
            },
        }
    }
}

// This structure tracks and event lifecycle, and is eventually
// sent to the logging system where it's structured and written
// out to the current logging BE.
#[derive(Debug)]
pub struct AuditEvent {
    // vec of start/end points of various parts of the event?
    // We probably need some functions for this. Is there a way in rust
    // to automatically annotate line numbers of code?
    time_start: (),
    time_end: (),
}


