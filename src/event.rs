use super::filter::Filter;
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
    pub filter: Filter,
    class: (), // String
}

impl Message for SearchEvent {
    type Result = Result<EventResult, ()>;
}

impl SearchEvent {
    pub fn new(filter: Filter) -> Self {
        SearchEvent {
            filter: filter,
            class: (),
        }
    }
    // We need event -> some kind of json event string for logging
    // Could we turn the event from json back to an event for testing later?
}

#[derive(Debug)]
pub struct CreateEvent {
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    pub entries: Vec<Entry>,
    // It could be better to box this later ...
}

impl Message for CreateEvent {
    type Result = Result<EventResult, ()>;
}

impl CreateEvent {
    pub fn new(entries: Vec<Entry>) -> Self {
        CreateEvent { entries: entries }
    }
}
