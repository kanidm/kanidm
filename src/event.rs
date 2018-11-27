use super::filter::Filter;
use super::proto_v1::Entry as ProtoEntry;
use super::proto_v1::{CreateRequest, SearchRequest, SearchResponse, Response};
use actix::prelude::*;
use entry::Entry;
use error::OperationError;

// Should the event Result have the log items?
// FIXME: Remove seralising here - each type should
// have it's own result type!

#[derive(Debug)]
pub struct OpResult {
}

impl OpResult {
    pub fn response(self) -> Response {
        Response{}
    }
}

#[derive(Debug)]
pub struct SearchResult {
    entries: Vec<ProtoEntry>,
}

impl SearchResult {
    pub fn new(entries: Vec<Entry>) -> Self {
        SearchResult {
            // FIXME: Can we consume this iter?
            entries: entries.iter().map(|e| {
                // FIXME: The issue here is this probably is applying transforms
                // like access control ... May need to change.
                e.into()

            }).collect()
        }
    }

    // Consume self into a search response
    pub fn response(self) -> SearchResponse {
        SearchResponse {
            entries: self.entries
        }
    }
}

// At the top we get "event types" and they contain the needed
// actions, and a generic event component.

#[derive(Debug)]
pub struct SearchEvent {
    pub filter: Filter,
    class: (), // String
}

impl Message for SearchEvent {
    type Result = Result<SearchResult, OperationError>;
}

impl SearchEvent {
    pub fn from_request(request: SearchRequest) -> Self {
        SearchEvent {
            filter: request.filter,
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
    type Result = Result<OpResult, OperationError>;
}

// FIXME: Should this actually be in createEvent handler?
impl CreateEvent {
    pub fn from_request(request: CreateRequest) -> Self {
        CreateEvent {
            // From ProtoEntry -> Entry
            // What is the correct consuming iterator here? Can we
            // even do that?
            entries: request.entries.iter().map(|e|
                Entry::from(e)
            ).collect(),
        }
    }

    pub fn from_vec(entries: Vec<Entry>) -> Self {
        CreateEvent {
            entries: entries
        }
    }
}
