use super::filter::Filter;
use super::proto_v1::Entry as ProtoEntry;
use super::proto_v1::{CreateRequest, Response, SearchRequest, SearchResponse};
use actix::prelude::*;
use entry::Entry;
use error::OperationError;

// Should the event Result have the log items?
// FIXME: Remove seralising here - each type should
// have it's own result type!

#[derive(Debug)]
pub struct OpResult {}

impl OpResult {
    pub fn response(self) -> Response {
        Response {}
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
            entries: entries
                .iter()
                .map(|e| {
                    // FIXME: The issue here is this probably is applying transforms
                    // like access control ... May need to change.
                    e.into()
                })
                .collect(),
        }
    }

    // Consume self into a search response
    pub fn response(self) -> SearchResponse {
        SearchResponse {
            entries: self.entries,
        }
    }
}

// At the top we get "event types" and they contain the needed
// actions, and a generic event component.

#[derive(Debug)]
pub struct SearchEvent {
    pub internal: bool,
    pub filter: Filter,
    class: (), // String
}

impl Message for SearchEvent {
    type Result = Result<SearchResult, OperationError>;
}

impl SearchEvent {
    pub fn from_request(request: SearchRequest) -> Self {
        SearchEvent {
            internal: false,
            filter: request.filter,
            class: (),
        }
    }
}

// Represents the decoded entries from the protocol -> internal entry representation
// including information about the identity performing the request, and if the
// request is internal or not.
#[derive(Debug)]
pub struct CreateEvent {
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    pub entries: Vec<Entry>,
    /// Is the CreateEvent from an internal or external source?
    /// This may affect which plugins are run ...
    pub internal: bool,
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
            internal: false,
            entries: request.entries.iter().map(|e| Entry::from(e)).collect(),
        }
    }

    // Is this an internal only function?
    pub fn from_vec(entries: Vec<Entry>) -> Self {
        CreateEvent {
            internal: false,
            entries: entries,
        }
    }
}
