use super::filter::{Filter, FilterInvalid};
use super::proto_v1::Entry as ProtoEntry;
use super::proto_v1::{
    AuthRequest, AuthResponse, AuthStatus, CreateRequest, DeleteRequest, ModifyRequest,
    OperationResponse, ReviveRecycledRequest, SearchRecycledRequest, SearchRequest, SearchResponse,
};
use entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
// use error::OperationError;
use error::OperationError;
use modify::{ModifyInvalid, ModifyList};
use server::{QueryServerTransaction, QueryServerWriteTransaction};

use actix::prelude::*;

// Should the event Result have the log items?
// FIXME: Remove seralising here - each type should
// have it's own result type!

// TODO: Every event should have a uuid for logging analysis

#[derive(Debug)]
pub struct OpResult {}

impl OpResult {
    pub fn response(self) -> OperationResponse {
        OperationResponse {}
    }
}

#[derive(Debug)]
pub struct SearchResult {
    entries: Vec<ProtoEntry>,
}

impl SearchResult {
    pub fn new(entries: Vec<Entry<EntryValid, EntryCommitted>>) -> Self {
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
    pub filter: Filter<FilterInvalid>,
    // TODO: Remove this
    class: (), // String
               // TODO: Add list of attributes to request
}

impl SearchEvent {
    pub fn from_request(
        request: SearchRequest,
        qs: &QueryServerTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(&request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                internal: false,
                filter: Filter::new_ignore_hidden(f),
                class: (),
            }),
            Err(e) => Err(e),
        }
    }

    // Just impersonate the account with no filter changes.
    pub fn new_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: filter,
            class: (),
        }
    }

    pub fn from_rec_request(
        request: SearchRecycledRequest,
        qs: &QueryServerTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(&request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                filter: Filter::new_recycled(f),
                internal: false,
                class: (),
            }),
            Err(e) => Err(e),
        }
    }

    pub fn new_rec_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: Filter::new_recycled(filter),
            class: (),
        }
    }

    /* Impersonate an external request */
    pub fn new_ext_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: Filter::new_ignore_hidden(filter),
            class: (),
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: true,
            filter: filter,
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
    pub entries: Vec<Entry<EntryInvalid, EntryNew>>,
    /// Is the CreateEvent from an internal or external source?
    /// This may affect which plugins are run ...
    pub internal: bool,
}

// FIXME: Should this actually be in createEvent handler?
impl CreateEvent {
    pub fn from_request(request: CreateRequest) -> Self {
        CreateEvent {
            // From ProtoEntry -> Entry
            // What is the correct consuming iterator here? Can we
            // even do that?
            internal: false,
            // TODO: Transform references here.
            entries: request.entries.iter().map(|e| Entry::from(e)).collect(),
        }
    }

    // Is this an internal only function?
    #[cfg(test)]
    pub fn from_vec(entries: Vec<Entry<EntryInvalid, EntryNew>>) -> Self {
        CreateEvent {
            internal: false,
            entries: entries,
        }
    }

    pub fn new_internal(entries: Vec<Entry<EntryInvalid, EntryNew>>) -> Self {
        CreateEvent {
            internal: true,
            entries: entries,
        }
    }
}

#[derive(Debug)]
pub struct ExistsEvent {
    pub filter: Filter<FilterInvalid>,
    pub internal: bool,
}

impl ExistsEvent {
    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            filter: filter,
            internal: true,
        }
    }
}

#[derive(Debug)]
pub struct DeleteEvent {
    pub filter: Filter<FilterInvalid>,
    pub internal: bool,
}

impl DeleteEvent {
    pub fn from_request(
        request: DeleteRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(&request.filter, qs) {
            Ok(f) => Ok(DeleteEvent {
                // TODO: Transform references here.
                filter: Filter::new_ignore_hidden(f),
                internal: false,
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub fn from_filter(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            filter: filter,
            internal: false,
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            filter: filter,
            internal: true,
        }
    }
}

#[derive(Debug)]
pub struct ModifyEvent {
    pub filter: Filter<FilterInvalid>,
    pub modlist: ModifyList<ModifyInvalid>,
    pub internal: bool,
}

impl ModifyEvent {
    pub fn from_request(
        request: ModifyRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(&request.filter, qs) {
            Ok(f) => Ok(ModifyEvent {
                // TODO: Transform references here.
                filter: Filter::new_ignore_hidden(f),
                // TODO: Transform references here.
                modlist: ModifyList::from(&request.modlist),
                internal: false,
            }),

            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub fn from_filter(filter: Filter<FilterInvalid>, modlist: ModifyList<ModifyInvalid>) -> Self {
        ModifyEvent {
            filter: filter,
            modlist: modlist,
            internal: false,
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>, modlist: ModifyList<ModifyInvalid>) -> Self {
        ModifyEvent {
            filter: filter,
            modlist: modlist,
            internal: true,
        }
    }
}

#[derive(Debug)]
pub struct AuthEvent {}

impl AuthEvent {
    pub fn from_request(_request: AuthRequest) -> Self {
        AuthEvent {}
    }
}

pub struct AuthResult {}

impl AuthResult {
    pub fn response(self) -> AuthResponse {
        AuthResponse {
            status: AuthStatus::Begin(String::from("hello")),
        }
    }
}

// TODO: Are these part of the proto?

#[derive(Debug)]
pub struct PurgeTombstoneEvent {}

impl Message for PurgeTombstoneEvent {
    type Result = ();
}

impl PurgeTombstoneEvent {
    pub fn new() -> Self {
        PurgeTombstoneEvent {}
    }
}

#[derive(Debug)]
pub struct PurgeRecycledEvent {}

impl Message for PurgeRecycledEvent {
    type Result = ();
}

impl PurgeRecycledEvent {
    pub fn new() -> Self {
        PurgeRecycledEvent {}
    }
}

#[derive(Debug)]
pub struct ReviveRecycledEvent {
    pub filter: Filter<FilterInvalid>,
    pub internal: bool,
}

impl Message for ReviveRecycledEvent {
    type Result = ();
}

impl ReviveRecycledEvent {
    pub fn from_request(
        request: ReviveRecycledRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(&request.filter, qs) {
            Ok(f) => Ok(ReviveRecycledEvent {
                // TODO: Transform references here (in theory should be none though)
                filter: Filter::new_recycled(f),
                internal: false,
            }),
            Err(e) => Err(e),
        }
    }
}
