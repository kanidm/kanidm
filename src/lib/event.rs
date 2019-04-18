use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use crate::filter::{Filter, FilterInvalid};
use crate::proto_v1::Entry as ProtoEntry;
use crate::proto_v1::{
    AuthRequest, AuthResponse, AuthStatus, CreateRequest, DeleteRequest, ModifyRequest,
    OperationResponse, ReviveRecycledRequest, SearchRequest, SearchResponse,
};
// use error::OperationError;
use crate::error::OperationError;
use crate::modify::{ModifyInvalid, ModifyList};
use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};

// Only used for internal tests
#[cfg(test)]
use crate::proto_v1::SearchRecycledRequest;

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
    // TODO: Add list of attributes to request
}

impl SearchEvent {
    pub fn from_request(
        audit: &mut AuditScope,
        request: SearchRequest,
        qs: &QueryServerTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(audit, &request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                internal: false,
                filter: Filter::new_ignore_hidden(f),
            }),
            Err(e) => Err(e),
        }
    }

    // Just impersonate the account with no filter changes.
    pub fn new_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: filter,
        }
    }

    #[cfg(test)]
    pub fn from_rec_request(
        audit: &mut AuditScope,
        request: SearchRecycledRequest,
        qs: &QueryServerTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(audit, &request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                filter: Filter::new_recycled(f),
                internal: false,
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub fn new_rec_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: Filter::new_recycled(filter),
        }
    }

    #[cfg(test)]
    /* Impersonate an external request */
    pub fn new_ext_impersonate(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: false,
            filter: Filter::new_ignore_hidden(filter),
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            internal: true,
            filter: filter,
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
    pub fn from_request(
        audit: &mut AuditScope,
        request: CreateRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let rentries: Result<Vec<_>, _> = request
            .entries
            .iter()
            .map(|e| Entry::from(audit, e, qs))
            .collect();
        match rentries {
            Ok(entries) => Ok(CreateEvent {
                // From ProtoEntry -> Entry
                // What is the correct consuming iterator here? Can we
                // even do that?
                internal: false,
                entries: entries,
            }),
            Err(e) => Err(e),
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
        audit: &mut AuditScope,
        request: DeleteRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &request.filter, qs) {
            Ok(f) => Ok(DeleteEvent {
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
        audit: &mut AuditScope,
        request: ModifyRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &request.filter, qs) {
            Ok(f) => match ModifyList::from(audit, &request.modlist, qs) {
                Ok(m) => Ok(ModifyEvent {
                    filter: Filter::new_ignore_hidden(f),
                    modlist: m,
                    internal: false,
                }),
                Err(e) => Err(e),
            },

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
        audit: &mut AuditScope,
        request: ReviveRecycledRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &request.filter, qs) {
            Ok(f) => Ok(ReviveRecycledEvent {
                filter: Filter::new_recycled(f),
                internal: false,
            }),
            Err(e) => Err(e),
        }
    }
}
