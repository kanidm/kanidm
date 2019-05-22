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
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};

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

#[derive(Debug, Clone)]
pub enum EventOrigin {
    // External event, needs a UUID associated! Perhaps even an Entry/User to improve ACP checks?
    User(Entry<EntryValid, EntryCommitted>),
    // Probably will bypass access profiles in many cases ...
    Internal,
    // Not used yet, but indicates that this change or event was triggered by a replication
    // event - may not even be needed ...
    // Replication,
}

#[derive(Debug, Clone)]
pub struct Event {
    // The event's initiator aka origin source.
    // This importantly, is used for access control!
    pub origin: EventOrigin,
}

impl Event {
    pub fn from_ro_request(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        user_uuid: &str,
    ) -> Result<Self, OperationError> {
        // Do we need to check or load the entry from the user_uuid?
        // In the future, probably yes.
        //
        // For now, no.
        let e = try_audit!(audit, qs.internal_search_uuid(audit, user_uuid));

        Ok(Event {
            origin: EventOrigin::User(e),
        })
    }

    pub fn from_rw_request(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        user_uuid: &str,
    ) -> Result<Self, OperationError> {
        // Do we need to check or load the entry from the user_uuid?
        // In the future, probably yes.
        //
        // For now, no.
        let e = try_audit!(audit, qs.internal_search_uuid(audit, user_uuid));

        Ok(Event {
            origin: EventOrigin::User(e),
        })
    }

    pub fn from_internal() -> Self {
        Event {
            origin: EventOrigin::Internal,
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry(e: Entry<EntryValid, EntryCommitted>) -> Self {
        Event {
            origin: EventOrigin::User(e),
        }
    }

    #[cfg(test)]
    pub unsafe fn from_impersonate_entry_ser(e: &str) -> Self {
        let ei: Entry<EntryValid, EntryNew> =
            serde_json::from_str(e).expect("Failed to deserialise!");
        Self::from_impersonate_entry(unsafe { ei.to_valid_committed() })
    }

    pub fn from_impersonate(event: &Self) -> Self {
        // TODO: In the future, we could change some of this data
        // to reflect the fact we are infact impersonating the action
        // rather than the user explicitly requesting it. Could matter
        // to audits and logs to determine what happened.
        event.clone()
    }

    pub fn is_internal(&self) -> bool {
        match self.origin {
            EventOrigin::Internal => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct SearchEvent {
    pub event: Event,
    pub filter: Filter<FilterInvalid>,
    // TODO: Add list of attributes to request
}

impl SearchEvent {
    pub fn from_request(
        audit: &mut AuditScope,
        request: SearchRequest,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(audit, &request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                event: Event::from_ro_request(audit, qs, request.user_uuid.as_str())?,
                filter: f.to_ignore_hidden(),
            }),
            Err(e) => Err(e),
        }
    }

    pub fn is_internal(&self) -> bool {
        self.event.is_internal()
    }

    // Just impersonate the account with no filter changes.
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            filter: filter,
        }
    }

    pub fn new_impersonate(event: &Event, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_impersonate(event),
            filter: filter,
        }
    }

    #[cfg(test)]
    pub fn from_rec_request(
        audit: &mut AuditScope,
        request: SearchRecycledRequest,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(audit, &request.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                event: Event::from_ro_request(audit, qs, request.user_uuid.as_str())?,
                filter: f.to_recycled(),
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    /* Impersonate a request for recycled objects */
    pub unsafe fn new_rec_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            filter: filter.to_recycled(),
        }
    }

    #[cfg(test)]
    /* Impersonate an external request AKA filter ts + recycle */
    pub unsafe fn new_ext_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            filter: filter.to_ignore_hidden(),
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_internal(),
            filter: filter,
        }
    }
}

// Represents the decoded entries from the protocol -> internal entry representation
// including information about the identity performing the request, and if the
// request is internal or not.
#[derive(Debug)]
pub struct CreateEvent {
    pub event: Event,
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    pub entries: Vec<Entry<EntryInvalid, EntryNew>>,
    // Is the CreateEvent from an internal or external source?
    // This may affect which plugins are run ...
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
            .map(|e| Entry::from_proto_entry(audit, e, qs))
            .collect();
        match rentries {
            Ok(entries) => Ok(CreateEvent {
                // From ProtoEntry -> Entry
                // What is the correct consuming iterator here? Can we
                // even do that?
                event: Event::from_rw_request(audit, qs, request.user_uuid.as_str())?,
                entries: entries,
            }),
            Err(e) => Err(e),
        }
    }

    // Is this an internal only function?
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        entries: Vec<Entry<EntryInvalid, EntryNew>>,
    ) -> Self {
        CreateEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            entries: entries,
        }
    }

    pub fn new_internal(entries: Vec<Entry<EntryInvalid, EntryNew>>) -> Self {
        CreateEvent {
            event: Event::from_internal(),
            entries: entries,
        }
    }
}

#[derive(Debug)]
pub struct ExistsEvent {
    pub event: Event,
    pub filter: Filter<FilterInvalid>,
}

impl ExistsEvent {
    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            event: Event::from_internal(),
            filter: filter,
        }
    }
}

#[derive(Debug)]
pub struct DeleteEvent {
    pub event: Event,
    pub filter: Filter<FilterInvalid>,
}

impl DeleteEvent {
    pub fn from_request(
        audit: &mut AuditScope,
        request: DeleteRequest,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &request.filter, qs) {
            Ok(f) => Ok(DeleteEvent {
                event: Event::from_rw_request(audit, qs, request.user_uuid.as_str())?,
                filter: f.to_ignore_hidden(),
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            filter: filter,
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: Event::from_internal(),
            filter: filter,
        }
    }
}

#[derive(Debug)]
pub struct ModifyEvent {
    pub event: Event,
    pub filter: Filter<FilterInvalid>,
    pub modlist: ModifyList<ModifyInvalid>,
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
                    event: Event::from_rw_request(audit, qs, request.user_uuid.as_str())?,
                    filter: f.to_ignore_hidden(),
                    modlist: m,
                }),
                Err(e) => Err(e),
            },

            Err(e) => Err(e),
        }
    }

    pub fn new_internal(filter: Filter<FilterInvalid>, modlist: ModifyList<ModifyInvalid>) -> Self {
        ModifyEvent {
            event: Event::from_internal(),
            filter: filter,
            modlist: modlist,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: unsafe { Event::from_impersonate_entry_ser(e) },
            filter: filter,
            modlist: modlist,
        }
    }

    pub fn new_impersonate(
        event: &Event,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_impersonate(event),
            filter: filter,
            modlist: modlist,
        }
    }
}

#[derive(Debug)]
pub struct AuthEvent {
    // pub event: Event,
}

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
pub struct PurgeTombstoneEvent {
    pub event: Event,
}

impl Message for PurgeTombstoneEvent {
    type Result = ();
}

impl PurgeTombstoneEvent {
    pub fn new() -> Self {
        PurgeTombstoneEvent {
            event: Event::from_internal(),
        }
    }
}

#[derive(Debug)]
pub struct PurgeRecycledEvent {
    pub event: Event,
}

impl Message for PurgeRecycledEvent {
    type Result = ();
}

impl PurgeRecycledEvent {
    pub fn new() -> Self {
        PurgeRecycledEvent {
            event: Event::from_internal(),
        }
    }
}

#[derive(Debug)]
pub struct ReviveRecycledEvent {
    pub event: Event,
    pub filter: Filter<FilterInvalid>,
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
                event: Event::from_rw_request(audit, qs, request.user_uuid.as_str())?,
                filter: f.to_recycled(),
            }),
            Err(e) => Err(e),
        }
    }
}
