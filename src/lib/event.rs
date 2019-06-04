use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use crate::filter::{Filter, FilterValid};
use crate::proto_v1::Entry as ProtoEntry;
use crate::proto_v1::{
    AuthRequest, AuthResponse, AuthStatus, CreateRequest, DeleteRequest, ModifyRequest,
    OperationResponse, ReviveRecycledRequest, SearchRequest, SearchResponse,
};
// use error::OperationError;
use crate::error::OperationError;
use crate::modify::{ModifyList, ModifyValid};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
// Bring in schematransaction trait for validate
// use crate::schema::SchemaTransaction;

// Only used for internal tests
#[cfg(test)]
use crate::filter::FilterInvalid;
#[cfg(test)]
use crate::modify::ModifyInvalid;
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
        Self::from_impersonate_entry(ei.to_valid_committed())
    }

    pub fn from_impersonate(event: &Self) -> Self {
        // TODO: In the future, we could change some of this data
        // to reflect the fact we are infact impersonating the action
        // rather than the user explicitly requesting it. Could matter
        // to audits and logs to determine what happened.
        event.clone()
    }
}

#[derive(Debug)]
pub struct SearchEvent {
    pub event: Event,
    // This is the filter as we apply and process it.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
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
                // We do need to do this twice to account for the ignore_hidden
                // changes.
                filter: f
                    .clone()
                    .to_ignore_hidden()
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
            }),
            Err(e) => Err(e),
        }
    }

    // Just impersonate the account with no filter changes.
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry_ser(e),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Entry<EntryValid, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    pub fn new_impersonate(
        event: &Event,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate(event),
            filter: filter,
            filter_orig: filter_orig,
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
                filter: f
                    .clone()
                    .to_recycled()
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    /* Impersonate a request for recycled objects */
    pub unsafe fn new_rec_impersonate_entry(
        e: Entry<EntryValid, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().to_recycled().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    #[cfg(test)]
    /* Impersonate an external request AKA filter ts + recycle */
    pub unsafe fn new_ext_impersonate_entry(
        e: Entry<EntryValid, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().to_ignore_hidden().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_internal(),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        SearchEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
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
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
}

impl ExistsEvent {
    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        ExistsEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            event: Event::from_internal(),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }
}

#[derive(Debug)]
pub struct DeleteEvent {
    pub event: Event,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
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
                filter: f
                    .clone()
                    .to_ignore_hidden()
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
            }),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: Event::from_impersonate_entry_ser(e),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: Event::from_internal(),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        DeleteEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }
}

#[derive(Debug)]
pub struct ModifyEvent {
    pub event: Event,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub modlist: ModifyList<ModifyValid>,
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
                    filter: f
                        .clone()
                        .to_ignore_hidden()
                        .validate(qs.get_schema())
                        .map_err(|e| OperationError::SchemaViolation(e))?,
                    filter_orig: f
                        .validate(qs.get_schema())
                        .map_err(|e| OperationError::SchemaViolation(e))?,
                    modlist: m
                        .validate(qs.get_schema())
                        .map_err(|e| OperationError::SchemaViolation(e))?,
                }),
                Err(e) => Err(e),
            },

            Err(e) => Err(e),
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>, modlist: ModifyList<ModifyValid>) -> Self {
        ModifyEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            modlist: modlist,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_internal(),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
            modlist: modlist.to_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_impersonate_entry_ser(e),
            filter: filter.clone().to_valid(),
            filter_orig: filter.to_valid(),
            modlist: modlist.to_valid(),
        }
    }

    pub fn new_impersonate(
        event: &Event,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
        modlist: ModifyList<ModifyValid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_impersonate(event),
            filter: filter,
            filter_orig: filter_orig,
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
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // Unlike the others, because of how this works, we don't need the orig filter
    // to be retained, because the filter is the orig filter for this check.
    //
    // It will be duplicated into the modify event as it exists.
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
                filter: f
                    .to_recycled()
                    .validate(qs.get_schema())
                    .map_err(|e| OperationError::SchemaViolation(e))?,
            }),
            Err(e) => Err(e),
        }
    }
}
