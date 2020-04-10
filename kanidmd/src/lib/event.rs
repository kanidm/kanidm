use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntryReduced, EntrySealed};
use crate::filter::{Filter, FilterInvalid, FilterValid};
use crate::schema::SchemaTransaction;
use crate::value::PartialValue;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::ModifyList as ProtoModifyList;
use kanidm_proto::v1::{
    AuthCredential, AuthResponse, AuthState, AuthStep, SearchResponse, UserAuthToken,
    WhoamiResponse,
};
// use error::OperationError;
use crate::modify::{ModifyInvalid, ModifyList, ModifyValid};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use kanidm_proto::v1::OperationError;

use crate::actors::v1_read::{
    AuthMessage, InternalSearchMessage, InternalSearchRecycledMessage, SearchMessage,
};
use crate::actors::v1_write::{CreateMessage, DeleteMessage, ModifyMessage};
// Bring in schematransaction trait for validate
// use crate::schema::SchemaTransaction;

use actix::prelude::*;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug)]
pub struct SearchResult {
    entries: Vec<ProtoEntry>,
}

impl SearchResult {
    pub fn new(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        entries: Vec<Entry<EntryReduced, EntryCommitted>>,
    ) -> Result<Self, OperationError> {
        let entries: Result<_, _> = entries
            .iter()
            .map(|e| {
                // All the needed transforms for this result are done
                // in search_ext. This is just an entry -> protoentry
                // step.
                e.to_pe(audit, qs)
            })
            .collect();
        Ok(SearchResult { entries: entries? })
    }

    // Consume self into a search response
    pub fn response(self) -> SearchResponse {
        SearchResponse {
            entries: self.entries,
        }
    }

    // Consume into the array of entries, used in the json proto
    pub fn into_proto_array(self) -> Vec<ProtoEntry> {
        self.entries
    }
}

// At the top we get "event types" and they contain the needed
// actions, and a generic event component.

#[derive(Debug, Clone, PartialEq)]
pub enum EventOriginId {
    // Time stamp of the originating event.
    // The uuid of the originiating user
    User(Uuid),
    Internal,
}

impl From<&EventOrigin> for EventOriginId {
    fn from(event: &EventOrigin) -> Self {
        match event {
            EventOrigin::Internal => EventOriginId::Internal,
            EventOrigin::User(e) => EventOriginId::User(e.get_uuid().clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventOrigin {
    // External event, needs a UUID associated! Perhaps even an Entry/User to improve ACP checks?
    User(Entry<EntrySealed, EntryCommitted>),
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
        let u = try_audit!(
            audit,
            Uuid::parse_str(user_uuid).map_err(|_| OperationError::InvalidUuid)
        );

        let e = try_audit!(audit, qs.internal_search_uuid(audit, &u));

        Ok(Event {
            origin: EventOrigin::User(e),
        })
    }

    pub fn from_ro_uat(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        uat: Option<UserAuthToken>,
    ) -> Result<Self, OperationError> {
        audit_log!(audit, "from_ro_uat -> {:?}", uat);
        let uat = uat.ok_or(OperationError::NotAuthenticated)?;
        let u = try_audit!(
            audit,
            Uuid::parse_str(uat.uuid.as_str()).map_err(|_| OperationError::InvalidUuid)
        );

        let e = try_audit!(audit, qs.internal_search_uuid(audit, &u));
        // TODO #64: Now apply claims from the uat into the Entry
        // to allow filtering.

        Ok(Event {
            origin: EventOrigin::User(e),
        })
    }

    pub fn from_rw_uat(
        audit: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        uat: Option<UserAuthToken>,
    ) -> Result<Self, OperationError> {
        audit_log!(audit, "from_rw_uat -> {:?}", uat);
        let uat = uat.ok_or(OperationError::NotAuthenticated)?;
        let u = try_audit!(
            audit,
            Uuid::parse_str(uat.uuid.as_str()).map_err(|_| OperationError::InvalidUuid)
        );

        let e = try_audit!(audit, qs.internal_search_uuid(audit, &u));
        // TODO #64: Now apply claims from the uat into the Entry
        // to allow filtering.

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
        let u = try_audit!(
            audit,
            Uuid::parse_str(user_uuid).map_err(|_| OperationError::InvalidUuid)
        );
        let e = try_audit!(audit, qs.internal_search_uuid(audit, &u));

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
    pub fn from_impersonate_entry(e: Entry<EntrySealed, EntryCommitted>) -> Self {
        Event {
            origin: EventOrigin::User(e),
        }
    }

    #[cfg(test)]
    pub unsafe fn from_impersonate_entry_ser(e: &str) -> Self {
        let ei: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(e);
        Self::from_impersonate_entry(ei.into_sealed_committed())
    }

    pub fn from_impersonate(event: &Self) -> Self {
        // TODO #64 ?: In the future, we could change some of this data
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

    pub fn get_uuid(&self) -> Option<&Uuid> {
        match &self.origin {
            EventOrigin::Internal => None,
            EventOrigin::User(e) => Some(e.get_uuid()),
        }
    }
}

#[derive(Debug)]
pub struct SearchEvent {
    pub event: Event,
    // This is the filter as we apply and process it.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub attrs: Option<BTreeSet<String>>,
}

impl SearchEvent {
    pub fn from_message(
        audit: &mut AuditScope,
        msg: SearchMessage,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_ro(audit, &msg.req.filter, qs) {
            Ok(f) => Ok(SearchEvent {
                event: Event::from_ro_uat(audit, qs, msg.uat)?,
                // We do need to do this twice to account for the ignore_hidden
                // changes.
                filter: f
                    .clone()
                    .into_ignore_hidden()
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
                // We can't get this from the SearchMessage because it's annoying with the
                // current macro design.
                attrs: None,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn from_internal_message(
        audit: &mut AuditScope,
        msg: InternalSearchMessage,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<String>> = msg.attrs.map(|vs| {
            vs.into_iter()
                .filter_map(|a| qs.get_schema().normalise_attr_if_exists(a.as_str()))
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                return Err(OperationError::EmptyRequest);
            }
        }

        Ok(SearchEvent {
            event: Event::from_ro_uat(audit, qs, msg.uat)?,
            // We do need to do this twice to account for the ignore_hidden
            // changes.
            filter: msg
                .filter
                .clone()
                .into_ignore_hidden()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: msg
                .filter
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            attrs: r_attrs,
        })
    }

    pub fn from_internal_recycle_message(
        audit: &mut AuditScope,
        msg: InternalSearchRecycledMessage,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<String>> = msg.attrs.map(|vs| {
            vs.into_iter()
                .filter_map(|a| qs.get_schema().normalise_attr_if_exists(a.as_str()))
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                return Err(OperationError::EmptyRequest);
            }
        }

        Ok(SearchEvent {
            event: Event::from_ro_uat(audit, qs, msg.uat)?,
            filter: msg
                .filter
                .clone()
                .into_recycled()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: msg
                .filter
                .into_recycled()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            attrs: r_attrs,
        })
    }

    pub fn from_whoami_request(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        Ok(SearchEvent {
            event: Event::from_ro_uat(audit, qs, uat)?,
            filter: filter!(f_self())
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: filter_all!(f_self())
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            // TODO: Should we limit this?
            attrs: None,
        })
    }

    pub fn from_target_uuid_request(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        target_uuid: Uuid,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        Ok(SearchEvent {
            event: Event::from_ro_uat(audit, qs, uat)?,
            filter: filter!(f_eq("uuid", PartialValue::new_uuid(target_uuid)))
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)))
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            attrs: None,
        })
    }

    // Just impersonate the account with no filter changes.
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry_ser(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    pub fn new_impersonate(
        event: &Event,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate(event),
            filter,
            filter_orig,
            attrs: None,
        }
    }

    #[cfg(test)]
    /* Impersonate a request for recycled objects */
    pub unsafe fn new_rec_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().into_recycled().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    #[cfg(test)]
    /* Impersonate an external request AKA filter ts + recycle */
    pub unsafe fn new_ext_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().into_ignore_hidden().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            event: Event::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        SearchEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            attrs: None,
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
    pub entries: Vec<Entry<EntryInit, EntryNew>>,
    // Is the CreateEvent from an internal or external source?
    // This may affect which plugins are run ...
}

impl CreateEvent {
    pub fn from_message(
        audit: &mut AuditScope,
        msg: CreateMessage,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let rentries: Result<Vec<_>, _> = msg
            .req
            .entries
            .iter()
            .map(|e| Entry::from_proto_entry(audit, e, qs))
            .collect();
        match rentries {
            Ok(entries) => Ok(CreateEvent {
                // From ProtoEntry -> Entry
                // What is the correct consuming iterator here? Can we
                // even do that?
                event: Event::from_rw_uat(audit, qs, msg.uat)?,
                entries,
            }),
            Err(e) => Err(e),
        }
    }

    // Is this an internal only function?
    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(
        e: &str,
        entries: Vec<Entry<EntryInit, EntryNew>>,
    ) -> Self {
        CreateEvent {
            event: Event::from_impersonate_entry_ser(e),
            entries,
        }
    }

    pub fn new_internal(entries: Vec<Entry<EntryInit, EntryNew>>) -> Self {
        CreateEvent {
            event: Event::from_internal(),
            entries,
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
    #[allow(dead_code)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            event: Event::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
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
    pub fn from_message(
        audit: &mut AuditScope,
        msg: DeleteMessage,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &msg.req.filter, qs) {
            Ok(f) => Ok(DeleteEvent {
                event: Event::from_rw_uat(audit, qs, msg.uat)?,
                filter: f
                    .clone()
                    .into_ignore_hidden()
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(DeleteEvent {
            event: Event::from_rw_uat(audit, qs, uat)?,
            filter: filter
                .clone()
                .into_ignore_hidden()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: filter
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
        })
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        DeleteEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry_ser(e: &str, filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: Event::from_impersonate_entry_ser(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            event: Event::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
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
    pub fn from_message(
        audit: &mut AuditScope,
        msg: ModifyMessage,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        match Filter::from_rw(audit, &msg.req.filter, qs) {
            Ok(f) => match ModifyList::from(audit, &msg.req.modlist, qs) {
                Ok(m) => Ok(ModifyEvent {
                    event: Event::from_rw_uat(audit, qs, msg.uat)?,
                    filter: f
                        .clone()
                        .into_ignore_hidden()
                        .validate(qs.get_schema())
                        .map_err(OperationError::SchemaViolation)?,
                    filter_orig: f
                        .validate(qs.get_schema())
                        .map_err(OperationError::SchemaViolation)?,
                    modlist: m
                        .validate(qs.get_schema())
                        .map_err(OperationError::SchemaViolation)?,
                }),
                Err(e) => Err(e),
            },

            Err(e) => Err(e),
        }
    }

    pub fn from_parts(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        target_uuid: Uuid,
        proto_ml: ProtoModifyList,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        match ModifyList::from(audit, &proto_ml, qs) {
            Ok(m) => Ok(ModifyEvent {
                event: Event::from_rw_uat(audit, qs, uat)?,
                filter: f
                    .clone()
                    .into_ignore_hidden()
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
                filter_orig: f
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
                modlist: m
                    .validate(qs.get_schema())
                    .map_err(OperationError::SchemaViolation)?,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn from_internal_parts(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        target_uuid: Uuid,
        ml: ModifyList<ModifyInvalid>,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        Ok(ModifyEvent {
            event: Event::from_rw_uat(audit, qs, uat)?,
            filter: f
                .clone()
                .into_ignore_hidden()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: f
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            modlist: ml
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
        })
    }

    pub fn from_target_uuid_attr_purge(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        target_uuid: Uuid,
        attr: String,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let ml = ModifyList::new_purge(attr.as_str());
        let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);
        Ok(ModifyEvent {
            event: Event::from_rw_uat(audit, qs, uat)?,
            filter: f
                .clone()
                .into_ignore_hidden()
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            filter_orig: f
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
            modlist: ml
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)?,
        })
    }

    pub fn new_internal(filter: Filter<FilterValid>, modlist: ModifyList<ModifyValid>) -> Self {
        ModifyEvent {
            event: Event::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            modlist,
        }
    }

    #[cfg(test)]
    pub unsafe fn new_internal_invalid(
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
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
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
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
            filter,
            filter_orig,
            modlist,
        }
    }
}

#[derive(Debug)]
pub struct AuthEventStepInit {
    pub name: String,
    pub appid: Option<String>,
}

#[derive(Debug)]
pub struct AuthEventStepCreds {
    pub sessionid: Uuid,
    pub creds: Vec<AuthCredential>,
}

#[derive(Debug)]
pub enum AuthEventStep {
    Init(AuthEventStepInit),
    Creds(AuthEventStepCreds),
}

impl AuthEventStep {
    fn from_authstep(aus: AuthStep, sid: Option<Uuid>) -> Result<Self, OperationError> {
        match aus {
            AuthStep::Init(name, appid) => {
                if sid.is_some() {
                    Err(OperationError::InvalidAuthState(
                        "session id present in init".to_string(),
                    ))
                } else {
                    Ok(AuthEventStep::Init(AuthEventStepInit { name, appid }))
                }
            }
            AuthStep::Creds(creds) => match sid {
                Some(ssid) => Ok(AuthEventStep::Creds(AuthEventStepCreds {
                    sessionid: ssid,
                    creds,
                })),
                None => Err(OperationError::InvalidAuthState(
                    "session id not present in cred".to_string(),
                )),
            },
        }
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: "anonymous".to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEventStep::Init(AuthEventStepInit {
            name: name.to_string(),
            appid: None,
        })
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEventStep::Creds(AuthEventStepCreds {
            sessionid: sid,
            creds: vec![AuthCredential::Anonymous],
        })
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEventStep::Creds(AuthEventStepCreds {
            sessionid: sid,
            creds: vec![AuthCredential::Password(pw.to_string())],
        })
    }
}

#[derive(Debug)]
pub struct AuthEvent {
    pub event: Option<Event>,
    pub step: AuthEventStep,
    // pub sessionid: Option<Uuid>,
}

impl AuthEvent {
    pub fn from_message(msg: AuthMessage) -> Result<Self, OperationError> {
        Ok(AuthEvent {
            event: None,
            step: AuthEventStep::from_authstep(msg.req.step, msg.sessionid)?,
        })
    }

    #[cfg(test)]
    pub fn anonymous_init() -> Self {
        AuthEvent {
            event: None,
            step: AuthEventStep::anonymous_init(),
        }
    }

    #[cfg(test)]
    pub fn named_init(name: &str) -> Self {
        AuthEvent {
            event: None,
            step: AuthEventStep::named_init(name),
        }
    }

    #[cfg(test)]
    pub fn cred_step_anonymous(sid: Uuid) -> Self {
        AuthEvent {
            event: None,
            step: AuthEventStep::cred_step_anonymous(sid),
        }
    }

    #[cfg(test)]
    pub fn cred_step_password(sid: Uuid, pw: &str) -> Self {
        AuthEvent {
            event: None,
            step: AuthEventStep::cred_step_password(sid, pw),
        }
    }
}

// Probably should be a struct with the session id present.
#[derive(Debug)]
pub struct AuthResult {
    pub sessionid: Uuid,
    pub state: AuthState,
}

impl AuthResult {
    pub fn response(self) -> AuthResponse {
        AuthResponse {
            sessionid: self.sessionid,
            state: self.state,
        }
    }
}

pub struct WhoamiResult {
    youare: ProtoEntry,
    uat: UserAuthToken,
}

impl WhoamiResult {
    pub fn new(
        audit: &mut AuditScope,
        qs: &QueryServerReadTransaction,
        e: Entry<EntryReduced, EntryCommitted>,
        uat: UserAuthToken,
    ) -> Result<Self, OperationError> {
        Ok(WhoamiResult {
            youare: e.to_pe(audit, qs)?,
            uat,
        })
    }

    pub fn response(self) -> WhoamiResponse {
        WhoamiResponse {
            youare: self.youare,
            uat: self.uat,
        }
    }
}

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
    pub fn from_parts(
        audit: &mut AuditScope,
        uat: Option<UserAuthToken>,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        Ok(ReviveRecycledEvent {
            event: Event::from_rw_uat(audit, qs, uat)?,
            filter: filter
                .into_recycled()
                .validate(qs.get_schema())
                .map_err(|e| OperationError::SchemaViolation(e))?,
        })
    }

    #[cfg(test)]
    pub unsafe fn new_impersonate_entry(
        e: Entry<EntrySealed, EntryCommitted>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        ReviveRecycledEvent {
            event: Event::from_impersonate_entry(e),
            filter: filter.into_valid(),
        }
    }
}
