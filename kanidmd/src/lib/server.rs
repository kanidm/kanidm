//! `server` contains the query server, which is the main high level construction
//! to coordinate queries and operations in the server.

// This is really only used for long lived, high level types that need clone
// that otherwise can't be cloned. Think Mutex.
use async_std::task;
use hashbrown::HashMap;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, SemaphorePermit};
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::be::{Backend, BackendReadTransaction, BackendTransaction, BackendWriteTransaction};

use crate::access::{
    AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlSearch,
    AccessControls, AccessControlsReadTransaction, AccessControlsTransaction,
    AccessControlsWriteTransaction,
};
// We use so many, we just import them all ...
use crate::constants::*;
use crate::entry::{
    Entry, EntryCommitted, EntryInit, EntryInvalid, EntryNew, EntryReduced, EntrySealed,
};
use crate::event::{
    CreateEvent, DeleteEvent, Event, EventOrigin, ExistsEvent, ModifyEvent, ReviveRecycledEvent,
    SearchEvent,
};
use crate::filter::{Filter, FilterInvalid, FilterValid};
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::plugins::Plugins;
use crate::repl::cid::Cid;
use crate::schema::{
    Schema, SchemaAttribute, SchemaClass, SchemaReadTransaction, SchemaTransaction,
    SchemaWriteTransaction,
};
use crate::value::{PartialValue, SyntaxType, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError, SchemaError};
use smartstring::alias::String as AttrString;

type EntrySealedCommitted = Entry<EntrySealed, EntryCommitted>;
type EntryInvalidCommitted = Entry<EntryInvalid, EntryCommitted>;
type EntryTuple = (EntrySealedCommitted, EntryInvalidCommitted);

lazy_static! {
    static ref PVCLASS_ATTRIBUTETYPE: PartialValue = PartialValue::new_class("attributetype");
    static ref PVCLASS_CLASSTYPE: PartialValue = PartialValue::new_class("classtype");
    static ref PVCLASS_TOMBSTONE: PartialValue = PartialValue::new_class("tombstone");
    static ref PVCLASS_RECYCLED: PartialValue = PartialValue::new_class("recycled");
    static ref PVCLASS_ACS: PartialValue = PartialValue::new_class("access_control_search");
    static ref PVCLASS_ACD: PartialValue = PartialValue::new_class("access_control_delete");
    static ref PVCLASS_ACM: PartialValue = PartialValue::new_class("access_control_modify");
    static ref PVCLASS_ACC: PartialValue = PartialValue::new_class("access_control_create");
    static ref PVCLASS_ACP: PartialValue = PartialValue::new_class("access_control_profile");
    static ref PVACP_ENABLE_FALSE: PartialValue = PartialValue::new_bool(false);
}

#[derive(Clone)]
pub struct QueryServer {
    s_uuid: Uuid,
    d_uuid: Uuid,
    be: Backend,
    schema: Arc<Schema>,
    accesscontrols: Arc<AccessControls>,
    db_tickets: Arc<Semaphore>,
    write_ticket: Arc<Semaphore>,
}

pub struct QueryServerReadTransaction<'a> {
    be_txn: BackendReadTransaction<'a>,
    // Anything else? In the future, we'll need to have a schema transaction
    // type, maybe others?
    schema: SchemaReadTransaction,
    accesscontrols: AccessControlsReadTransaction,
    _db_ticket: SemaphorePermit<'a>,
}

pub struct QueryServerWriteTransaction<'a> {
    committed: bool,
    d_uuid: Uuid,
    cid: Cid,
    be_txn: BackendWriteTransaction<'a>,
    schema: SchemaWriteTransaction<'a>,
    accesscontrols: AccessControlsWriteTransaction<'a>,
    // We store a set of flags that indicate we need a reload of
    // schema or acp, which is tested by checking the classes of the
    // changing content.
    changed_schema: Cell<bool>,
    changed_acp: Cell<bool>,
    _db_ticket: SemaphorePermit<'a>,
    _write_ticket: SemaphorePermit<'a>,
}

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code
/// The `QueryServerTransaction` trait provides a set of common read only operations to be
/// shared between [`QueryServerReadTransaction`] and [`QueryServerWriteTransaction`]s.
///
/// These operations tend to be high level constructions, generally different types of searches
/// that are capable of taking different types of parameters and applying access controls or not,
/// impersonating accounts, or bypassing these via internal searches.
///
/// [`QueryServerReadTransaction`]: struct.QueryServerReadTransaction.html
/// [`QueryServerWriteTransaction`]: struct.QueryServerWriteTransaction.html
pub trait QueryServerTransaction {
    type BackendTransactionType: BackendTransaction;
    fn get_be_txn(&self) -> &Self::BackendTransactionType;

    type SchemaTransactionType: SchemaTransaction;
    fn get_schema(&self) -> &Self::SchemaTransactionType;

    type AccessControlsTransactionType: AccessControlsTransaction;
    fn get_accesscontrols(&self) -> &Self::AccessControlsTransactionType;

    /// Conduct a search and apply access controls to yield a set of entries that
    /// have been reduced to the set of user visible avas. Note that if you provide
    /// a `SearchEvent` for the internal user, this query will fail. It is invalid for
    /// the [`access`] module to attempt to reduce avas for internal searches, and you
    /// should use [`fn search`] instead.
    ///
    /// [`SearchEvent`]: ../event/struct.SearchEvent.html
    /// [`access`]: ../access/index.html
    /// [`fn search`]: trait.QueryServerTransaction.html#method.search
    fn search_ext(
        &self,
        au: &mut AuditScope,
        se: &SearchEvent,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        lperf_segment!(au, "server::search_ext", || {
            /*
             * This just wraps search, but it's for the external interface
             * so as a result it also reduces the entry set's attributes at
             * the end.
             */
            let entries = self.search(au, se)?;

            let access = self.get_accesscontrols();
            access
                .search_filter_entry_attributes(au, se, entries)
                .map_err(|e| {
                    // Log and fail if something went wrong.
                    ladmin_error!(au, "Failed to filter entry attributes {:?}", e);
                    e
                })
            // This now returns the reduced vec.
        })
    }

    fn search(
        &self,
        au: &mut AuditScope,
        se: &SearchEvent,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_segment!(au, "server::search", || {
            if se.event.is_internal() {
                ltrace!(au, "search: internal filter -> {:?}", se.filter);
            } else {
                lsecurity!(au, "search initiator: -> {}", se.event);
                ladmin_info!(au, "search: external filter -> {:?}", se.filter);
            }

            // This is an important security step because it prevents us from
            // performing un-indexed searches on attr's that don't exist in the
            // server. This is why ExtensibleObject can only take schema that
            // exists in the server, not arbitrary attr names.
            //
            // This normalises and validates in a single step.
            //
            // NOTE: Filters are validated in event conversion.

            let be_txn = self.get_be_txn();
            let idxmeta = be_txn.get_idxmeta_ref();
            // Now resolve all references and indexes.
            let vfr = lperf_trace_segment!(au, "server::search<filter_resolve>", || {
                se.filter.resolve(&se.event, Some(idxmeta))
            })
            .map_err(|e| {
                ladmin_error!(au, "search filter resolve failure {:?}", e);
                e
            })?;

            let lims = se.get_limits();

            // NOTE: We currently can't build search plugins due to the inability to hand
            // the QS wr/ro to the plugin trait. However, there shouldn't be a need for search
            // plugis, because all data transforms should be in the write path.

            let res = self
                .get_be_txn()
                .search(au, lims, &vfr)
                .map(|r| r)
                .map_err(|e| {
                    ladmin_error!(au, "backend failure -> {:?}", e);
                    OperationError::Backend
                })?;

            // Apply ACP before we let the plugins "have at it".
            // WARNING; for external searches this is NOT the only
            // ACP application. There is a second application to reduce the
            // attribute set on the entries!
            //
            let access = self.get_accesscontrols();
            access.search_filter_entries(au, se, res).map_err(|e| {
                ladmin_error!(au, "Unable to access filter entries {:?}", e);
                e
            })
        })
    }

    fn exists(&self, au: &mut AuditScope, ee: &ExistsEvent) -> Result<bool, OperationError> {
        lperf_segment!(au, "server::exists", || {
            let be_txn = self.get_be_txn();
            let idxmeta = be_txn.get_idxmeta_ref();
            let vfr = ee.filter.resolve(&ee.event, Some(idxmeta)).map_err(|e| {
                ladmin_error!(au, "Failed to resolve filter {:?}", e);
                e
            })?;

            let lims = ee.get_limits();

            self.get_be_txn().exists(au, &lims, &vfr).map_err(|e| {
                ladmin_error!(au, "backend failure -> {:?}", e);
                OperationError::Backend
            })
        })
    }

    // Should this actually be names_to_uuids and we do batches?
    //  In the initial design "no", we can always write a batched
    //  interface later.
    //
    // The main question is if we need association between the name and
    // the request uuid - if we do, we need singular. If we don't, we can
    // just do the batching.
    //
    // Filter conversion likely needs 1:1, due to and/or conversions
    // but create/mod likely doesn't due to the nature of the attributes.
    //
    // In the end, singular is the simple and correct option, so lets do
    // that first, and we can add batched (and cache!) later.
    //
    // Remember, we don't care if the name is invalid, because search
    // will validate/normalise the filter we construct for us. COOL!
    fn name_to_uuid(&self, audit: &mut AuditScope, name: &str) -> Result<Uuid, OperationError> {
        // Is it just a uuid?
        Uuid::parse_str(name).or_else(|_| {
            let lname = name.to_lowercase();
            self.get_be_txn()
                .name2uuid(audit, lname.as_str())?
                .ok_or(OperationError::NoMatchingEntries)
        })
    }

    fn uuid_to_spn(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError> {
        let r = self.get_be_txn().uuid2spn(audit, uuid)?;

        match &r {
            Some(n) => {
                debug_assert!(n.is_spn() || n.is_iname());
            }
            None => {}
        }
        Ok(r)
    }

    fn uuid_to_rdn(&self, audit: &mut AuditScope, uuid: &Uuid) -> Result<String, OperationError> {
        // If we have a some, pass it on, else unwrap into a default.
        self.get_be_txn()
            .uuid2rdn(audit, uuid)
            .map(|v| v.unwrap_or_else(|| format!("uuid={}", uuid.to_hyphenated_ref())))
    }

    // From internal, generate an exists event and dispatch
    fn internal_exists(
        &self,
        au: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<bool, OperationError> {
        lperf_segment!(au, "server::internal_exists", || {
            // Check the filter
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            // Build an exists event
            let ee = ExistsEvent::new_internal(f_valid);
            // Submit it
            self.exists(au, &ee)
        })
    }

    fn internal_search(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_segment!(audit, "server::internal_search", || {
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let se = SearchEvent::new_internal(f_valid);
            self.search(audit, &se)
        })
    }

    fn impersonate_search_valid(
        &self,
        audit: &mut AuditScope,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_segment!(audit, "server::internal_search_valid", || {
            let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
            self.search(audit, &se)
        })
    }

    // this applys ACP to filter result entries.
    fn impersonate_search_ext_valid(
        &self,
        audit: &mut AuditScope,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        self.search_ext(audit, &se)
    }

    // Who they are will go here
    fn impersonate_search(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        self.impersonate_search_valid(audit, f_valid, f_intent_valid, event)
    }

    fn impersonate_search_ext(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        lperf_segment!(audit, "server::internal_search_ext_valid", || {
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let f_intent_valid = filter_intent
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            self.impersonate_search_ext_valid(audit, f_valid, f_intent_valid, event)
        })
    }

    // Get a single entry by it's UUID. This is heavily relied on for internal
    // server operations, especially in login and acp checks for acp.
    fn internal_search_uuid(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Entry<EntrySealed, EntryCommitted>, OperationError> {
        lperf_segment!(audit, "server::internal_search_uuid", || {
            let filter = filter!(f_eq("uuid", PartialValue::new_uuid(*uuid)));
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let se = SearchEvent::new_internal(f_valid);
            let res = self.search(audit, &se);
            match res {
                Ok(vs) => {
                    if vs.len() > 1 {
                        return Err(OperationError::NoMatchingEntries);
                    }
                    vs.into_iter()
                        .next()
                        .ok_or(OperationError::NoMatchingEntries)
                }
                Err(e) => Err(e),
            }
        })
    }

    fn impersonate_search_ext_uuid(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        event: &Event,
    ) -> Result<Entry<EntryReduced, EntryCommitted>, OperationError> {
        lperf_segment!(audit, "server::internal_search_ext_uuid", || {
            let filter_intent = filter_all!(f_eq("uuid", PartialValue::new_uuid(*uuid)));
            let filter = filter!(f_eq("uuid", PartialValue::new_uuid(*uuid)));
            let res = self.impersonate_search_ext(audit, filter, filter_intent, event);
            match res {
                Ok(vs) => {
                    if vs.len() > 1 {
                        return Err(OperationError::NoMatchingEntries);
                    }
                    vs.into_iter()
                        .next()
                        .ok_or(OperationError::NoMatchingEntries)
                }
                Err(e) => Err(e),
            }
        })
    }

    fn impersonate_search_uuid(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
        event: &Event,
    ) -> Result<Entry<EntrySealed, EntryCommitted>, OperationError> {
        lperf_segment!(audit, "server::internal_search_uuid", || {
            let filter_intent = filter_all!(f_eq("uuid", PartialValue::new_uuid(*uuid)));
            let filter = filter!(f_eq("uuid", PartialValue::new_uuid(*uuid)));
            let res = self.impersonate_search(audit, filter, filter_intent, event);
            match res {
                Ok(vs) => {
                    if vs.len() > 1 {
                        return Err(OperationError::NoMatchingEntries);
                    }
                    vs.into_iter()
                        .next()
                        .ok_or(OperationError::NoMatchingEntries)
                }
                Err(e) => Err(e),
            }
        })
    }

    /// Do a schema aware conversion from a String:String to String:Value for modification
    /// present.
    fn clone_value(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        value: &str,
    ) -> Result<Value, OperationError> {
        let schema = self.get_schema();

        // Should this actually be a fn of Value - no - I think that introduces issues with the
        // monomorphisation of the trait for transactions, so we should have this here.

        // Lookup the attr
        match schema.get_attributes().get(attr) {
            Some(schema_a) => {
                match schema_a.syntax {
                    SyntaxType::UTF8STRING => Ok(Value::new_utf8(value.to_string())),
                    SyntaxType::UTF8STRING_INSENSITIVE => Ok(Value::new_iutf8(value)),
                    SyntaxType::UTF8STRING_INAME => Ok(Value::new_iname(value)),
                    SyntaxType::BOOLEAN => Value::new_bools(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid boolean syntax".to_string())),
                    SyntaxType::SYNTAX_ID => Value::new_syntaxs(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())),
                    SyntaxType::INDEX_ID => Value::new_indexs(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Index syntax".to_string())),
                    SyntaxType::UUID => {
                        // It's a uuid - we do NOT check for existance, because that
                        // could be revealing or disclosing - it is up to acp to assert
                        // if we can see the value or not, and it's not up to us to
                        // assert the filter value exists.
                        Value::new_uuids(value)
                            .or_else(|| {
                                // it's not a uuid, try to resolve it.
                                // if the value is NOT found, we map to "does not exist" to allow
                                // the value to continue being evaluated, which of course, will fail
                                // all subsequent filter tests because it ... well, doesn't exist.
                                let un = self
                                    .name_to_uuid(audit, value)
                                    .unwrap_or_else(|_| *UUID_DOES_NOT_EXIST);
                                Some(Value::new_uuid(un))
                            })
                            // I think this is unreachable due to how the .or_else works.
                            .ok_or_else(|| OperationError::InvalidAttribute("Invalid UUID syntax".to_string()))
                    }
                    SyntaxType::REFERENCE_UUID => {
                        // See comments above.
                        Value::new_refer_s(value)
                            .or_else(|| {
                                let un = self
                                    .name_to_uuid(audit, value)
                                    .unwrap_or_else(|_| *UUID_DOES_NOT_EXIST);
                                Some(Value::new_refer(un))
                            })
                            // I think this is unreachable due to how the .or_else works.
                            .ok_or_else(|| OperationError::InvalidAttribute("Invalid Reference syntax".to_string()))
                    }
                    SyntaxType::JSON_FILTER => Value::new_json_filter(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Filter syntax".to_string())),
                    SyntaxType::CREDENTIAL => Err(OperationError::InvalidAttribute("Credentials can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::RADIUS_UTF8STRING => Err(OperationError::InvalidAttribute("Radius secrets can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SSHKEY => Err(OperationError::InvalidAttribute("SSH public keys can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SERVICE_PRINCIPLE_NAME => Err(OperationError::InvalidAttribute("SPNs are generated and not able to be set.".to_string())),
                    SyntaxType::UINT32 => Value::new_uint32_str(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid uint32 syntax".to_string())),
                    SyntaxType::CID => Err(OperationError::InvalidAttribute("CIDs are generated and not able to be set.".to_string())),
                    SyntaxType::NSUNIQUEID => Ok(Value::new_nsuniqueid_s(value)),
                    SyntaxType::DATETIME => Value::new_datetime_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid DateTime (rfc3339) syntax".to_string())),
                }
            }
            None => {
                // No attribute of this name exists - fail fast, there is no point to
                // proceed, as nothing can be satisfied.
                Err(OperationError::InvalidAttributeName(attr.to_string()))
            }
        }
    }

    fn clone_partialvalue(
        &self,
        audit: &mut AuditScope,
        attr: &str,
        value: &str,
    ) -> Result<PartialValue, OperationError> {
        let schema = self.get_schema();

        // Lookup the attr
        match schema.get_attributes().get(attr) {
            Some(schema_a) => {
                match schema_a.syntax {
                    SyntaxType::UTF8STRING => Ok(PartialValue::new_utf8(value.to_string())),
                    SyntaxType::UTF8STRING_INSENSITIVE => Ok(PartialValue::new_iutf8(value)),
                    SyntaxType::UTF8STRING_INAME => Ok(PartialValue::new_iname(value)),
                    SyntaxType::BOOLEAN => PartialValue::new_bools(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid boolean syntax".to_string())
                    }),
                    SyntaxType::SYNTAX_ID => PartialValue::new_syntaxs(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())
                    }),
                    SyntaxType::INDEX_ID => PartialValue::new_indexs(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid Index syntax".to_string())
                    }),
                    SyntaxType::UUID => {
                        PartialValue::new_uuids(value)
                            .or_else(|| {
                                // it's not a uuid, try to resolve it.
                                // if the value is NOT found, we map to "does not exist" to allow
                                // the value to continue being evaluated, which of course, will fail
                                // all subsequent filter tests because it ... well, doesn't exist.
                                let un = self
                                    .name_to_uuid(audit, value)
                                    .unwrap_or_else(|_| *UUID_DOES_NOT_EXIST);
                                Some(PartialValue::new_uuid(un))
                            })
                            // I think this is unreachable due to how the .or_else works.
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute("Invalid UUID syntax".to_string())
                            })
                    }
                    SyntaxType::REFERENCE_UUID => {
                        // See comments above.
                        PartialValue::new_refer_s(value)
                            .or_else(|| {
                                let un = self
                                    .name_to_uuid(audit, value)
                                    .unwrap_or_else(|_| *UUID_DOES_NOT_EXIST);
                                Some(PartialValue::new_refer(un))
                            })
                            // I think this is unreachable due to how the .or_else works.
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid Reference syntax".to_string(),
                                )
                            })
                    }
                    SyntaxType::JSON_FILTER => {
                        PartialValue::new_json_filter(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid Filter syntax".to_string())
                        })
                    }
                    SyntaxType::CREDENTIAL => Ok(PartialValue::new_credential_tag(value)),
                    SyntaxType::RADIUS_UTF8STRING => Ok(PartialValue::new_radius_string()),
                    SyntaxType::SSHKEY => Ok(PartialValue::new_sshkey_tag_s(value)),
                    SyntaxType::SERVICE_PRINCIPLE_NAME => PartialValue::new_spn_s(value)
                        .ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid spn syntax".to_string())
                        }),
                    SyntaxType::UINT32 => PartialValue::new_uint32_str(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid uint32 syntax".to_string())
                    }),
                    SyntaxType::CID => PartialValue::new_cid_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute("Invalid cid syntax".to_string())
                    }),
                    SyntaxType::NSUNIQUEID => Ok(PartialValue::new_nsuniqueid_s(value)),
                    SyntaxType::DATETIME => PartialValue::new_datetime_s(value).ok_or_else(|| {
                        OperationError::InvalidAttribute(
                            "Invalid DateTime (rfc3339) syntax".to_string(),
                        )
                    }),
                }
            }
            None => {
                // No attribute of this name exists - fail fast, there is no point to
                // proceed, as nothing can be satisfied.
                Err(OperationError::InvalidAttributeName(attr.to_string()))
            }
        }
    }

    // In the opposite direction, we can resolve values for presentation
    fn resolve_value(
        &self,
        audit: &mut AuditScope,
        value: &Value,
    ) -> Result<String, OperationError> {
        // Are we a reference type? Try and resolve.
        if let Some(ur) = value.to_ref_uuid() {
            let nv = self.uuid_to_spn(audit, ur)?;
            return match nv {
                Some(v) => Ok(v.to_proto_string_clone()),
                None => Ok(value.to_proto_string_clone()),
            };
        }

        // Not? Okay, do the to string.
        Ok(value.to_proto_string_clone())
    }

    fn resolve_value_ldap(
        &self,
        audit: &mut AuditScope,
        value: &Value,
        basedn: &str,
    ) -> Result<String, OperationError> {
        if let Some(ur) = value.to_ref_uuid() {
            let rdn = self.uuid_to_rdn(audit, ur)?;
            Ok(format!("{},{}", rdn, basedn))
        } else if value.is_sshkey() {
            value
                .get_sshkey()
                .map(|s| s.to_string())
                .ok_or_else(|| OperationError::InvalidValueState)
        } else {
            // Not? Okay, do the to string.
            Ok(value.to_proto_string_clone())
        }
    }

    // This is a prebaked helper to get the domain name for related modules.
    // in the future we could make this cache the value to avoid entry lookups.
    fn get_domain_name(&self, audit: &mut AuditScope) -> Result<String, OperationError> {
        self.internal_search_uuid(audit, &UUID_DOMAIN_INFO)
            .and_then(|e| {
                e.get_ava_single_str("domain_name")
                    .map(|s| s.to_string())
                    .ok_or(OperationError::InvalidEntryState)
            })
            .map_err(|e| {
                ladmin_error!(audit, "Error getting domain name -> {:?}", e);
                e
            })
    }
}

// Actually conduct a search request
// This is the core of the server, as it processes the entire event
// applies all parts required in order and more.
impl<'a> QueryServerTransaction for QueryServerReadTransaction<'a> {
    type BackendTransactionType = BackendReadTransaction<'a>;

    fn get_be_txn(&self) -> &BackendReadTransaction<'a> {
        &self.be_txn
    }

    type SchemaTransactionType = SchemaReadTransaction;

    fn get_schema(&self) -> &SchemaReadTransaction {
        &self.schema
    }

    type AccessControlsTransactionType = AccessControlsReadTransaction;

    fn get_accesscontrols(&self) -> &AccessControlsReadTransaction {
        &self.accesscontrols
    }
}

impl<'a> QueryServerReadTransaction<'a> {
    // Verify the data content of the server is as expected. This will probably
    // call various functions for validation, including possibly plugin
    // verifications.
    fn verify(&self, au: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        // If we fail after backend, we need to return NOW because we can't
        // assert any other faith in the DB states.
        //  * backend
        let be_errs = self.get_be_txn().verify();

        if !be_errs.is_empty() {
            return be_errs;
        }

        //  * in memory schema consistency.
        let sc_errs = self.get_schema().validate(au);

        if !sc_errs.is_empty() {
            return sc_errs;
        }

        //  * Indexing (req be + sch )
        /*
        idx_errs = self.get_be_txn()
            .verify_indexes();

        if !idx_errs.is_empty() {
            return idx_errs;
        }
         */

        // Ok BE passed, lets move on to the content.
        // Most of our checks are in the plugins, so we let them
        // do their job.

        // Now, call the plugins verification system.
        Plugins::run_verify(au, self)
        // Finished
    }
}

impl<'a> QueryServerTransaction for QueryServerWriteTransaction<'a> {
    type BackendTransactionType = BackendWriteTransaction<'a>;

    fn get_be_txn(&self) -> &BackendWriteTransaction<'a> {
        &self.be_txn
    }

    type SchemaTransactionType = SchemaWriteTransaction<'a>;

    fn get_schema(&self) -> &SchemaWriteTransaction<'a> {
        &self.schema
    }

    type AccessControlsTransactionType = AccessControlsWriteTransaction<'a>;

    fn get_accesscontrols(&self) -> &AccessControlsWriteTransaction<'a> {
        &self.accesscontrols
    }
}

#[derive(Clone, Debug)]
struct QueryServerMeta {
    pub max_cid: Cid,
}

impl QueryServer {
    pub fn new(be: Backend, schema: Schema) -> Self {
        let (s_uuid, d_uuid) = {
            let wr = be.write();
            (wr.get_db_s_uuid(), wr.get_db_d_uuid())
        };

        let pool_size = be.get_pool_size();

        info!("Server ID -> {:?}", s_uuid);
        info!("Domain ID -> {:?}", d_uuid);
        info!("DB tickets -> {:?}", pool_size);
        // log_event!(log, "Starting query worker ...");
        QueryServer {
            s_uuid,
            d_uuid,
            be,
            schema: Arc::new(schema),
            accesscontrols: Arc::new(AccessControls::new()),
            db_tickets: Arc::new(Semaphore::new(pool_size)),
            write_ticket: Arc::new(Semaphore::new(1)),
        }
    }

    #[cfg(test)]
    pub fn read(&self) -> QueryServerReadTransaction {
        task::block_on(self.read_async())
    }

    pub async fn read_async(&self) -> QueryServerReadTransaction<'_> {
        // We need to ensure a db conn will be available
        #[allow(clippy::expect_used)]
        let db_ticket = self
            .db_tickets
            .acquire()
            .await
            .expect("unable to aquire db_ticket for qsr");

        QueryServerReadTransaction {
            be_txn: self.be.read(),
            schema: self.schema.read(),
            accesscontrols: self.accesscontrols.read(),
            _db_ticket: db_ticket,
        }
    }

    #[cfg(test)]
    pub fn write(&self, ts: Duration) -> QueryServerWriteTransaction {
        // Feed the current schema index metadata to the be write transaction.
        task::block_on(self.write_async(ts))
    }

    pub async fn write_async(&self, ts: Duration) -> QueryServerWriteTransaction<'_> {
        // Guarantee we are the only writer on the thread pool
        #[allow(clippy::expect_used)]
        let write_ticket = self
            .write_ticket
            .acquire()
            .await
            .expect("unable to aquire writer_ticket for qsw");
        // We need to ensure a db conn will be available
        #[allow(clippy::expect_used)]
        let db_ticket = self
            .db_tickets
            .acquire()
            .await
            .expect("unable to aquire db_ticket for qsw");

        // let schema_write = self.schema.write().await;
        let schema_write = self.schema.write();
        let be_txn = self.be.write();

        #[allow(clippy::expect_used)]
        let ts_max = be_txn.get_db_ts_max(&ts).expect("Unable to get db_ts_max");
        let cid = Cid::new_lamport(self.s_uuid, self.d_uuid, ts, &ts_max);

        QueryServerWriteTransaction {
            // I think this is *not* needed, because commit is mut self which should
            // take ownership of the value, and cause the commit to "only be run
            // once".
            //
            // The commited flag is however used for abort-specific code in drop
            // which today I don't think we have ... yet.
            committed: false,
            d_uuid: self.d_uuid,
            cid,
            be_txn,
            schema: schema_write,
            accesscontrols: self.accesscontrols.write(),
            changed_schema: Cell::new(false),
            changed_acp: Cell::new(false),
            _db_ticket: db_ticket,
            _write_ticket: write_ticket,
        }
    }

    pub(crate) fn initialise_helper(
        &self,
        audit: &mut AuditScope,
        ts: Duration,
    ) -> Result<(), OperationError> {
        // First, check our database version - attempt to do an initial indexing
        // based on the in memory configuration
        //
        // If we ever change the core in memory schema, or the schema that we ship
        // in fixtures, we have to bump these values. This is how we manage the
        // first-run and upgrade reindexings.
        //
        // A major reason here to split to multiple transactions is to allow schema
        // reloading to occur, which causes the idxmeta to update, and allows validation
        // of the schema in the subsequent steps as we proceed.

        let reindex_write_1 = task::block_on(self.write_async(ts));
        reindex_write_1
            .upgrade_reindex(audit, SYSTEM_INDEX_VERSION)
            .and_then(|_| reindex_write_1.commit(audit))?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structuded, and this is all
        // marked "system", then we won't have an issue here.
        let ts_write_1 = task::block_on(self.write_async(ts));
        ts_write_1
            .initialise_schema_core(audit)
            .and_then(|_| ts_write_1.commit(audit))?;

        let ts_write_2 = task::block_on(self.write_async(ts));
        ts_write_2
            .initialise_schema_idm(audit)
            .and_then(|_| ts_write_2.commit(audit))?;

        // reindex and set to version + 1, this way when we bump the version
        // we are essetially pushing this version id back up to step write_1
        let reindex_write_2 = task::block_on(self.write_async(ts));
        reindex_write_2
            .upgrade_reindex(audit, SYSTEM_INDEX_VERSION + 1)
            .and_then(|_| reindex_write_2.commit(audit))?;

        // Now, based on the system version apply migrations. You may ask "should you not
        // be doing migrations before indexes?". And this is a very good question! The issue
        // is within a migration we must be able to search for content by pres index, and those
        // rely on us being indexed! It *is* safe to index content even if the
        // migration would cause a value type change (ie name changing from iutf8s to iname) because
        // the indexing subsystem is schema/value agnostic - the fact the values still let their keys
        // be extracted, means that the pres indexes will be valid even though the entries are pending
        // migration. We must be sure to NOT use EQ/SUB indexes in the migration code however!
        let migrate_txn = task::block_on(self.write_async(ts));
        // If we are "in the process of being setup" this is 0, and the migrations will have no
        // effect as ... there is nothing to migrate! It allows reset of the version to 0 to force
        // db migrations to take place.
        let system_info_version = match migrate_txn.internal_search_uuid(audit, &UUID_SYSTEM_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32("version").unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;
        ladmin_info!(audit, "current system version -> {:?}", system_info_version);

        if system_info_version < 3 {
            migrate_txn.migrate_2_to_3(audit)?;
        }

        migrate_txn.commit(audit)?;
        // Migrations complete. Init idm will now set the version as needed.

        let ts_write_3 = task::block_on(self.write_async(ts));
        ts_write_3
            .initialise_idm(audit)
            .and_then(|_| ts_write_3.commit(audit))?;

        ladmin_info!(audit, "ready to rock! 🤘");
        Ok(())
    }

    pub fn verify(&self, au: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let r_txn = task::block_on(self.read_async());
        r_txn.verify(au)
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    pub fn create(&self, au: &mut AuditScope, ce: &CreateEvent) -> Result<(), OperationError> {
        lperf_segment!(au, "server::create", || {
            // The create event is a raw, read only representation of the request
            // that was made to us, including information about the identity
            // performing the request.
            if !ce.event.is_internal() {
                lsecurity!(au, "create initiator: -> {}", ce.event);
            }

            // Log the request

            // TODO #67: Do we need limits on number of creates, or do we constraint
            // based on request size in the frontend?

            // Copy the entries to a writeable form, this involves assigning a
            // change id so we can track what's happening.
            let candidates: Vec<Entry<EntryInit, EntryNew>> = ce.entries.clone();

            // Do we have rights to perform these creates?
            // create_allow_operation
            let access = self.get_accesscontrols();
            let op_allow = access
                .create_allow_operation(au, ce, &candidates)
                .map_err(|e| {
                    ladmin_error!(au, "Failed to check create access {:?}", e);
                    e
                })?;
            if !op_allow {
                return Err(OperationError::AccessDenied);
            }

            // Assign our replication metadata now, since we can proceed with this operation.
            let mut candidates: Vec<Entry<EntryInvalid, EntryNew>> = candidates
                .into_iter()
                .map(|e| e.assign_cid(self.cid.clone()))
                .collect();

            // run any pre plugins, giving them the list of mutable candidates.
            // pre-plugins are defined here in their correct order of calling!
            // I have no intent to make these dynamic or configurable.

            Plugins::run_pre_create_transform(au, self, &mut candidates, ce).map_err(|e| {
                ladmin_error!(
                    au,
                    "Create operation failed (pre_transform plugin), {:?}",
                    e
                );
                e
            })?;

            // NOTE: This is how you map from Vec<Result<T>> to Result<Vec<T>>
            // remember, that you only get the first error and the iter terminates.

            // Now, normalise AND validate!

            let res: Result<Vec<Entry<EntrySealed, EntryNew>>, OperationError> = candidates
                .into_iter()
                .map(|e| {
                    e.validate(&self.schema)
                        .map_err(|e| {
                            ladmin_error!(au, "Schema Violation -> {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        .map(|e| {
                            // Then seal the changes?
                            e.seal()
                        })
                })
                .collect();

            let norm_cand: Vec<Entry<_, _>> = res?;

            // Run any pre-create plugins now with schema validated entries.
            // This is important for normalisation of certain types IE class
            // or attributes for these checks.
            Plugins::run_pre_create(au, self, &norm_cand, ce).map_err(|e| {
                ladmin_error!(au, "Create operation failed (plugin), {:?}", e);
                e
            })?;

            // We may change from ce.entries later to something else?
            let commit_cand = self.be_txn.create(au, norm_cand).map_err(|e| {
                ladmin_error!(au, "betxn create failure {:?}", e);
                e
            })?;
            // Run any post plugins

            Plugins::run_post_create(au, self, &commit_cand, ce).map_err(|e| {
                ladmin_error!(au, "Create operation failed (post plugin), {:?}", e);
                e
            })?;

            // We have finished all plugs and now have a successful operation - flag if
            // schema or acp requires reload.
            let _ = self
                .changed_schema
                .replace(commit_cand.iter().fold(false, |acc, e| {
                    if acc {
                        acc
                    } else {
                        e.attribute_value_pres("class", &PVCLASS_CLASSTYPE)
                            || e.attribute_value_pres("class", &PVCLASS_ATTRIBUTETYPE)
                    }
                }));
            let _ = self
                .changed_acp
                .replace(commit_cand.iter().fold(false, |acc, e| {
                    if acc {
                        acc
                    } else {
                        e.attribute_value_pres("class", &PVCLASS_ACP)
                    }
                }));
            ltrace!(
                au,
                "Schema reload: {:?}, ACP reload: {:?}",
                self.changed_schema,
                self.changed_acp
            );

            // We are complete, finalise logging and return

            if ce.event.is_internal() {
                ltrace!(au, "Create operation success");
            } else {
                ladmin_info!(au, "Create operation success");
            }
            Ok(())
        })
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn delete(&self, au: &mut AuditScope, de: &DeleteEvent) -> Result<(), OperationError> {
        lperf_segment!(au, "server::delete", || {
            // Do you have access to view all the set members? Reduce based on your
            // read permissions and attrs
            // THIS IS PRETTY COMPLEX SEE THE DESIGN DOC
            // In this case we need a search, but not INTERNAL to keep the same
            // associated credentials.
            // We only need to retrieve uuid though ...
            if !de.event.is_internal() {
                lsecurity!(au, "delete initiator: -> {}", de.event);
            }

            // Now, delete only what you can see
            let pre_candidates = match self.impersonate_search_valid(
                au,
                de.filter.clone(),
                de.filter_orig.clone(),
                &de.event,
            ) {
                Ok(results) => results,
                Err(e) => {
                    ladmin_error!(au, "delete: error in pre-candidate selection {:?}", e);
                    return Err(e);
                }
            };

            // Apply access controls to reduce the set if required.
            // delete_allow_operation
            let access = self.get_accesscontrols();
            let op_allow = access
                .delete_allow_operation(au, de, &pre_candidates)
                .map_err(|e| {
                    ladmin_error!(au, "Failed to check delete access {:?}", e);
                    e
                })?;
            if !op_allow {
                return Err(OperationError::AccessDenied);
            }

            // Is the candidate set empty?
            if pre_candidates.is_empty() {
                lrequest_error!(au, "delete: no candidates match filter {:?}", de.filter);
                return Err(OperationError::NoMatchingEntries);
            };

            let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
                .iter()
                // Invalidate and assign change id's
                .map(|er| er.clone().invalidate(self.cid.clone()))
                .collect();

            ltrace!(au, "delete: candidates -> {:?}", candidates);

            // Pre delete plugs
            Plugins::run_pre_delete(au, self, &mut candidates, de).map_err(|e| {
                ladmin_error!(au, "Delete operation failed (plugin), {:?}", e);
                e
            })?;

            ltrace!(
                au,
                "delete: now marking candidates as recycled -> {:?}",
                candidates
            );

            let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
                .into_iter()
                .map(|e| {
                    e.into_recycled()
                        .validate(&self.schema)
                        .map_err(|e| {
                            ladmin_error!(au, "Schema Violation -> {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        // seal if it worked.
                        .map(|r| r.seal())
                })
                .collect();

            let del_cand: Vec<Entry<_, _>> = res?;

            self.be_txn
                .modify(au, &pre_candidates, &del_cand)
                .map_err(|e| {
                    // be_txn is dropped, ie aborted here.
                    ladmin_error!(au, "Delete operation failed (backend), {:?}", e);
                    e
                })?;

            // Post delete plugs
            Plugins::run_post_delete(au, self, &del_cand, de).map_err(|e| {
                ladmin_error!(au, "Delete operation failed (plugin), {:?}", e);
                e
            })?;

            // We have finished all plugs and now have a successful operation - flag if
            // schema or acp requires reload.
            let _ = self
                .changed_schema
                .replace(del_cand.iter().fold(false, |acc, e| {
                    if acc {
                        acc
                    } else {
                        e.attribute_value_pres("class", &PVCLASS_CLASSTYPE)
                            || e.attribute_value_pres("class", &PVCLASS_ATTRIBUTETYPE)
                    }
                }));
            let _ = self
                .changed_acp
                .replace(del_cand.iter().fold(false, |acc, e| {
                    if acc {
                        acc
                    } else {
                        e.attribute_value_pres("class", &PVCLASS_ACP)
                    }
                }));
            ltrace!(
                au,
                "Schema reload: {:?}, ACP reload: {:?}",
                self.changed_schema,
                self.changed_acp
            );

            // Send result
            if de.event.is_internal() {
                ltrace!(au, "Delete operation success");
            } else {
                ladmin_info!(au, "Delete operation success");
            }
            Ok(())
        })
    }

    pub fn purge_tombstones(&self, au: &mut AuditScope) -> Result<(), OperationError> {
        lperf_segment!(au, "server::purge_tombstones", || {
            // delete everything that is a tombstone.
            let cid = self.cid.sub_secs(CHANGELOG_MAX_AGE).map_err(|e| {
                ladmin_error!(au, "Unable to generate search cid {:?}", e);
                e
            })?;
            let ts = match self.internal_search(
                au,
                filter_all!(f_and!([
                    f_eq("class", PVCLASS_TOMBSTONE.clone()),
                    f_lt("last_modified_cid", PartialValue::new_cid(cid)),
                ])),
            ) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            if ts.is_empty() {
                ladmin_info!(au, "No Tombstones present - purge operation success");
                return Ok(());
            }

            // Delete them - this is a TRUE delete, no going back now!
            self.be_txn
                .delete(au, &ts)
                .map_err(|e| {
                    ladmin_error!(au, "Tombstone purge operation failed (backend), {:?}", e);
                    e
                })
                .map(|_| {
                    ladmin_info!(au, "Tombstone purge operation success");
                })
        })
    }

    pub fn purge_recycled(&self, au: &mut AuditScope) -> Result<(), OperationError> {
        lperf_segment!(au, "server::purge_recycled", || {
            // Send everything that is recycled to tombstone
            // Search all recycled
            let cid = self.cid.sub_secs(RECYCLEBIN_MAX_AGE).map_err(|e| {
                ladmin_error!(au, "Unable to generate search cid {:?}", e);
                e
            })?;
            let rc = match self.internal_search(
                au,
                filter_all!(f_and!([
                    f_eq("class", PVCLASS_RECYCLED.clone()),
                    f_lt("last_modified_cid", PartialValue::new_cid(cid)),
                ])),
            ) {
                Ok(r) => r,
                Err(e) => return Err(e),
            };

            if rc.is_empty() {
                ladmin_info!(au, "No recycled present - purge operation success");
                return Ok(());
            }

            // Modify them to strip all avas except uuid
            let tombstone_cand: Result<Vec<_>, _> = rc
                .iter()
                .map(|e| {
                    e.to_tombstone(self.cid.clone())
                        .validate(&self.schema)
                        .map_err(|e| {
                            ladmin_error!(au, "Schema Violationi {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        // seal if it worked.
                        .map(|r| r.seal())
                })
                .collect();

            let tombstone_cand = tombstone_cand?;

            // Backend Modify
            self.be_txn
                .modify(au, &rc, &tombstone_cand)
                .map_err(|e| {
                    ladmin_error!(au, "Purge recycled operation failed (backend), {:?}", e);
                    e
                })
                .map(|_| {
                    ladmin_info!(au, "Purge recycled operation success");
                })
        })
    }

    // Should this take a revive event?
    pub fn revive_recycled(
        &self,
        au: &mut AuditScope,
        re: &ReviveRecycledEvent,
    ) -> Result<(), OperationError> {
        lperf_segment!(au, "server::revive_recycled", || {
            // Revive an entry to live. This is a specialised (limited)
            // modify proxy.
            //
            // impersonate modify will require ability to search the class=recycled
            // and the ability to remove that from the object.

            // create the modify
            // tl;dr, remove the class=recycled
            let modlist = ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("class"),
                PVCLASS_RECYCLED.clone(),
            )]);

            let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
                ladmin_error!(au, "revive recycled modlist Schema Violation {:?}", e);
                OperationError::SchemaViolation(e)
            })?;

            // Get the entries we are about to revive.
            //    we make a set of per-entry mod lists. A list of lists even ...
            let revive_cands =
                self.impersonate_search_valid(au, re.filter.clone(), re.filter.clone(), &re.event)?;

            let mut dm_mods: HashMap<Uuid, ModifyList<ModifyInvalid>> =
                HashMap::with_capacity(revive_cands.len());

            revive_cands.into_iter().for_each(|e| {
                // Get this entries uuid.
                let u: Uuid = *e.get_uuid();

                if let Some(riter) = e.get_ava_as_refuuid("directmemberof") {
                    riter.for_each(|g_uuid| {
                        dm_mods
                            .entry(*g_uuid)
                            .and_modify(|mlist| {
                                let m = Modify::Present(
                                    AttrString::from("member"),
                                    Value::new_refer_r(&u),
                                );
                                mlist.push_mod(m);
                            })
                            .or_insert({
                                let m = Modify::Present(
                                    AttrString::from("member"),
                                    Value::new_refer_r(&u),
                                );
                                ModifyList::new_list(vec![m])
                            });
                    });
                };
            });

            // Now impersonate the modify
            self.impersonate_modify_valid(
                au,
                re.filter.clone(),
                re.filter.clone(),
                m_valid,
                &re.event,
            )?;
            // If and only if that succeeds, apply the direct membership modifications
            // if possible.
            let r: Result<_, _> = dm_mods
                .into_iter()
                .map(|(g, mods)| {
                    // I think the filter/filter_all shouldn't matter here because the only
                    // valid direct memberships should be still valid/live references.
                    let f = filter_all!(f_eq("uuid", PartialValue::new_uuid(g)));
                    self.internal_modify(au, &f, &mods)
                })
                .collect();
            r
        })
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn modify(&self, au: &mut AuditScope, me: &ModifyEvent) -> Result<(), OperationError> {
        lperf_segment!(au, "server::modify", || {
            // Get the candidates.
            // Modify applies a modlist to a filter, so we need to internal search
            // then apply.
            if !me.event.is_internal() {
                lsecurity!(au, "modify initiator: -> {}", me.event);
            }

            // Validate input.

            // Is the modlist non zero?
            if me.modlist.len() == 0 {
                lrequest_error!(au, "modify: empty modify request");
                return Err(OperationError::EmptyRequest);
            }

            // Is the modlist valid?
            // This is now done in the event transform

            // Is the filter invalid to schema?
            // This is now done in the event transform

            // This also checks access controls due to use of the impersonation.
            let pre_candidates = match self.impersonate_search_valid(
                au,
                me.filter.clone(),
                me.filter_orig.clone(),
                &me.event,
            ) {
                Ok(results) => results,
                Err(e) => {
                    ladmin_error!(au, "modify: error in pre-candidate selection {:?}", e);
                    return Err(e);
                }
            };

            if pre_candidates.is_empty() {
                match me.event.origin {
                    EventOrigin::Internal => {
                        ltrace!(
                            au,
                            "modify: no candidates match filter ... continuing {:?}",
                            me.filter
                        );
                        return Ok(());
                    }
                    _ => {
                        lrequest_error!(
                            au,
                            "modify: no candidates match filter, failure {:?}",
                            me.filter
                        );
                        return Err(OperationError::NoMatchingEntries);
                    }
                }
            };

            // Are we allowed to make the changes we want to?
            // modify_allow_operation
            let access = self.get_accesscontrols();
            let op_allow = access
                .modify_allow_operation(au, me, &pre_candidates)
                .map_err(|e| {
                    ladmin_error!(au, "Unable to check modify access {:?}", e);
                    e
                })?;
            if !op_allow {
                return Err(OperationError::AccessDenied);
            }

            // Clone a set of writeables.
            // Apply the modlist -> Remember, we have a set of origs
            // and the new modified ents.
            let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
                .iter()
                .map(|er| er.clone().invalidate(self.cid.clone()))
                .collect();

            candidates
                .iter_mut()
                .for_each(|er| er.apply_modlist(&me.modlist));

            ltrace!(au, "modify: candidates -> {:?}", candidates);

            // Pre mod plugins
            // We should probably supply the pre-post cands here.
            Plugins::run_pre_modify(au, self, &mut candidates, me).map_err(|e| {
                ladmin_error!(au, "Modify operation failed (plugin), {:?}", e);
                e
            })?;

            // NOTE: There is a potential optimisation here, where if
            // candidates == pre-candidates, then we don't need to store anything
            // because we effectively just did an assert. However, like all
            // optimisations, this could be premature - so we for now, just
            // do the CORRECT thing and recommit as we may find later we always
            // want to add CSN's or other.

            let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
                .into_iter()
                .map(|e| {
                    e.validate(&self.schema)
                        .map_err(|e| {
                            ladmin_error!(au, "Schema Violation {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        .map(|e| e.seal())
                })
                .collect();

            let norm_cand: Vec<Entry<_, _>> = res?;

            // Backend Modify
            self.be_txn
                .modify(au, &pre_candidates, &norm_cand)
                .map_err(|e| {
                    ladmin_error!(au, "Modify operation failed (backend), {:?}", e);
                    e
                })?;

            // Post Plugins
            //
            // memberOf actually wants the pre cand list and the norm_cand list to see what
            // changed. Could be optimised, but this is correct still ...
            Plugins::run_post_modify(au, self, &pre_candidates, &norm_cand, me).map_err(|e| {
                ladmin_error!(au, "Modify operation failed (plugin), {:?}", e);
                e
            })?;

            // We have finished all plugs and now have a successful operation - flag if
            // schema or acp requires reload. Remember, this is a modify, so we need to check
            // pre and post cands.
            let _ =
                self.changed_schema
                    .replace(norm_cand.iter().chain(pre_candidates.iter()).fold(
                        false,
                        |acc, e| {
                            if acc {
                                acc
                            } else {
                                e.attribute_value_pres("class", &PVCLASS_CLASSTYPE)
                                    || e.attribute_value_pres("class", &PVCLASS_ATTRIBUTETYPE)
                            }
                        },
                    ));
            let _ =
                self.changed_acp
                    .replace(norm_cand.iter().chain(pre_candidates.iter()).fold(
                        false,
                        |acc, e| {
                            if acc {
                                acc
                            } else {
                                e.attribute_value_pres("class", &PVCLASS_ACP)
                            }
                        },
                    ));
            ltrace!(
                au,
                "Schema reload: {:?}, ACP reload: {:?}",
                self.changed_schema,
                self.changed_acp
            );

            // return
            if me.event.is_internal() {
                ltrace!(au, "Modify operation success");
            } else {
                ladmin_info!(au, "Modify operation success");
            }
            Ok(())
        })
    }

    /// Used in conjunction with internal_batch_modify, to get a pre/post
    /// pair, where post is pre-configured with metadata to allow
    /// modificiation before submit back to internal_batch_modify
    pub(crate) fn internal_search_writeable(
        &self,
        audit: &mut AuditScope,
        filter: &Filter<FilterInvalid>,
    ) -> Result<Vec<EntryTuple>, OperationError> {
        lperf_segment!(audit, "server::internal_search_writeable", || {
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let se = SearchEvent::new_internal(f_valid);
            self.search(audit, &se).map(|vs| {
                vs.into_iter()
                    .map(|e| {
                        let writeable = e.clone().invalidate(self.cid.clone());
                        (e, writeable)
                    })
                    .collect()
            })
        })
    }

    /// Allows writing batches of modified entries without going through
    /// the modlist path. This allows more effecient batch transformations
    /// such as memberof, but at the expense that YOU must guarantee you
    /// uphold all other plugin and state rules that are important. You
    /// probably want modify instead.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn internal_batch_modify(
        &self,
        au: &mut AuditScope,
        pre_candidates: Vec<Entry<EntrySealed, EntryCommitted>>,
        candidates: Vec<Entry<EntryInvalid, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        lperf_segment!(au, "server::internal_batch_modify", || {
            lsecurity!(au, "modify initiator: -> internal batch modify");

            if pre_candidates.is_empty() && candidates.is_empty() {
                // No action needed.
                return Ok(());
            }

            if pre_candidates.len() != candidates.len() {
                ladmin_error!(au, "internal_batch_modify - cand lengths differ");
                return Err(OperationError::InvalidRequestState);
            }

            let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
                .into_iter()
                .map(|e| {
                    e.validate(&self.schema)
                        .map_err(|e| {
                            ladmin_error!(au, "Schema Violation {:?}", e);
                            OperationError::SchemaViolation(e)
                        })
                        .map(|e| e.seal())
                })
                .collect();

            let norm_cand: Vec<Entry<_, _>> = res?;

            if cfg!(debug_assertions) {
                pre_candidates
                    .iter()
                    .zip(norm_cand.iter())
                    .try_for_each(|(pre, post)| {
                        if pre.get_uuid() == post.get_uuid() {
                            Ok(())
                        } else {
                            ladmin_error!(au, "modify - cand sets not correctly aligned");
                            Err(OperationError::InvalidRequestState)
                        }
                    })?;
            }

            // Backend Modify
            self.be_txn
                .modify(au, &pre_candidates, &norm_cand)
                .map_err(|e| {
                    ladmin_error!(au, "Modify operation failed (backend), {:?}", e);
                    e
                })?;

            let _ =
                self.changed_schema
                    .replace(norm_cand.iter().chain(pre_candidates.iter()).fold(
                        false,
                        |acc, e| {
                            if acc {
                                acc
                            } else {
                                e.attribute_value_pres("class", &PVCLASS_CLASSTYPE)
                                    || e.attribute_value_pres("class", &PVCLASS_ATTRIBUTETYPE)
                            }
                        },
                    ));
            let _ =
                self.changed_acp
                    .replace(norm_cand.iter().chain(pre_candidates.iter()).fold(
                        false,
                        |acc, e| {
                            if acc {
                                acc
                            } else {
                                e.attribute_value_pres("class", &PVCLASS_ACP)
                            }
                        },
                    ));
            ltrace!(
                au,
                "Schema reload: {:?}, ACP reload: {:?}",
                self.changed_schema,
                self.changed_acp
            );

            ltrace!(au, "Modify operation success");
            Ok(())
        })
    }

    /// Migrate 2 to 3 changes the name, domain_name types from iutf8 to iname.
    pub fn migrate_2_to_3(&self, au: &mut AuditScope) -> Result<(), OperationError> {
        lperf_segment!(au, "server::migrate_2_to_3", || {
            ladmin_warning!(au, "starting 2 to 3 migration. THIS MAY TAKE A LONG TIME!");
            // Get all entries where pres name or domain_name. INCLUDE TS + RECYCLE.

            let filt = filter_all!(f_or!([f_pres("name"), f_pres("domain_name"),]));

            let pre_candidates = self.internal_search(au, filt).map_err(|e| {
                ladmin_error!(au, "migrate_2_to_3 internal search failure -> {:?}", e);
                e
            })?;

            // If there is nothing, we donn't need to do anything.
            if pre_candidates.is_empty() {
                ladmin_info!(au, "migrate_2_to_3 no entries to migrate, complete");
                return Ok(());
            }

            // Change the value type.
            let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
                .iter()
                .map(|er| er.clone().invalidate(self.cid.clone()))
                .collect();

            candidates.iter_mut().for_each(|er| {
                let opt_names: Option<BTreeSet<_>> = er.pop_ava("name").map(|vs| {
                    vs.into_iter()
                        .filter_map(|v| v.migrate_iutf8_iname())
                        .collect()
                });
                let opt_dnames: Option<BTreeSet<_>> = er.pop_ava("domain_name").map(|vs| {
                    vs.into_iter()
                        .filter_map(|v| v.migrate_iutf8_iname())
                        .collect()
                });

                ltrace!(au, "{:?}", opt_names);
                ltrace!(au, "{:?}", opt_dnames);
                if let Some(v) = opt_names {
                    er.set_ava("name", v)
                };
                if let Some(v) = opt_dnames {
                    er.set_ava("domain_name", v)
                };
            });

            // Schema check all.
            let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, SchemaError> = candidates
                .into_iter()
                .map(|e| e.validate(&self.schema).map(|e| e.seal()))
                .collect();

            let norm_cand: Vec<Entry<_, _>> = match res {
                Ok(v) => v,
                Err(e) => {
                    ladmin_error!(au, "migrate_2_to_3 schema error -> {:?}", e);
                    return Err(OperationError::SchemaViolation(e));
                }
            };

            // Write them back.
            self.be_txn
                .modify(au, &pre_candidates, &norm_cand)
                .map_err(|e| {
                    ladmin_error!(au, "migrate_2_to_3 modification failure -> {:?}", e);
                    e
                })

            // Complete
        })
    }

    // These are where searches and other actions are actually implemented. This
    // is the "internal" version, where we define the event as being internal
    // only, allowing certain plugin by passes etc.

    pub fn internal_create(
        &self,
        audit: &mut AuditScope,
        entries: Vec<Entry<EntryInit, EntryNew>>,
    ) -> Result<(), OperationError> {
        // Start the audit scope
        // Create the CreateEvent
        let ce = CreateEvent::new_internal(entries);
        self.create(audit, &ce)
    }

    pub fn internal_delete(
        &self,
        audit: &mut AuditScope,
        filter: &Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let de = DeleteEvent::new_internal(f_valid);
        self.delete(audit, &de)
    }

    pub fn internal_modify(
        &self,
        audit: &mut AuditScope,
        filter: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        lperf_segment!(audit, "server::internal_modify", || {
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let m_valid = modlist
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let me = ModifyEvent::new_internal(f_valid, m_valid);
            self.modify(audit, &me)
        })
    }

    pub fn impersonate_modify_valid(
        &self,
        audit: &mut AuditScope,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        m_valid: ModifyList<ModifyValid>,
        event: &Event,
    ) -> Result<(), OperationError> {
        let me = ModifyEvent::new_impersonate(event, f_valid, f_intent_valid, m_valid);
        self.modify(audit, &me)
    }

    pub fn impersonate_modify(
        &self,
        audit: &mut AuditScope,
        filter: &Filter<FilterInvalid>,
        filter_intent: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
        event: &Event,
    ) -> Result<(), OperationError> {
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            ladmin_error!(audit, "filter Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let f_intent_valid = filter_intent.validate(self.get_schema()).map_err(|e| {
            ladmin_error!(audit, "f_intent Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            ladmin_error!(audit, "modlist Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        self.impersonate_modify_valid(audit, f_valid, f_intent_valid, m_valid, event)
    }

    // internal server operation types.
    // These just wrap the fn create/search etc, but they allow
    // creating the needed create event with the correct internal flags
    // and markers. They act as though they have the highest level privilege
    // IE there are no access control checks.

    /*
    pub fn internal_exists_or_create(
        &self,
        _e: Entry<EntryValid, EntryNew>,
    ) -> Result<(), OperationError> {
        // If the thing exists, stop.
        // if not, create from Entry.
        unimplemented!()
    }
    */

    pub fn internal_migrate_or_create_str(
        &self,
        audit: &mut AuditScope,
        e_str: &str,
    ) -> Result<(), OperationError> {
        let res = lperf_segment!(audit, "server::internal_migrate_or_create_str", || {
            Entry::from_proto_entry_str(audit, e_str, self)
                /*
                .and_then(|e: Entry<EntryInvalid, EntryNew>| {
                    let schema = self.get_schema();
                    e.validate(schema).map_err(OperationError::SchemaViolation)
                })
                */
                .and_then(|e: Entry<EntryInit, EntryNew>| self.internal_migrate_or_create(audit, e))
        });
        ltrace!(audit, "internal_migrate_or_create_str -> result {:?}", res);
        debug_assert!(res.is_ok());
        res
    }

    pub fn internal_migrate_or_create(
        &self,
        audit: &mut AuditScope,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // if the thing exists, ensure the set of attributes on
        // Entry A match and are present (but don't delete multivalue, or extended
        // attributes in the situation.
        // If not exist, create from Entry B
        //
        // This will extra classes an attributes alone!
        //
        // NOTE: gen modlist IS schema aware and will handle multivalue
        // correctly!
        ltrace!(
            audit,
            "internal_migrate_or_create operating on {:?}",
            e.get_uuid()
        );

        let filt = match e.filter_from_attrs(&[AttrString::from("uuid")]) {
            Some(f) => f,
            None => return Err(OperationError::FilterGeneration),
        };

        ltrace!(audit, "internal_migrate_or_create search {:?}", filt);

        match self.internal_search(audit, filt.clone()) {
            Ok(results) => {
                if results.is_empty() {
                    // It does not exist. Create it.
                    self.internal_create(audit, vec![e])
                } else if results.len() == 1 {
                    // If the thing is subset, pass
                    match e.gen_modlist_assert(&self.schema) {
                        Ok(modlist) => {
                            // Apply to &results[0]
                            ltrace!(audit, "Generated modlist -> {:?}", modlist);
                            self.internal_modify(audit, &filt, &modlist)
                        }
                        Err(e) => Err(OperationError::SchemaViolation(e)),
                    }
                } else {
                    Err(OperationError::InvalidDBState)
                }
            }
            Err(e) => {
                // An error occured. pass it back up.
                Err(e)
            }
        }
    }

    /*
    pub fn internal_assert_or_create_str(
        &mut self,
        audit: &mut AuditScope,
        e_str: &str,
    ) -> Result<(), OperationError> {
        let res = audit_segment!(audit, || Entry::from_proto_entry_str(audit, e_str, self)
            .and_then(
                |e: Entry<EntryInit, EntryNew>| self.internal_assert_or_create(audit, e)
            ));
        ltrace!(audit, "internal_assert_or_create_str -> result {:?}", res);
        debug_assert!(res.is_ok());
        res
    }

    // Should this take a be_txn?
    pub fn internal_assert_or_create(
        &mut self,
        audit: &mut AuditScope,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // If exists, ensure the object is exactly as provided
        // else, if not exists, create it. IE no extra or excess
        // attributes and classes.

        ltrace!(
            audit,
            "internal_assert_or_create operating on {:?}",
            e.get_uuid()
        );

        // Create a filter from the entry for assertion.
        let filt = match e.filter_from_attrs(&[String::from("uuid")]) {
            Some(f) => f,
            None => return Err(OperationError::FilterGeneration),
        };

        // Does it exist? we use search here, not exists, so that if the entry does exist
        // we can compare it is identical, which avoids a delete/create cycle that would
        // trigger csn/repl each time we start up.
        match self.internal_search(audit, filt.clone()) {
            Ok(results) => {
                if results.is_empty() {
                    // It does not exist. Create it.
                    self.internal_create(audit, vec![e])
                } else if results.len() == 1 {
                    // it exists. To guarantee content exactly as is, we compare if it's identical.
                    if !e.compare(&results[0]) {
                        self.internal_delete(audit, filt)
                            .and_then(|_| self.internal_create(audit, vec![e]))
                    } else {
                        // No action required
                        Ok(())
                    }
                } else {
                    Err(OperationError::InvalidDBState)
                }
            }
            Err(er) => {
                // An error occured. pass it back up.
                Err(er)
            }
        }
    }
    */

    pub fn initialise_schema_core(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        ladmin_info!(audit, "initialise_schema_core -> start ...");
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // internal_migrate_or_create.
        let r: Result<_, _> = entries
            .into_iter()
            .map(|e| {
                ltrace!(audit, "init schema -> {}", e);
                self.internal_migrate_or_create(audit, e)
            })
            .collect();
        if r.is_ok() {
            ladmin_info!(audit, "initialise_schema_core -> Ok!");
        } else {
            ladmin_error!(audit, "initialise_schema_core -> Error {:?}", r);
        }
        debug_assert!(r.is_ok());
        r
    }

    pub fn initialise_schema_idm(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        ladmin_info!(audit, "initialise_schema_idm -> start ...");
        // List of IDM schemas to init.
        let idm_schema: Vec<&str> = vec![
            JSON_SCHEMA_ATTR_DISPLAYNAME,
            JSON_SCHEMA_ATTR_LEGALNAME,
            JSON_SCHEMA_ATTR_MAIL,
            JSON_SCHEMA_ATTR_SSH_PUBLICKEY,
            JSON_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
            JSON_SCHEMA_ATTR_RADIUS_SECRET,
            JSON_SCHEMA_ATTR_DOMAIN_NAME,
            JSON_SCHEMA_ATTR_DOMAIN_UUID,
            JSON_SCHEMA_ATTR_DOMAIN_SSID,
            JSON_SCHEMA_ATTR_GIDNUMBER,
            JSON_SCHEMA_ATTR_BADLIST_PASSWORD,
            JSON_SCHEMA_ATTR_LOGINSHELL,
            JSON_SCHEMA_ATTR_UNIX_PASSWORD,
            JSON_SCHEMA_ATTR_ACCOUNT_EXPIRE,
            JSON_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
            JSON_SCHEMA_CLASS_PERSON,
            JSON_SCHEMA_CLASS_GROUP,
            JSON_SCHEMA_CLASS_ACCOUNT,
            JSON_SCHEMA_CLASS_DOMAIN_INFO,
            JSON_SCHEMA_CLASS_POSIXACCOUNT,
            JSON_SCHEMA_CLASS_POSIXGROUP,
            JSON_SCHEMA_CLASS_SYSTEM_CONFIG,
            JSON_SCHEMA_ATTR_NSUNIQUEID,
        ];

        let r: Result<Vec<()>, _> = idm_schema
            .iter()
            // Each item individually logs it's result
            .map(|e_str| self.internal_migrate_or_create_str(audit, e_str))
            .collect();
        if r.is_ok() {
            ladmin_info!(audit, "initialise_schema_idm -> Ok!");
        } else {
            ladmin_error!(audit, "initialise_schema_idm -> Error {:?}", r);
        }
        debug_assert!(r.is_ok());

        r.map(|_| ())
    }

    // This function is idempotent
    pub fn initialise_idm(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty const thing. Also check anonymous, important to many
        // concepts.
        let res = self
            .internal_migrate_or_create_str(audit, JSON_SYSTEM_INFO_V1)
            .and_then(|_| self.internal_migrate_or_create_str(audit, JSON_DOMAIN_INFO_V1))
            .and_then(|_| self.internal_migrate_or_create_str(audit, JSON_SYSTEM_CONFIG_V1));
        if res.is_err() {
            ladmin_error!(audit, "initialise_idm p1 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // The domain info now exists, we should be able to do these migrations as they will
        // cause SPN regenerations to occur

        // Check the admin object exists (migrations).
        // Create the default idm_admin group.
        let admin_entries = [
            JSON_ANONYMOUS_V1,
            JSON_ADMIN_V1,
            JSON_IDM_ADMIN_V1,
            JSON_IDM_ADMINS_V1,
            JSON_SYSTEM_ADMINS_V1,
        ];
        let res: Result<(), _> = admin_entries
            .iter()
            // Each item individually logs it's result
            .map(|e_str| self.internal_migrate_or_create_str(audit, e_str))
            .collect();
        if res.is_err() {
            ladmin_error!(audit, "initialise_idm p2 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // Create any system default schema entries.

        // Create any system default access profile entries.
        let idm_entries = [
            // Builtin groups
            JSON_IDM_PEOPLE_MANAGE_PRIV_V1,
            JSON_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
            JSON_IDM_PEOPLE_EXTEND_PRIV_V1,
            JSON_IDM_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_PEOPLE_READ_PRIV_V1,
            JSON_IDM_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_GROUP_WRITE_PRIV_V1,
            JSON_IDM_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_RADIUS_SERVERS_V1,
            // Write deps on read, so write must be added first.
            JSON_IDM_HP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_HP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_SCHEMA_MANAGE_PRIV_V1,
            JSON_IDM_HP_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_HP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_ACP_MANAGE_PRIV_V1,
            JSON_DOMAIN_ADMINS,
            JSON_IDM_HIGH_PRIVILEGE_V1,
            // Built in access controls.
            JSON_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1,
            JSON_IDM_ADMINS_ACP_REVIVE_V1,
            // JSON_IDM_ADMINS_ACP_MANAGE_V1,
            JSON_IDM_ALL_ACP_READ_V1,
            JSON_IDM_SELF_ACP_READ_V1,
            JSON_IDM_SELF_ACP_WRITE_V1,
            JSON_IDM_ACP_PEOPLE_READ_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_WRITE_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_MANAGE_PRIV_V1,
            JSON_IDM_ACP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_ACP_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACP_RADIUS_SERVERS_V1,
            JSON_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1,
            JSON_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1,
            JSON_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1,
            JSON_IDM_ACP_HP_GROUP_WRITE_PRIV_V1,
            JSON_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1,
            JSON_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1,
            JSON_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1,
            JSON_IDM_ACP_ACP_MANAGE_PRIV_V1,
            JSON_IDM_ACP_DOMAIN_ADMIN_PRIV_V1,
            JSON_IDM_ACP_SYSTEM_CONFIG_PRIV_V1,
            JSON_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
            JSON_IDM_ACP_PEOPLE_EXTEND_PRIV_V1,
        ];

        let res: Result<(), _> = idm_entries
            .iter()
            // Each item individually logs it's result
            .map(|e_str| self.internal_migrate_or_create_str(audit, e_str))
            .collect();
        if res.is_ok() {
            ladmin_info!(audit, "initialise_idm -> result Ok!");
        } else {
            ladmin_error!(audit, "initialise_idm p3 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        Ok(())
    }

    fn reload_schema(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        lperf_segment!(audit, "server::reload_schema", || {
            ltrace!(audit, "Schema reload started ...");

            // supply entries to the writable schema to reload from.
            // find all attributes.
            let filt = filter!(f_eq("class", PVCLASS_ATTRIBUTETYPE.clone()));
            let res = self.internal_search(audit, filt).map_err(|e| {
                ladmin_error!(audit, "reload schema internal search failed {:?}", e);
                e
            })?;
            // load them.
            let attributetypes: Result<Vec<_>, _> = res
                .iter()
                .map(|e| SchemaAttribute::try_from(audit, e))
                .collect();
            let attributetypes = attributetypes.map_err(|e| {
                ladmin_error!(audit, "reload schema attributetypes {:?}", e);
                e
            })?;

            self.schema.update_attributes(attributetypes).map_err(|e| {
                ladmin_error!(audit, "reload schema update attributetypes {:?}", e);
                e
            })?;

            // find all classes
            let filt = filter!(f_eq("class", PVCLASS_CLASSTYPE.clone()));
            let res = self.internal_search(audit, filt).map_err(|e| {
                ladmin_error!(audit, "reload schema internal search failed {:?}", e);
                e
            })?;
            // load them.
            let classtypes: Result<Vec<_>, _> = res
                .iter()
                .map(|e| SchemaClass::try_from(audit, e))
                .collect();
            let classtypes = classtypes.map_err(|e| {
                ladmin_error!(audit, "reload schema classtypes {:?}", e);
                e
            })?;

            self.schema.update_classes(classtypes).map_err(|e| {
                ladmin_error!(audit, "reload schema update classtypes {:?}", e);
                e
            })?;

            // validate.
            let valid_r = self.schema.validate(audit);

            // Translate the result.
            if valid_r.is_empty() {
                // Now use this to reload the backend idxmeta
                ltrace!(audit, "Reloading idxmeta ...");
                self.be_txn.update_idxmeta(self.schema.reload_idxmeta());
                Ok(())
            } else {
                // Log the failures?
                ladmin_error!(audit, "Schema reload failed -> {:?}", valid_r);
                Err(OperationError::ConsistencyError(valid_r))
            }
        })
    }

    fn reload_accesscontrols(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // supply entries to the writable access controls to reload from.
        // This has to be done in FOUR passes - one for each type!
        //
        // Note, we have to do the search, parse, then submit here, because of the
        // requirement to have the write query server reference in the parse stage - this
        // would cause a rust double-borrow if we had AccessControls to try to handle
        // the entry lists themself.
        ltrace!(audit, "ACP reload started ...");

        // Update search
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACS.clone()),
            f_andnot(f_eq("acp_enable", PVACP_ENABLE_FALSE.clone())),
        ]));

        let res = self.internal_search(audit, filt).map_err(|e| {
            ladmin_error!(
                audit,
                "reload accesscontrols internal search failed {:?}",
                e
            );
            e
        })?;
        let search_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlSearch::try_from(audit, self, e))
            .collect();

        let search_acps = search_acps.map_err(|e| {
            ladmin_error!(audit, "Unable to parse search accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols
            .update_search(search_acps)
            .map_err(|e| {
                ladmin_error!(audit, "Failed to update search accesscontrols {:?}", e);
                e
            })?;
        // Update create
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACC.clone()),
            f_andnot(f_eq("acp_enable", PVACP_ENABLE_FALSE.clone())),
        ]));

        let res = self.internal_search(audit, filt).map_err(|e| {
            ladmin_error!(
                audit,
                "reload accesscontrols internal search failed {:?}",
                e
            );
            e
        })?;
        let create_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlCreate::try_from(audit, self, e))
            .collect();

        let create_acps = create_acps.map_err(|e| {
            ladmin_error!(audit, "Unable to parse create accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols
            .update_create(create_acps)
            .map_err(|e| {
                ladmin_error!(audit, "Failed to update create accesscontrols {:?}", e);
                e
            })?;
        // Update modify
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACM.clone()),
            f_andnot(f_eq("acp_enable", PVACP_ENABLE_FALSE.clone())),
        ]));

        let res = self.internal_search(audit, filt).map_err(|e| {
            ladmin_error!(
                audit,
                "reload accesscontrols internal search failed {:?}",
                e
            );
            e
        })?;
        let modify_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlModify::try_from(audit, self, e))
            .collect();

        let modify_acps = modify_acps.map_err(|e| {
            ladmin_error!(audit, "Unable to parse modify accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols
            .update_modify(modify_acps)
            .map_err(|e| {
                ladmin_error!(audit, "Failed to update modify accesscontrols {:?}", e);
                e
            })?;
        // Update delete
        let filt = filter!(f_and!([
            f_eq("class", PVCLASS_ACP.clone()),
            f_eq("class", PVCLASS_ACD.clone()),
            f_andnot(f_eq("acp_enable", PVACP_ENABLE_FALSE.clone())),
        ]));

        let res = self.internal_search(audit, filt).map_err(|e| {
            ladmin_error!(
                audit,
                "reload accesscontrols internal search failed {:?}",
                e
            );
            e
        })?;
        let delete_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlDelete::try_from(audit, self, e))
            .collect();

        let delete_acps = delete_acps.map_err(|e| {
            ladmin_error!(audit, "Unable to parse delete accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols.update_delete(delete_acps).map_err(|e| {
            ladmin_error!(audit, "Failed to update delete accesscontrols {:?}", e);
            e
        })
    }

    pub(crate) fn get_domain_uuid(&self) -> Uuid {
        self.d_uuid
    }

    /// Initiate a domain rename process. This is generally an internal function but it's
    /// exposed to the cli for admins to be able to initiate the process.
    pub fn domain_rename(
        &self,
        audit: &mut AuditScope,
        new_domain_name: &str,
    ) -> Result<(), OperationError> {
        let modl = ModifyList::new_purge_and_set("domain_name", Value::new_iname(new_domain_name));
        let udi = PartialValue::new_uuidr(&UUID_DOMAIN_INFO);
        let filt = filter_all!(f_eq("uuid", udi));
        self.internal_modify(audit, &filt, &modl)
    }

    pub fn reindex(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // initiate a be reindex here. This could have been from first run checking
        // the versions, or it could just be from the cli where an admin needs to do an
        // indexing.
        self.be_txn.reindex(audit)
    }

    pub(crate) fn upgrade_reindex(
        &self,
        audit: &mut AuditScope,
        v: i64,
    ) -> Result<(), OperationError> {
        self.be_txn.upgrade_reindex(audit, v)
    }

    pub fn commit(mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // This could be faster if we cache the set of classes changed
        // in an operation so we can check if we need to do the reload or not
        //
        // Reload the schema from qs.
        if self.changed_schema.get() {
            self.reload_schema(audit)?;
        }
        // Determine if we need to update access control profiles
        // based on any modifications that have occured.
        // IF SCHEMA CHANGED WE MUST ALSO RELOAD!!! IE if schema had an attr removed
        // that we rely on we MUST fail this here!!
        if self.changed_schema.get() || self.changed_acp.get() {
            self.reload_accesscontrols(audit)?;
        }

        // Now destructure the transaction ready to reset it.
        let QueryServerWriteTransaction {
            committed,
            be_txn,
            schema,
            accesscontrols,
            cid,
            ..
        } = self;
        debug_assert!(!committed);

        // Write the cid to the db. If this fails, we can't assume replication
        // will be stable, so return if it fails.
        be_txn.set_db_ts_max(&cid.ts)?;
        // Validate the schema as we just loaded it.
        let r = schema.validate(audit);

        if r.is_empty() {
            // Schema has been validated, so we can go ahead and commit it with the be
            // because both are consistent.
            schema
                .commit()
                .and_then(|_| accesscontrols.commit().and_then(|_| be_txn.commit(audit)))
        } else {
            Err(OperationError::ConsistencyError(r))
        }
        // Audit done
    }
}

// Auth requests? How do we structure these ...

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::constants::{
        CHANGELOG_MAX_AGE, JSON_ADMIN_V1, JSON_DOMAIN_INFO_V1, JSON_SYSTEM_CONFIG_V1,
        JSON_SYSTEM_INFO_V1, RECYCLEBIN_MAX_AGE, SYSTEM_INDEX_VERSION, UUID_ADMIN,
        UUID_DOMAIN_INFO,
    };
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::Credential;
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, ReviveRecycledEvent, SearchEvent};
    use crate::modify::{Modify, ModifyList};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use crate::value::{PartialValue, Value};
    use kanidm_proto::v1::{OperationError, SchemaError};
    use smartstring::alias::String as AttrString;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn test_qs_create_user() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());
            let filt = filter!(f_eq("name", PartialValue::new_iname("testperson")));
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");

            let se1 = unsafe { SearchEvent::new_impersonate_entry(admin.clone(), filt.clone()) };
            let se2 = unsafe { SearchEvent::new_impersonate_entry(admin, filt) };

            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson"))
            );

            let ce = CreateEvent::new_internal(vec![e.clone()]);

            let r1 = server_txn.search(audit, &se1).expect("search failure");
            assert!(r1.is_empty());

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            let r2 = server_txn.search(audit, &se2).expect("search failure");
            debug!("--> {:?}", r2);
            assert!(r2.len() == 1);

            let expected = unsafe { vec![e.into_sealed_committed()] };

            assert_eq!(r2, expected);

            assert!(server_txn.commit(audit).is_ok());
        });
    }

    #[test]
    fn test_qs_init_idempotent_schema_core() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            {
                // Setup and abort.
                let server_txn = server.write(duration_from_epoch_now());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
            }
            {
                let server_txn = server.write(duration_from_epoch_now());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
            {
                // Now do it again in a new txn, but abort
                let server_txn = server.write(duration_from_epoch_now());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
            }
            {
                // Now do it again in a new txn.
                let server_txn = server.write(duration_from_epoch_now());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
        });
    }

    #[test]
    fn test_qs_modify() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create an object
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson2")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63932").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson2")),
                ("displayname", Value::new_utf8s("testperson2"))
            );

            let ce = CreateEvent::new_internal(vec![e1.clone(), e2.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Empty Modlist (filter is valid)
            let me_emp = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_pres("class")),
                    ModifyList::new_list(vec![]),
                )
            };
            assert!(server_txn.modify(audit, &me_emp) == Err(OperationError::EmptyRequest));

            // Mod changes no objects
            let me_nochg = unsafe {
                ModifyEvent::new_impersonate_entry_ser(
                    JSON_ADMIN_V1,
                    filter!(f_eq("name", PartialValue::new_iname("flarbalgarble"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("description"),
                        Value::from("anusaosu"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_nochg) == Err(OperationError::NoMatchingEntries));

            // Filter is invalid to schema - to check this due to changes in the way events are
            // handled, we put this via the internal modify function to get the modlist
            // checked for us. Normal server operation doesn't allow weird bypasses like
            // this.
            let r_inv_1 = server_txn.internal_modify(
                audit,
                &filter!(f_eq("tnanuanou", PartialValue::new_iname("Flarbalgarble"))),
                &ModifyList::new_list(vec![Modify::Present(
                    AttrString::from("description"),
                    Value::from("anusaosu"),
                )]),
            );
            assert!(
                r_inv_1
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute("tnanuanou".to_string())
                    ))
            );

            // Mod is invalid to schema
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_pres("class")),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("htnaonu"),
                        Value::from("anusaosu"),
                    )]),
                )
            };
            assert!(
                server_txn.modify(audit, &me_inv_m)
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute("htnaonu".to_string())
                    ))
            );

            // Mod single object
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson2"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("description"),
                        Value::from("anusaosu"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Mod multiple object
            let me_mult = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_or!([
                        f_eq("name", PartialValue::new_iname("testperson1")),
                        f_eq("name", PartialValue::new_iname("testperson2")),
                    ])),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("description"),
                        Value::from("anusaosu"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_mult).is_ok());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_modify_invalid_class() {
        // Test modifying an entry and adding an extra class, that would cause the entry
        // to no longer conform to schema.
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );

            let ce = CreateEvent::new_internal(vec![e1.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Add class but no values
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("class"),
                        Value::new_class("system_info"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // Add multivalue where not valid
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("name"),
                        Value::new_iname("testpersonx"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // add class and valid values?
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    ModifyList::new_list(vec![
                        Modify::Present(AttrString::from("class"), Value::new_class("system_info")),
                        // Modify::Present("domain".to_string(), Value::new_iutf8("domain.name")),
                        Modify::Present(AttrString::from("version"), Value::new_uint32(1)),
                    ]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Replace a value
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    ModifyList::new_list(vec![
                        Modify::Purged(AttrString::from("name")),
                        Modify::Present(AttrString::from("name"), Value::new_iname("testpersonx")),
                    ]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_ok());
        })
    }

    #[test]
    fn test_qs_delete() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson2")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63932").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson2"))
            );

            let e3 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson3")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63933").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson3"))
            );

            let ce = CreateEvent::new_internal(vec![e1.clone(), e2.clone(), e3.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Delete filter is syntax invalid
            let de_inv =
                unsafe { DeleteEvent::new_internal_invalid(filter!(f_pres("nhtoaunaoehtnu"))) };
            assert!(server_txn.delete(audit, &de_inv).is_err());

            // Delete deletes nothing
            let de_empty = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "uuid",
                    PartialValue::new_uuids("cc8e95b4-c24f-4d68-ba54-000000000000").unwrap()
                )))
            };
            assert!(server_txn.delete(audit, &de_empty).is_err());

            // Delete matches one
            let de_sin = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "name",
                    PartialValue::new_iname("testperson3")
                )))
            };
            assert!(server_txn.delete(audit, &de_sin).is_ok());

            // Delete matches many
            let de_mult = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "description",
                    PartialValue::new_utf8s("testperson")
                )))
            };
            assert!(server_txn.delete(audit, &de_mult).is_ok());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_tombstone() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // First we setup some timestamps
            let time_p1 = duration_from_epoch_now();
            let time_p2 = time_p1 + Duration::from_secs(CHANGELOG_MAX_AGE * 2);

            let server_txn = server.write(time_p1);
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");

            let filt_i_ts = filter_all!(f_eq("class", PartialValue::new_class("tombstone")));

            // Create fake external requests. Probably from admin later
            // Should we do this with impersonate instead of using the external
            let me_ts = unsafe {
                ModifyEvent::new_impersonate_entry(
                    admin.clone(),
                    filt_i_ts.clone(),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("class"),
                        Value::new_class("tombstone"),
                    )]),
                )
            };

            let de_ts =
                unsafe { DeleteEvent::new_impersonate_entry(admin.clone(), filt_i_ts.clone()) };
            let se_ts = unsafe { SearchEvent::new_ext_impersonate_entry(admin, filt_i_ts.clone()) };

            // First, create a tombstone
            let e_ts = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("tombstone")),
                (
                    "uuid",
                    Value::new_uuids("9557f49c-97a5-4277-a9a5-097d17eb8317").expect("uuid")
                )
            );

            let ce = CreateEvent::new_internal(vec![e_ts]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_ts).expect("search failed");
            assert!(r1.is_empty());

            // Can it be deleted (external delete)
            // Should be err-no candidates.
            assert!(server_txn.delete(audit, &de_ts).is_err());

            // Can it be modified? (external modify)
            // Should be err-no candidates
            assert!(server_txn.modify(audit, &me_ts).is_err());

            // Can it be seen (internal search)
            // Internal search should see it.
            let r2 = server_txn
                .internal_search(audit, filt_i_ts.clone())
                .expect("internal search failed");
            assert!(r2.len() == 1);

            // If we purge now, nothing happens, we aren't past the time window.
            assert!(server_txn.purge_tombstones(audit).is_ok());

            let r3 = server_txn
                .internal_search(audit, filt_i_ts.clone())
                .expect("internal search failed");
            assert!(r3.len() == 1);

            // Commit
            assert!(server_txn.commit(audit).is_ok());

            // New txn, push the cid forward.
            let server_txn = server.write(time_p2);

            // Now purge
            assert!(server_txn.purge_tombstones(audit).is_ok());

            // Assert it's gone
            // Internal search should not see it.
            let r4 = server_txn
                .internal_search(audit, filt_i_ts)
                .expect("internal search failed");
            assert!(r4.is_empty());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_recycle_simple() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // First we setup some timestamps
            let time_p1 = duration_from_epoch_now();
            let time_p2 = time_p1 + Duration::from_secs(RECYCLEBIN_MAX_AGE * 2);

            let server_txn = server.write(time_p1);
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");

            let filt_i_rc = filter_all!(f_eq("class", PartialValue::new_class("recycled")));

            let filt_i_ts = filter_all!(f_eq("class", PartialValue::new_class("tombstone")));

            let filt_i_per = filter_all!(f_eq("class", PartialValue::new_class("person")));

            // Create fake external requests. Probably from admin later
            let me_rc = unsafe {
                ModifyEvent::new_impersonate_entry(
                    admin.clone(),
                    filt_i_rc.clone(),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("class"),
                        Value::new_class("recycled"),
                    )]),
                )
            };

            let de_rc =
                unsafe { DeleteEvent::new_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

            let se_rc =
                unsafe { SearchEvent::new_ext_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

            let sre_rc =
                unsafe { SearchEvent::new_rec_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

            let rre_rc = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin,
                    filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                )
            };

            // Create some recycled objects
            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("recycled")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("recycled")),
                ("name", Value::new_iname("testperson2")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63932").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson2")),
                ("displayname", Value::new_utf8s("testperson2"))
            );

            let ce = CreateEvent::new_internal(vec![e1, e2]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_rc).expect("search failed");
            assert!(r1.is_empty());

            // Can it be deleted (external delete)
            // Should be err-no candidates.
            assert!(server_txn.delete(audit, &de_rc).is_err());

            // Can it be modified? (external modify)
            // Should be err-no candidates
            assert!(server_txn.modify(audit, &me_rc).is_err());

            // Can in be seen by special search? (external recycle search)
            let r2 = server_txn.search(audit, &sre_rc).expect("search failed");
            assert!(r2.len() == 2);

            // Can it be seen (internal search)
            // Internal search should see it.
            let r2 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .expect("internal search failed");
            assert!(r2.len() == 2);

            // There are now two paths forward
            //  revival or purge!
            assert!(server_txn.revive_recycled(audit, &rre_rc).is_ok());

            // Not enough time has passed, won't have an effect for purge to TS
            assert!(server_txn.purge_recycled(audit).is_ok());
            let r3 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .expect("internal search failed");
            assert!(r3.len() == 1);

            // Commit
            assert!(server_txn.commit(audit).is_ok());

            // Now, establish enough time for the recycled items to be purged.
            let server_txn = server.write(time_p2);

            //  purge to tombstone, now that time has passed.
            assert!(server_txn.purge_recycled(audit).is_ok());

            // Should be no recycled objects.
            let r4 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .expect("internal search failed");
            assert!(r4.is_empty());

            // There should be one tombstone
            let r5 = server_txn
                .internal_search(audit, filt_i_ts.clone())
                .expect("internal search failed");
            assert!(r5.len() == 1);

            // There should be one entry
            let r6 = server_txn
                .internal_search(audit, filt_i_per.clone())
                .expect("internal search failed");
            assert!(r6.len() == 1);

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    // The delete test above should be unaffected by recycle anyway
    #[test]
    fn test_qs_recycle_advanced() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create items
            let server_txn = server.write(duration_from_epoch_now());
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let ce = CreateEvent::new_internal(vec![e1]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());
            // Delete and ensure they became recycled.
            let de_sin = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "name",
                    PartialValue::new_iname("testperson1")
                )))
            };
            assert!(server_txn.delete(audit, &de_sin).is_ok());
            // Can in be seen by special search? (external recycle search)
            let filt_rc = filter_all!(f_eq("class", PartialValue::new_class("recycled")));
            let sre_rc = unsafe { SearchEvent::new_rec_impersonate_entry(admin, filt_rc.clone()) };
            let r2 = server_txn.search(audit, &sre_rc).expect("search failed");
            assert!(r2.len() == 1);

            // Create dup uuid (rej)
            // After a delete -> recycle, create duplicate name etc.
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_err());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_name_to_uuid() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Name doesn't exist
            let r1 = server_txn.name_to_uuid(audit, "testpers");
            assert!(r1.is_err());
            // Name doesn't exist (not syntax normalised)
            let r2 = server_txn.name_to_uuid(audit, "tEsTpErS");
            assert!(r2.is_err());
            // Name does exist
            let r3 = server_txn.name_to_uuid(audit, "testperson1");
            assert!(r3.is_ok());
            // Name is not syntax normalised (but exists)
            let r4 = server_txn.name_to_uuid(audit, "tEsTpErSoN1");
            assert!(r4.is_ok());
        })
    }

    #[test]
    fn test_qs_uuid_to_spn() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Name doesn't exist
            let r1 = server_txn.uuid_to_spn(
                audit,
                &Uuid::parse_str("bae3f507-e6c3-44ba-ad01-f8ff1083534a").unwrap(),
            );
            // There is nothing.
            assert!(r1 == Ok(None));
            // Name does exist
            let r3 = server_txn.uuid_to_spn(
                audit,
                &Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap(),
            );
            println!("{:?}", r3);
            assert!(r3.unwrap().unwrap() == Value::new_spn_str("testperson1", "example.com"));
            // Name is not syntax normalised (but exists)
            let r4 = server_txn.uuid_to_spn(
                audit,
                &Uuid::parse_str("CC8E95B4-C24F-4D68-BA54-8BED76F63930").unwrap(),
            );
            assert!(r4.unwrap().unwrap() == Value::new_spn_str("testperson1", "example.com"));
        })
    }

    #[test]
    fn test_qs_uuid_to_rdn() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Name doesn't exist
            let r1 = server_txn.uuid_to_rdn(
                audit,
                &Uuid::parse_str("bae3f507-e6c3-44ba-ad01-f8ff1083534a").unwrap(),
            );
            // There is nothing.
            assert!(r1.unwrap() == "uuid=bae3f507-e6c3-44ba-ad01-f8ff1083534a");
            // Name does exist
            let r3 = server_txn.uuid_to_rdn(
                audit,
                &Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap(),
            );
            println!("{:?}", r3);
            assert!(r3.unwrap() == "spn=testperson1@example.com");
            // Uuid is not syntax normalised (but exists)
            let r4 = server_txn.uuid_to_rdn(
                audit,
                &Uuid::parse_str("CC8E95B4-C24F-4D68-BA54-8BED76F63930").unwrap(),
            );
            assert!(r4.unwrap() == "spn=testperson1@example.com");
        })
    }

    #[test]
    fn test_qs_uuid_to_star_recycle() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );

            let tuuid = Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap();

            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            assert!(
                server_txn.uuid_to_rdn(audit, &tuuid)
                    == Ok("spn=testperson1@example.com".to_string())
            );

            assert!(
                server_txn.uuid_to_spn(audit, &tuuid)
                    == Ok(Some(Value::new_spn_str("testperson1", "example.com")))
            );

            assert!(server_txn.name_to_uuid(audit, "testperson1") == Ok(tuuid));

            // delete
            let de_sin = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "name",
                    PartialValue::new_iname("testperson1")
                )))
            };
            assert!(server_txn.delete(audit, &de_sin).is_ok());

            // all should fail
            assert!(
                server_txn.uuid_to_rdn(audit, &tuuid)
                    == Ok("uuid=cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string())
            );

            assert!(server_txn.uuid_to_spn(audit, &tuuid) == Ok(None));

            assert!(server_txn.name_to_uuid(audit, "testperson1").is_err());

            // revive
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");
            let rre_rc = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin,
                    filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rre_rc).is_ok());

            // all checks pass

            assert!(
                server_txn.uuid_to_rdn(audit, &tuuid)
                    == Ok("spn=testperson1@example.com".to_string())
            );

            assert!(
                server_txn.uuid_to_spn(audit, &tuuid)
                    == Ok(Some(Value::new_spn_str("testperson1", "example.com")))
            );

            assert!(server_txn.name_to_uuid(audit, "testperson1") == Ok(tuuid));
        })
    }

    #[test]
    fn test_qs_clone_value() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());
            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // test attr not exist
            let r1 =
                server_txn.clone_value(audit, &"tausau".to_string(), &"naoeutnhaou".to_string());

            assert!(r1.is_err());

            // test attr not-normalised (error)
            // test attr not-reference
            let r2 = server_txn.clone_value(audit, &"NaMe".to_string(), &"NaMe".to_string());

            assert!(r2.is_err());

            // test attr reference
            let r3 =
                server_txn.clone_value(audit, &"member".to_string(), &"testperson1".to_string());

            assert!(r3 == Ok(Value::new_refer_s("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap()));

            // test attr reference already resolved.
            let r4 = server_txn.clone_value(
                audit,
                &"member".to_string(),
                &"cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string(),
            );

            debug!("{:?}", r4);
            assert!(r4 == Ok(Value::new_refer_s("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap()));
        })
    }

    #[test]
    fn test_qs_dynamic_schema_class() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("testclass")),
                ("name", Value::new_iname("testobj1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                )
            );

            // Class definition
            let e_cd = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("classtype")),
                ("classname", Value::new_iutf8("testclass")),
                (
                    "uuid",
                    Value::new_uuids("cfcae205-31c3-484b-8ced-667d1709c5e3").expect("uuid")
                ),
                ("description", Value::new_utf8s("Test Class")),
                ("may", Value::new_iutf8("name"))
            );
            let server_txn = server.write(duration_from_epoch_now());
            // Add a new class.
            let ce_class = CreateEvent::new_internal(vec![e_cd.clone()]);
            assert!(server_txn.create(audit, &ce_class).is_ok());
            // Trying to add it now should fail.
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // Add the class to an object
            // should work
            let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_work).is_ok());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // delete the class
            let de_class = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "classname",
                    PartialValue::new_class("testclass")
                )))
            };
            assert!(server_txn.delete(audit, &de_class).is_ok());
            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // Trying to add now should fail
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());
            // Search our entry
            let testobj1 = server_txn
                .internal_search_uuid(
                    audit,
                    &Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap(),
                )
                .expect("failed");
            assert!(testobj1.attribute_value_pres("class", &PartialValue::new_class("testclass")));

            // Should still be good
            server_txn.commit(audit).expect("should not fail");
            // Commit.
        })
    }

    #[test]
    fn test_qs_dynamic_schema_attr() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("extensibleobject")),
                ("name", Value::new_iname("testobj1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("testattr", Value::new_utf8s("test"))
            );

            // Attribute definition
            let e_ad = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("attributetype")),
                (
                    "uuid",
                    Value::new_uuids("cfcae205-31c3-484b-8ced-667d1709c5e3").expect("uuid")
                ),
                ("attributename", Value::new_iutf8("testattr")),
                ("description", Value::new_utf8s("Test Attribute")),
                ("multivalue", Value::new_bool(false)),
                ("unique", Value::new_bool(false)),
                ("syntax", Value::new_syntaxs("UTF8STRING").expect("syntax"))
            );

            let server_txn = server.write(duration_from_epoch_now());
            // Add a new attribute.
            let ce_attr = CreateEvent::new_internal(vec![e_ad.clone()]);
            assert!(server_txn.create(audit, &ce_attr).is_ok());
            // Trying to add it now should fail. (use extensible object)
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // Add the attr to an object
            // should work
            let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_work).is_ok());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // delete the attr
            let de_attr = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq(
                    "attributename",
                    PartialValue::new_iutf8("testattr")
                )))
            };
            assert!(server_txn.delete(audit, &de_attr).is_ok());
            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write(duration_from_epoch_now());
            // Trying to add now should fail
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());
            // Search our attribute - should FAIL
            let filt = filter!(f_eq("testattr", PartialValue::new_utf8s("test")));
            assert!(server_txn.internal_search(audit, filt).is_err());
            // Search the entry - the attribute will still be present
            // even if we can't search on it.
            let testobj1 = server_txn
                .internal_search_uuid(
                    audit,
                    &Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap(),
                )
                .expect("failed");
            assert!(testobj1.attribute_value_pres("testattr", &PartialValue::new_utf8s("test")));

            server_txn.commit(audit).expect("should not fail");
            // Commit.
        })
    }

    #[test]
    fn test_qs_modify_password_only() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("person")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("testperson1")),
                (
                    "uuid",
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
                ),
                ("description", Value::new_utf8s("testperson1")),
                ("displayname", Value::new_utf8s("testperson1"))
            );
            let server_txn = server.write(duration_from_epoch_now());
            // Add the entry. Today we have no syntax to take simple str to a credential
            // but honestly, that's probably okay :)
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Build the credential.
            let p = CryptoPolicy::minimum();
            let cred = Credential::new_password_only(&p, "test_password").unwrap();
            let v_cred = Value::new_credential("primary", cred);
            assert!(v_cred.validate());

            // now modify and provide a primary credential.
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    ModifyList::new_list(vec![Modify::Present(
                        AttrString::from("primary_credential"),
                        v_cred,
                    )]),
                )
            };
            // go!
            assert!(server_txn.modify(audit, &me_inv_m).is_ok());

            // assert it exists and the password checks out
            let test_ent = server_txn
                .internal_search_uuid(
                    audit,
                    &Uuid::parse_str("cc8e95b4-c24f-4d68-ba54-8bed76f63930").unwrap(),
                )
                .expect("failed");
            // get the primary ava
            let cred_ref = test_ent
                .get_ava_single_credential("primary_credential")
                .expect("Failed");
            // do a pw check.
            assert!(cred_ref.verify_password("test_password").unwrap());
        })
    }

    fn create_user(name: &str, uuid: &str) -> Entry<EntryInit, EntryNew> {
        entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname(name)),
            ("uuid", Value::new_uuids(uuid).expect("uuid")),
            ("description", Value::new_utf8s("testperson-entry")),
            ("displayname", Value::new_utf8s(name))
        )
    }

    fn create_group(name: &str, uuid: &str, members: &[&str]) -> Entry<EntryInit, EntryNew> {
        let mut e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("name", Value::new_iname(name)),
            ("uuid", Value::new_uuids(uuid).expect("uuid")),
            ("description", Value::new_utf8s("testgroup-entry"))
        );
        members
            .iter()
            .for_each(|m| e1.add_ava("member", Value::new_refer_s(m).unwrap()));
        e1
    }

    fn check_entry_has_mo(
        qs: &QueryServerWriteTransaction,
        audit: &mut AuditScope,
        name: &str,
        mo: &str,
    ) -> bool {
        let e = qs
            .internal_search(audit, filter!(f_eq("name", PartialValue::new_iname(name))))
            .unwrap()
            .pop()
            .unwrap();

        e.attribute_value_pres("memberof", &PartialValue::new_refer_s(mo).unwrap())
    }

    #[test]
    fn test_qs_revive_advanced_directmemberships() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create items
            let server_txn = server.write(duration_from_epoch_now());
            let admin = server_txn
                .internal_search_uuid(audit, &UUID_ADMIN)
                .expect("failed");

            // Right need a user in a direct group.
            let u1 = create_user("u1", "22b47373-d123-421f-859e-9ddd8ab14a2a");
            let g1 = create_group(
                "g1",
                "cca2bbfc-5b43-43f3-be9e-f5b03b3defec",
                &["22b47373-d123-421f-859e-9ddd8ab14a2a"],
            );

            // Need a user in A -> B -> User, such that A/B are re-adde as MO
            let u2 = create_user("u2", "5c19a4a2-b9f0-4429-b130-5782de5fddda");
            let g2a = create_group(
                "g2a",
                "e44cf9cd-9941-44cb-a02f-307b6e15ac54",
                &["5c19a4a2-b9f0-4429-b130-5782de5fddda"],
            );
            let g2b = create_group(
                "g2b",
                "d3132e6e-18ce-4b87-bee1-1d25e4bfe96d",
                &["e44cf9cd-9941-44cb-a02f-307b6e15ac54"],
            );

            // Need a user in a group that is recycled after, then revived at the same time.
            let u3 = create_user("u3", "68467a41-6e8e-44d0-9214-a5164e75ca03");
            let g3 = create_group(
                "g3",
                "36048117-e479-45ed-aeb5-611e8d83d5b1",
                &["68467a41-6e8e-44d0-9214-a5164e75ca03"],
            );

            // A user in a group that is recycled, user is revived, THEN the group is. Group
            // should be present in MO after the second revive.
            let u4 = create_user("u4", "d696b10f-1729-4f1a-83d0-ca06525c2f59");
            let g4 = create_group(
                "g4",
                "d5c59ac6-c533-4b00-989f-d0e183f07bab",
                &["d696b10f-1729-4f1a-83d0-ca06525c2f59"],
            );

            let ce = CreateEvent::new_internal(vec![u1, g1, u2, g2a, g2b, u3, g3, u4, g4]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Now recycle the needed entries.
            let de = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_or(vec![
                    f_eq("name", PartialValue::new_iname("u1")),
                    f_eq("name", PartialValue::new_iname("u2")),
                    f_eq("name", PartialValue::new_iname("u3")),
                    f_eq("name", PartialValue::new_iname("g3")),
                    f_eq("name", PartialValue::new_iname("u4")),
                    f_eq("name", PartialValue::new_iname("g4"))
                ])))
            };
            assert!(server_txn.delete(audit, &de).is_ok());

            // Now revive and check each one, one at a time.
            let rev1 = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin.clone(),
                    filter_all!(f_eq("name", PartialValue::new_iname("u1"))),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rev1).is_ok());
            // check u1 contains MO ->
            assert!(check_entry_has_mo(
                &server_txn,
                audit,
                "u1",
                "cca2bbfc-5b43-43f3-be9e-f5b03b3defec"
            ));

            // Revive u2 and check it has two mo.
            let rev2 = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin.clone(),
                    filter_all!(f_eq("name", PartialValue::new_iname("u2"))),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rev2).is_ok());
            assert!(check_entry_has_mo(
                &server_txn,
                audit,
                "u2",
                "e44cf9cd-9941-44cb-a02f-307b6e15ac54"
            ));
            assert!(check_entry_has_mo(
                &server_txn,
                audit,
                "u2",
                "d3132e6e-18ce-4b87-bee1-1d25e4bfe96d"
            ));

            // Revive u3 and g3 at the same time.
            let rev3 = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin.clone(),
                    filter_all!(f_or(vec![
                        f_eq("name", PartialValue::new_iname("u3")),
                        f_eq("name", PartialValue::new_iname("g3"))
                    ])),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rev3).is_ok());
            assert!(
                check_entry_has_mo(
                    &server_txn,
                    audit,
                    "u3",
                    "36048117-e479-45ed-aeb5-611e8d83d5b1"
                ) == false
            );

            // Revive u4, should NOT have the MO.
            let rev4a = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin.clone(),
                    filter_all!(f_eq("name", PartialValue::new_iname("u4"))),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rev4a).is_ok());
            assert!(
                check_entry_has_mo(
                    &server_txn,
                    audit,
                    "u4",
                    "d5c59ac6-c533-4b00-989f-d0e183f07bab"
                ) == false
            );

            // Now revive g4, should allow MO onto u4.
            let rev4b = unsafe {
                ReviveRecycledEvent::new_impersonate_entry(
                    admin,
                    filter_all!(f_eq("name", PartialValue::new_iname("g4"))),
                )
            };
            assert!(server_txn.revive_recycled(audit, &rev4b).is_ok());
            assert!(
                check_entry_has_mo(
                    &server_txn,
                    audit,
                    "u4",
                    "d5c59ac6-c533-4b00-989f-d0e183f07bab"
                ) == false
            );

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    /*
    #[test]
    fn test_qs_schema_dump_attrs() {
        run_test!(|server: &QueryServer, _audit: &mut AuditScope| {
            use crate::schema::SchemaTransaction;
            let server_txn = server.write();
            let schema = server_txn.get_schema();

            for k in schema.get_attributes().keys() {
                debug!("{}", k);
            }
            debug!("====");
            for k in schema.get_classes().keys() {
                debug!("{}", k);
            }

        })
    }
    */

    #[test]
    fn test_qs_upgrade_entry_attrs() {
        run_test_no_init!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write(duration_from_epoch_now());
            assert!(server_txn
                .upgrade_reindex(audit, SYSTEM_INDEX_VERSION)
                .is_ok());
            assert!(server_txn.commit(audit).is_ok());

            let server_txn = server.write(duration_from_epoch_now());
            server_txn.initialise_schema_core(audit).unwrap();
            server_txn.initialise_schema_idm(audit).unwrap();
            assert!(server_txn.commit(audit).is_ok());

            let server_txn = server.write(duration_from_epoch_now());
            assert!(server_txn
                .upgrade_reindex(audit, SYSTEM_INDEX_VERSION + 1)
                .is_ok());
            assert!(server_txn.commit(audit).is_ok());

            let server_txn = server.write(duration_from_epoch_now());
            assert!(server_txn
                .internal_migrate_or_create_str(audit, JSON_SYSTEM_INFO_V1)
                .is_ok());
            assert!(server_txn
                .internal_migrate_or_create_str(audit, JSON_DOMAIN_INFO_V1)
                .is_ok());
            assert!(server_txn
                .internal_migrate_or_create_str(audit, JSON_SYSTEM_CONFIG_V1)
                .is_ok());
            assert!(server_txn.commit(audit).is_ok());

            let server_txn = server.write(duration_from_epoch_now());
            // ++ Mod the schema to set name to the old string type
            let me_syn = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_or!([
                        f_eq("attributename", PartialValue::new_iutf8("name")),
                        f_eq("attributename", PartialValue::new_iutf8("domain_name")),
                    ])),
                    ModifyList::new_purge_and_set(
                        "syntax",
                        Value::new_syntaxs("UTF8STRING_INSENSITIVE").unwrap(),
                    ),
                )
            };
            assert!(server_txn.modify(audit, &me_syn).is_ok());
            assert!(server_txn.commit(audit).is_ok());

            let server_txn = server.write(duration_from_epoch_now());
            // ++ Mod domain name and name to be the old type.
            let me_dn = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("uuid", PartialValue::new_uuidr(&UUID_DOMAIN_INFO))),
                    ModifyList::new_list(vec![
                        Modify::Purged(AttrString::from("name")),
                        Modify::Purged(AttrString::from("domain_name")),
                        Modify::Present(AttrString::from("name"), Value::new_iutf8("domain_local")),
                        Modify::Present(
                            AttrString::from("domain_name"),
                            Value::new_iutf8("example.com"),
                        ),
                    ]),
                )
            };
            assert!(server_txn.modify(audit, &me_dn).is_ok());
            // Now, both the types are invalid.
            assert!(server_txn.commit(audit).is_ok());

            // We can't just re-run the migrate here because name takes it's definition from
            // in memory, and we can't re-run the initial memory gen. So we just fix it to match
            // what the migrate "would do".
            let server_txn = server.write(duration_from_epoch_now());
            let me_syn = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_or!([
                        f_eq("attributename", PartialValue::new_iutf8("name")),
                        f_eq("attributename", PartialValue::new_iutf8("domain_name")),
                    ])),
                    ModifyList::new_purge_and_set(
                        "syntax",
                        Value::new_syntaxs("UTF8STRING_INAME").unwrap(),
                    ),
                )
            };
            assert!(server_txn.modify(audit, &me_syn).is_ok());
            assert!(server_txn.commit(audit).is_ok());

            // ++ Run the upgrade for X to Y
            let server_txn = server.write(duration_from_epoch_now());
            assert!(server_txn.migrate_2_to_3(audit).is_ok());
            assert!(server_txn.commit(audit).is_ok());

            // Assert that it migrated and worked as expected.
            let server_txn = server.write(duration_from_epoch_now());
            let domain = server_txn
                .internal_search_uuid(audit, &UUID_DOMAIN_INFO)
                .expect("failed");
            // ++ assert all names are iname
            domain
                .get_ava("name")
                .expect("no name?")
                .for_each(|v| assert!(v.is_iname()));
            // ++ assert all domain/domain_name are iname
            domain
                .get_ava("domain_name")
                .expect("no domain_name?")
                .for_each(|v| assert!(v.is_iname()));
            assert!(server_txn.commit(audit).is_ok());
        })
    }
}
