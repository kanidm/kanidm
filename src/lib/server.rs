// This is really only used for long lived, high level types that need clone
// that otherwise can't be cloned. Think Mutex.
// use actix::prelude::*;
use std::sync::Arc;

use crate::audit::AuditScope;
use crate::be::{Backend, BackendReadTransaction, BackendTransaction, BackendWriteTransaction};

use crate::access::{
    AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlSearch,
    AccessControls, AccessControlsReadTransaction, AccessControlsTransaction,
    AccessControlsWriteTransaction,
};
use crate::constants::{
    JSON_ADMIN_V1, JSON_ANONYMOUS_V1, JSON_IDM_ADMINS_ACP_REVIVE_V1, JSON_IDM_ADMINS_ACP_SEARCH_V1,
    JSON_IDM_ADMINS_V1, JSON_IDM_SELF_ACP_READ_V1, JSON_SCHEMA_ATTR_DISPLAYNAME,
    JSON_SCHEMA_ATTR_MAIL, JSON_SCHEMA_ATTR_PASSWORD, JSON_SCHEMA_ATTR_SSH_PUBLICKEY,
    JSON_SCHEMA_CLASS_ACCOUNT, JSON_SCHEMA_CLASS_GROUP, JSON_SCHEMA_CLASS_PERSON,
    JSON_SYSTEM_INFO_V1,
};
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryNormalised, EntryValid};
use crate::error::{ConsistencyError, OperationError, SchemaError};
use crate::event::{
    CreateEvent, DeleteEvent, Event, EventOrigin, ExistsEvent, ModifyEvent, ReviveRecycledEvent,
    SearchEvent,
};
use crate::filter::{Filter, FilterInvalid, FilterValid};
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::plugins::Plugins;
use crate::schema::{
    Schema, SchemaAttribute, SchemaClass, SchemaReadTransaction, SchemaTransaction,
    SchemaWriteTransaction, SyntaxType,
};

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code
pub trait QueryServerTransaction {
    type BackendTransactionType: BackendTransaction;
    fn get_be_txn(&self) -> &Self::BackendTransactionType;

    type SchemaTransactionType: SchemaTransaction;
    fn get_schema(&self) -> &Self::SchemaTransactionType;

    type AccessControlsTransactionType: AccessControlsTransaction;
    fn get_accesscontrols(&self) -> &Self::AccessControlsTransactionType;

    fn search_ext(
        &self,
        au: &mut AuditScope,
        se: &SearchEvent,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        /*
         * This just wraps search, but it's for the external interface
         * so as a result it also reduces the entry set's attributes at
         * the end.
         */
        let entries = self.search(au, se)?;

        let mut audit_acp = AuditScope::new("access_control_profiles");
        let access = self.get_accesscontrols();
        let acp_res = access.search_filter_entry_attributes(&mut audit_acp, se, entries);
        au.append_scope(audit_acp);
        // Log and fail if something went wrong.
        let entries_filtered = try_audit!(au, acp_res);

        // This is the final entry set that was reduced.
        Ok(entries_filtered)
    }

    fn search(
        &self,
        au: &mut AuditScope,
        se: &SearchEvent,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        audit_log!(au, "search: filter -> {:?}", se.filter);

        // This is an important security step because it prevents us from
        // performing un-indexed searches on attr's that don't exist in the
        // server. This is why ExtensibleObject can only take schema that
        // exists in the server, not arbitrary attr names.
        //
        // This normalises and validates in a single step.
        /*
        let vf = match se.filter.validate(self.get_schema()) {
            Ok(f) => f,
            // TODO: Do something with this error
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        audit_log!(au, "search: valid filter -> {:?}", vf);
        */

        // Now resolve all references.
        let vfr = try_audit!(au, se.filter.resolve(&se.event));

        // TODO: Assert access control allows the filter and requested attrs.

        /*
        let mut audit_plugin_pre = AuditScope::new("plugin_pre_search");
        let plug_pre_res = Plugins::run_pre_search(&mut audit_plugin_pre);
        au.append_scope(audit_plugin_pre);

        match plug_pre_res {
            Ok(_) => {}
            Err(e) => {
                audit_log!(au, "Search operation failed (plugin), {:?}", e);
                return Err(e);
            }
        }
        */

        let mut audit_be = AuditScope::new("backend_search");
        let res = self
            .get_be_txn()
            .search(&mut audit_be, &vfr)
            .map(|r| r)
            .map_err(|_| OperationError::Backend);
        au.append_scope(audit_be);

        let res = try_audit!(au, res);

        // Apply ACP before we let the plugins "have at it".
        // WARNING; for external searches this is NOT the only
        // ACP application. There is a second application to reduce the
        // attribute set on the entries!
        //
        // TODO: Make a search_ext that applies search_filter_entry_attributes
        // and does Entry -> EntryReduced.
        let mut audit_acp = AuditScope::new("access_control_profiles");
        let access = self.get_accesscontrols();
        let acp_res = access.search_filter_entries(&mut audit_acp, se, res);

        au.append_scope(audit_acp);
        let acp_res = try_audit!(au, acp_res);

        /*
        let mut audit_plugin_post = AuditScope::new("plugin_post_search");
        let plug_post_res = Plugins::run_post_search(&mut audit_plugin_post);
        au.append_scope(audit_plugin_post);

        match plug_post_res {
            Ok(_) => {}
            Err(e) => {
                audit_log!(au, "Search operation failed (plugin), {:?}", e);
                return Err(e);
            }
        }
        */

        Ok(acp_res)
    }

    fn exists(&self, au: &mut AuditScope, ee: &ExistsEvent) -> Result<bool, OperationError> {
        let mut audit_be = AuditScope::new("backend_exists");

        // How to get schema?
        /*
        let vf = match ee.filter.validate(self.get_schema()) {
            Ok(f) => f,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };
        */

        let vfr = try_audit!(au, ee.filter.resolve(&ee.event));

        let res = self
            .get_be_txn()
            .exists(&mut audit_be, &vfr)
            .map(|r| r)
            .map_err(|_| OperationError::Backend);
        au.append_scope(audit_be);
        res
    }

    // TODO: Should this actually be names_to_uuids and we do batches?
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
    fn name_to_uuid(
        &self,
        audit: &mut AuditScope,
        name: &String,
    ) -> Result<String, OperationError> {
        // For now this just constructs a filter and searches, but later
        // we could actually improve this to contact the backend and do
        // index searches, completely bypassing id2entry.

        // construct the filter
        let filt = filter!(f_eq("name", name));
        audit_log!(audit, "name_to_uuid: name -> {:?}", name);

        // Internal search - DO NOT SEARCH TOMBSTONES AND RECYCLE
        let res = match self.internal_search(audit, filt) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        audit_log!(audit, "name_to_uuid: results -- {:?}", res);

        if res.len() == 0 {
            // If result len == 0, error no such result
            return Err(OperationError::NoMatchingEntries);
        } else if res.len() >= 2 {
            // if result len >= 2, error, invaid entry state.
            return Err(OperationError::InvalidDBState);
        }

        // TODO: fine for 0/1 case, but check len for >= 2 to eliminate that case.
        let e = res.first().ok_or(OperationError::NoMatchingEntries)?;
        // Get the uuid from the entry. Again, check it exists, and only one.
        let uuid_res: String = e.get_uuid().to_string();

        audit_log!(audit, "name_to_uuid: uuid <- {:?}", uuid_res);

        Ok(uuid_res)
    }

    fn uuid_to_name(
        &self,
        audit: &mut AuditScope,
        uuid: &String,
    ) -> Result<String, OperationError> {
        // construct the filter
        let filt = filter!(f_eq("uuid", uuid));
        audit_log!(audit, "uuid_to_name: uuid -> {:?}", uuid);

        // Internal search - DO NOT SEARCH TOMBSTONES AND RECYCLE
        let res = match self.internal_search(audit, filt) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        audit_log!(audit, "uuid_to_name: results -- {:?}", res);

        if res.len() == 0 {
            // If result len == 0, error no such result
            return Err(OperationError::NoMatchingEntries);
        } else if res.len() >= 2 {
            // if result len >= 2, error, invaid entry state.
            return Err(OperationError::InvalidDBState);
        }

        // fine for 0/1 case, but check len for >= 2 to eliminate that case.
        let e = res.first().ok_or(OperationError::NoMatchingEntries)?;
        // Get the uuid from the entry. Again, check it exists, and only one.
        let name_res = match e.get_ava(&String::from("name")) {
            Some(vas) => match vas.first() {
                Some(u) => u.clone(),
                None => return Err(OperationError::InvalidEntryState),
            },
            None => return Err(OperationError::InvalidEntryState),
        };

        audit_log!(audit, "uuid_to_name: name <- {:?}", name_res);

        Ok(name_res)
    }

    // From internal, generate an exists event and dispatch
    fn internal_exists(
        &self,
        au: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<bool, OperationError> {
        // Check the filter
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        // Build an exists event
        let ee = ExistsEvent::new_internal(f_valid);
        // Submit it
        let mut audit_int = AuditScope::new("internal_exists");
        let res = self.exists(&mut audit_int, &ee);
        au.append_scope(audit_int);
        // return result
        res
    }

    fn internal_search(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let se = SearchEvent::new_internal(f_valid);
        let mut audit_int = AuditScope::new("internal_search");
        let res = self.search(&mut audit_int, &se);
        audit.append_scope(audit_int);
        res
    }

    fn impersonate_search_valid(
        &self,
        audit: &mut AuditScope,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        let mut audit_int = AuditScope::new("impersonate_search");
        let res = self.search(&mut audit_int, &se);
        audit.append_scope(audit_int);
        res
    }

    // Who they are will go here
    fn impersonate_search(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Event,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        self.impersonate_search_valid(audit, f_valid, f_intent_valid, event)
    }

    // Get a single entry by it's UUID. This is heavily relied on for internal
    // server operations, especially in login and acp checks for acp.
    fn internal_search_uuid(
        &self,
        audit: &mut AuditScope,
        uuid: &str,
    ) -> Result<Entry<EntryValid, EntryCommitted>, OperationError> {
        let filter = filter!(f_eq("uuid", uuid));
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let se = SearchEvent::new_internal(f_valid);
        let mut audit_int = AuditScope::new("internal_search_uuid");
        let res = self.search(&mut audit_int, &se);
        audit.append_scope(audit_int);
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
    }

    // Do a schema aware clone, that fixes values that need some kind of alteration
    // or lookup from the front end.
    //
    // For example, reference types.
    //
    // For passwords, hashing and changes will take place later.
    //
    // TODO: It could be argued that we should have a proper "Value" type, so that we can
    // take care of this a bit cleaner, and do the checks in that, but I think for
    // now this is good enough.
    fn clone_value(
        &self,
        audit: &mut AuditScope,
        attr: &String,
        value: &String,
    ) -> Result<String, OperationError> {
        let schema = self.get_schema();
        // TODO: Normalise the attr, else lookup with fail ....
        let schema_name = schema
            .get_attributes()
            .get("name")
            .expect("Schema corrupted");

        // TODO: Should we return the normalise attr?
        let temp_a = schema_name.normalise_value(attr);

        // Lookup the attr
        match schema.get_attributes().get(&temp_a) {
            Some(schema_a) => {
                // Now check the type of the attribute ...
                match schema_a.syntax {
                    SyntaxType::REFERENCE_UUID => {
                        match schema_a.validate_value(value) {
                            // So, if possible, resolve the value
                            // to a concrete uuid.
                            Ok(_) => {
                                // TODO: Should this check existance?
                                // Could this be a security risk for disclosure?
                                //  So it would only reveal if a name/uuid did/did not exist
                                // because this pre-acp check, but inversely, this means if we
                                // fail fast here, we would not hae a situation where we would create
                                // then ref-int would invalidate the structure immediately.
                                //
                                // I can see a situation where you would modify, and then immediately
                                // have the mod removed because it would fail the refint (IE add
                                // raw uuid X, then immediately it's removed)
                                //
                                // This would never be the case with resolved uuid's though, because
                                // they are inside the txn. So do we just ignore this as an edge case?
                                //
                                // For now, refint will fight the raw uuid's, and will be tested to
                                // assume they don't exist on create/mod/etc.. If this check was added
                                // then refint may not need post_create handlers.
                                Ok(value.clone())
                            }
                            Err(_) => {
                                // it's not a uuid, try to resolve it.
                                // TODO: If this errors, should we actually pass
                                // back a place holder "no such uuid" and then
                                // fail an exists check later?
                                Ok(self.name_to_uuid(audit, value)?)
                            }
                        }
                    }
                    _ => {
                        // Probs okay.
                        Ok(value.clone())
                    }
                }
            }
            None => {
                // Welp, you'll break when we hit schema validation soon anyway.
                // Just clone in this case ...
                // TODO: Honestly, we could just return the schema error here ...
                Ok(value.clone())
            }
        }
    }

    // In the opposite direction, we can resolve values for presentation
    fn resolve_value(&self, _attr: &String, value: &String) -> Result<String, OperationError> {
        Ok(value.clone())
    }
}

pub struct QueryServerReadTransaction {
    be_txn: BackendReadTransaction,
    // Anything else? In the future, we'll need to have a schema transaction
    // type, maybe others?
    schema: SchemaReadTransaction,
    accesscontrols: AccessControlsReadTransaction,
}

// Actually conduct a search request
// This is the core of the server, as it processes the entire event
// applies all parts required in order and more.
impl QueryServerTransaction for QueryServerReadTransaction {
    type BackendTransactionType = BackendReadTransaction;

    fn get_be_txn(&self) -> &BackendReadTransaction {
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

impl QueryServerReadTransaction {
    // Verify the data content of the server is as expected. This will probably
    // call various functions for validation, including possibly plugin
    // verifications.
    fn verify(&self, au: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let mut audit = AuditScope::new("verify");

        // If we fail after backend, we need to return NOW because we can't
        // assert any other faith in the DB states.
        //  * backend
        let be_errs = self.get_be_txn().verify();

        if be_errs.len() != 0 {
            au.append_scope(audit);
            return be_errs;
        }

        //  * in memory schema consistency.
        let sc_errs = self.get_schema().validate(&mut audit);

        if sc_errs.len() != 0 {
            au.append_scope(audit);
            return sc_errs;
        }

        //  * Indexing (req be + sch )
        /*
        idx_errs = self.get_be_txn()
            .verify_indexes();

        if idx_errs.len() != 0 {
            au.append_scope(audit);
            return idx_errs;
        }
         */

        // Ok BE passed, lets move on to the content.
        // Most of our checks are in the plugins, so we let them
        // do their job.

        // Now, call the plugins verification system.
        let pl_errs = Plugins::run_verify(&mut audit, self);

        // Finish up ...
        au.append_scope(audit);
        pl_errs
    }
}

pub struct QueryServerWriteTransaction<'a> {
    committed: bool,
    // be_write_txn: BackendWriteTransaction,
    // schema_write: SchemaWriteTransaction,
    // read: QueryServerReadTransaction,
    be_txn: BackendWriteTransaction,
    schema: SchemaWriteTransaction<'a>,
    accesscontrols: AccessControlsWriteTransaction<'a>,
}

impl<'a> QueryServerTransaction for QueryServerWriteTransaction<'a> {
    type BackendTransactionType = BackendWriteTransaction;

    fn get_be_txn(&self) -> &BackendWriteTransaction {
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

#[derive(Clone)]
pub struct QueryServer {
    // log: actix::Addr<EventLog>,
    be: Backend,
    schema: Arc<Schema>,
    accesscontrols: Arc<AccessControls>,
}

impl QueryServer {
    pub fn new(be: Backend, schema: Schema) -> Self {
        // log_event!(log, "Starting query worker ...");
        QueryServer {
            be: be,
            schema: Arc::new(schema),
            accesscontrols: Arc::new(AccessControls::new()),
        }
    }

    pub fn read(&self) -> QueryServerReadTransaction {
        QueryServerReadTransaction {
            be_txn: self.be.read(),
            schema: self.schema.read(),
            accesscontrols: self.accesscontrols.read(),
        }
    }

    pub fn write(&self) -> QueryServerWriteTransaction {
        QueryServerWriteTransaction {
            // I think this is *not* needed, because commit is mut self which should
            // take ownership of the value, and cause the commit to "only be run
            // once".
            //
            // The commited flag is however used for abort-specific code in drop
            // which today I don't think we have ... yet.
            committed: false,
            be_txn: self.be.write(),
            schema: self.schema.write(),
            accesscontrols: self.accesscontrols.write(),
        }
    }

    pub(crate) fn initialise_helper(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let ts_write_1 = self.write();
        ts_write_1
            .initialise_schema_core(audit)
            .and_then(|_| ts_write_1.commit(audit))?;

        let ts_write_2 = self.write();
        ts_write_2
            .initialise_schema_idm(audit)
            .and_then(|_| ts_write_2.commit(audit))?;

        let ts_write_3 = self.write();
        ts_write_3
            .initialise_idm(audit)
            .and_then(|_| ts_write_3.commit(audit))
    }

    pub fn verify(&self, au: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let r_txn = self.read();
        r_txn.verify(au)
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    pub fn create(&self, au: &mut AuditScope, ce: &CreateEvent) -> Result<(), OperationError> {
        // The create event is a raw, read only representation of the request
        // that was made to us, including information about the identity
        // performing the request.

        // Log the request

        // TODO: Do we need limits on number of creates, or do we constraint
        // based on request size in the frontend?

        // Copy the entries to a writeable form.
        let candidates: Vec<Entry<EntryInvalid, EntryNew>> =
            ce.entries.iter().map(|er| er.clone()).collect();

        // TODO: Normalise but DO NOT validate the entries.
        let norm_cand: Result<Vec<Entry<EntryNormalised, EntryNew>>, _> = candidates
            .into_iter()
            .map(|e| {
                e.normalise(&self.schema)
                    .map_err(|er| OperationError::SchemaViolation(er))
            })
            .collect();

        let norm_cand = try_audit!(au, norm_cand);

        // Handle the error.

        // Do we have rights to perform these creates?
        // create_allow_operation
        let mut audit_acp = AuditScope::new("access_control_profiles");
        let access = self.get_accesscontrols();
        let acp_res = access.create_allow_operation(&mut audit_acp, ce, &norm_cand);
        au.append_scope(audit_acp);
        if try_audit!(au, acp_res) != true {
            return Err(OperationError::AccessDenied);
        }

        // Invalidate them all again ...
        let mut candidates: Vec<Entry<EntryInvalid, EntryNew>> =
            norm_cand.into_iter().map(|e| e.invalidate()).collect();

        // run any pre plugins, giving them the list of mutable candidates.
        // pre-plugins are defined here in their correct order of calling!
        // I have no intent to make these dynamic or configurable.

        let mut audit_plugin_pre_transform = AuditScope::new("plugin_pre_create_transform");
        let plug_pre_transform_res = Plugins::run_pre_create_transform(
            &mut audit_plugin_pre_transform,
            &self,
            &mut candidates,
            ce,
        );
        au.append_scope(audit_plugin_pre_transform);

        let _ = try_audit!(
            au,
            plug_pre_transform_res,
            "Create operation failed (plugin), {:?}"
        );

        // NOTE: This is how you map from Vec<Result<T>> to Result<Vec<T>>
        // remember, that you only get the first error and the iter terminates.

        // Now, normalise AND validate!

        let res: Result<Vec<Entry<EntryValid, EntryNew>>, OperationError> = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|er| OperationError::SchemaViolation(er))
            })
            .collect();

        let norm_cand: Vec<Entry<_, _>> = try_audit!(au, res);

        // Run any pre-create plugins now with schema validated entries.
        // This is important for normalisation of certain types IE class
        // or attributes for these checks.
        let mut audit_plugin_pre = AuditScope::new("plugin_pre_create");
        let plug_pre_res = Plugins::run_pre_create(&mut audit_plugin_pre, &self, &norm_cand, ce);
        au.append_scope(audit_plugin_pre);

        let _ = try_audit!(au, plug_pre_res, "Create operation failed (plugin), {:?}");

        let mut audit_be = AuditScope::new("backend_create");
        // We may change from ce.entries later to something else?
        let res = self
            .be_txn
            .create(&mut audit_be, &norm_cand)
            .map(|_| ())
            .map_err(|e| e);

        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Create operation failed (backend), {:?}", res);
            return res;
        }
        // Run any post plugins

        let mut audit_plugin_post = AuditScope::new("plugin_post_create");
        let plug_post_res = Plugins::run_post_create(&mut audit_plugin_post, &self, &norm_cand, ce);
        au.append_scope(audit_plugin_post);

        if plug_post_res.is_err() {
            audit_log!(au, "Create operation failed (plugin), {:?}", plug_post_res);
            return plug_post_res;
        }

        // We are complete, finalise logging and return

        audit_log!(au, "Create operation success");
        res
    }

    pub fn delete(&self, au: &mut AuditScope, de: &DeleteEvent) -> Result<(), OperationError> {
        // Do you have access to view all the set members? Reduce based on your
        // read permissions and attrs
        // THIS IS PRETTY COMPLEX SEE THE DESIGN DOC
        // In this case we need a search, but not INTERNAL to keep the same
        // associated credentials.
        // We only need to retrieve uuid though ...

        // Now, delete only what you can see
        let pre_candidates = match self.impersonate_search_valid(
            au,
            de.filter.clone(),
            de.filter_orig.clone(),
            &de.event,
        ) {
            Ok(results) => results,
            Err(e) => {
                audit_log!(au, "delete: error in pre-candidate selection {:?}", e);
                return Err(e);
            }
        };

        // Apply access controls to reduce the set if required.
        // delete_allow_operation
        let mut audit_acp = AuditScope::new("access_control_profiles");
        let access = self.get_accesscontrols();
        let acp_res = access.delete_allow_operation(&mut audit_acp, de, &pre_candidates);
        au.append_scope(audit_acp);
        if try_audit!(au, acp_res) != true {
            return Err(OperationError::AccessDenied);
        }

        // Is the candidate set empty?
        if pre_candidates.len() == 0 {
            audit_log!(au, "delete: no candidates match filter {:?}", de.filter);
            return Err(OperationError::NoMatchingEntries);
        };

        let modlist_inv = ModifyList::new_list(vec![Modify::Present(
            String::from("class"),
            String::from("recycled"),
        )]);

        let modlist = match modlist_inv.validate(&self.schema) {
            Ok(ml) => ml,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.clone().invalidate())
            .collect();

        candidates
            .iter_mut()
            .for_each(|er| er.apply_modlist(&modlist));

        audit_log!(au, "delete: candidates -> {:?}", candidates);

        // Pre delete plugs
        let mut audit_plugin_pre = AuditScope::new("plugin_pre_delete");
        let plug_pre_res =
            Plugins::run_pre_delete(&mut audit_plugin_pre, &self, &mut candidates, de);
        au.append_scope(audit_plugin_pre);

        if plug_pre_res.is_err() {
            audit_log!(au, "Delete operation failed (plugin), {:?}", plug_pre_res);
            return plug_pre_res;
        }

        let res: Result<Vec<Entry<EntryValid, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema))
            .collect();

        let del_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        let mut audit_be = AuditScope::new("backend_modify");

        let res = self.be_txn.modify(&mut audit_be, &del_cand);
        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Delete operation failed (backend), {:?}", res);
            return res;
        }

        // Post delete plugs
        let mut audit_plugin_post = AuditScope::new("plugin_post_delete");
        let plug_post_res = Plugins::run_post_delete(&mut audit_plugin_post, &self, &del_cand, de);
        au.append_scope(audit_plugin_post);

        if plug_post_res.is_err() {
            audit_log!(au, "Delete operation failed (plugin), {:?}", plug_post_res);
            return plug_post_res;
        }

        // Send result
        audit_log!(au, "Delete operation success");
        res
    }

    pub fn purge_tombstones(&self, au: &mut AuditScope) -> Result<(), OperationError> {
        // delete everything that is a tombstone.

        // Search for tombstones
        let ts = match self.internal_search(au, filter_all!(f_eq("class", "tombstone"))) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        // TODO: Has an appropriate amount of time/condition past (ie replication events?)

        // Delete them
        let mut audit_be = AuditScope::new("backend_delete");

        let res = self
            .be_txn
            // Change this to an update, not delete.
            .delete(&mut audit_be, &ts);
        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Tombstone purge operation failed (backend), {:?}", res);
            return res;
        }

        // Send result
        audit_log!(au, "Tombstone purge operation success");
        res
    }

    pub fn purge_recycled(&self, au: &mut AuditScope) -> Result<(), OperationError> {
        // Send everything that is recycled to tombstone
        // Search all recycled
        let rc = match self.internal_search(au, filter_all!(f_eq("class", "recycled"))) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        // Modify them to strip all avas except uuid
        let tombstone_cand = rc.iter().map(|e| e.to_tombstone()).collect();

        // Backend Modify
        let mut audit_be = AuditScope::new("backend_modify");

        let res = self.be_txn.modify(&mut audit_be, &tombstone_cand);
        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Purge recycled operation failed (backend), {:?}", res);
            return res;
        }

        // return
        audit_log!(au, "Purge recycled operation success");
        res
    }

    // Should this take a revive event?
    pub fn revive_recycled(
        &self,
        au: &mut AuditScope,
        re: &ReviveRecycledEvent,
    ) -> Result<(), OperationError> {
        // Revive an entry to live. This is a specialised (limited)
        // modify proxy.
        //
        // impersonate modify will require ability to search the class=recycled
        // and the ability to remove that from the object.

        // create the modify
        // tl;dr, remove the class=recycled
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            "class".to_string(),
            "recycled".to_string(),
        )]);

        let m_valid = try_audit!(
            au,
            modlist
                .validate(self.get_schema())
                .map_err(|e| OperationError::SchemaViolation(e))
        );

        // Now impersonate the modify
        self.impersonate_modify_valid(au, re.filter.clone(), re.filter.clone(), m_valid, &re.event)
    }

    pub fn modify(&self, au: &mut AuditScope, me: &ModifyEvent) -> Result<(), OperationError> {
        // Get the candidates.
        // Modify applies a modlist to a filter, so we need to internal search
        // then apply.

        // Validate input.

        // Is the modlist non zero?
        if me.modlist.len() == 0 {
            audit_log!(au, "modify: empty modify request");
            return Err(OperationError::EmptyRequest);
        }

        // Is the modlist valid?
        // This is now done in the event transform

        // Is the filter invalid to schema?
        // This is now done in the event transform

        // TODO: Fix this filter clone ....
        // Likely this will be fixed if search takes &filter, and then clone
        // to normalise, instead of attempting to mut the filter on norm.
        //
        // This also checks access controls due to use of the impersonation.
        let pre_candidates = match self.impersonate_search_valid(
            au,
            me.filter.clone(),
            me.filter_orig.clone(),
            &me.event,
        ) {
            Ok(results) => results,
            Err(e) => {
                audit_log!(au, "modify: error in pre-candidate selection {:?}", e);
                return Err(e);
            }
        };

        if pre_candidates.len() == 0 {
            match me.event.origin {
                EventOrigin::Internal => {
                    audit_log!(
                        au,
                        "modify: no candidates match filter ... continuing {:?}",
                        me.filter
                    );
                    return Ok(());
                }
                _ => {
                    audit_log!(
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
        let mut audit_acp = AuditScope::new("access_control_profiles");
        let access = self.get_accesscontrols();
        let acp_res = access.modify_allow_operation(&mut audit_acp, me, &pre_candidates);
        au.append_scope(audit_acp);
        if try_audit!(au, acp_res) != true {
            return Err(OperationError::AccessDenied);
        }

        // Clone a set of writeables.
        // Apply the modlist -> Remember, we have a set of origs
        // and the new modified ents.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| er.clone().invalidate())
            .collect();

        candidates
            .iter_mut()
            .for_each(|er| er.apply_modlist(&me.modlist));

        // let mut candidates = try_audit!(au, candidates);

        audit_log!(au, "modify: candidates -> {:?}", candidates);

        // Pre mod plugins
        let mut audit_plugin_pre = AuditScope::new("plugin_pre_modify");
        let plug_pre_res =
            Plugins::run_pre_modify(&mut audit_plugin_pre, &self, &mut candidates, me);
        au.append_scope(audit_plugin_pre);

        if plug_pre_res.is_err() {
            audit_log!(au, "Modify operation failed (plugin), {:?}", plug_pre_res);
            return plug_pre_res;
        }

        // TODO: There is a potential optimisation here, where if
        // candidates == pre-candidates, then we don't need to store anything
        // because we effectively just did an assert. However, like all
        // optimisations, this could be premature - so we for now, just
        // do the CORRECT thing and recommit as we may find later we always
        // want to add CSN's or other.
        //
        // memberOf actually wants the pre cand list and the norm_cand list to see what
        // changed. Could be optimised, but this is correct still ...

        let res: Result<Vec<Entry<EntryValid, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema))
            .collect();

        let norm_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        // Backend Modify
        let mut audit_be = AuditScope::new("backend_modify");

        let res = self.be_txn.modify(&mut audit_be, &norm_cand);
        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Modify operation failed (backend), {:?}", res);
            return res;
        }

        // Post Plugins
        let mut audit_plugin_post = AuditScope::new("plugin_post_modify");
        let plug_post_res = Plugins::run_post_modify(
            &mut audit_plugin_post,
            &self,
            &pre_candidates,
            &norm_cand,
            me,
        );
        au.append_scope(audit_plugin_post);

        if plug_post_res.is_err() {
            audit_log!(au, "Modify operation failed (plugin), {:?}", plug_post_res);
            return plug_post_res;
        }

        // return
        audit_log!(au, "Modify operation success");
        res
    }

    // These are where searches and other actions are actually implemented. This
    // is the "internal" version, where we define the event as being internal
    // only, allowing certain plugin by passes etc.

    pub fn internal_create(
        &self,
        audit: &mut AuditScope,
        entries: Vec<Entry<EntryInvalid, EntryNew>>,
    ) -> Result<(), OperationError> {
        // Start the audit scope
        let mut audit_int = AuditScope::new("internal_create");
        // Create the CreateEvent
        let ce = CreateEvent::new_internal(entries);
        let res = self.create(&mut audit_int, &ce);
        audit.append_scope(audit_int);
        res
    }

    pub fn internal_delete(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let mut audit_int = AuditScope::new("internal_delete");
        let de = DeleteEvent::new_internal(f_valid);
        let res = self.delete(&mut audit_int, &de);
        audit.append_scope(audit_int);
        res
    }

    pub fn internal_modify(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let mut audit_int = AuditScope::new("internal_modify");
        let me = ModifyEvent::new_internal(f_valid, m_valid);
        let res = self.modify(&mut audit_int, &me);
        audit.append_scope(audit_int);
        res
    }

    pub fn impersonate_modify_valid(
        &self,
        audit: &mut AuditScope,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        m_valid: ModifyList<ModifyValid>,
        event: &Event,
    ) -> Result<(), OperationError> {
        let mut audit_int = AuditScope::new("impersonate_modify");
        let me = ModifyEvent::new_impersonate(event, f_valid, f_intent_valid, m_valid);
        let res = self.modify(&mut audit_int, &me);
        audit.append_scope(audit_int);
        res
    }

    pub fn impersonate_modify(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
        event: &Event,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(|e| OperationError::SchemaViolation(e))?;
        self.impersonate_modify_valid(audit, f_valid, f_intent_valid, m_valid, event)
    }

    // internal server operation types.
    // These just wrap the fn create/search etc, but they allow
    // creating the needed create event with the correct internal flags
    // and markers. They act as though they have the highest level privilege
    // IE there are no access control checks.

    pub fn internal_exists_or_create(
        &self,
        _e: Entry<EntryValid, EntryNew>,
    ) -> Result<(), OperationError> {
        // If the thing exists, stop.
        // if not, create from Entry.
        unimplemented!()
    }

    pub fn internal_migrate_or_create_str(
        &self,
        audit: &mut AuditScope,
        e_str: &str,
    ) -> Result<(), OperationError> {
        let res = audit_segment!(audit, || serde_json::from_str(e_str)
            .map_err(|_| OperationError::SerdeJsonError)
            .and_then(
                |e: Entry<EntryValid, EntryNew>| self.internal_migrate_or_create(audit, e)
            ));
        audit_log!(audit, "internal_migrate_or_create_str -> result {:?}", res);
        assert!(res.is_ok());
        res
    }

    pub fn internal_migrate_or_create(
        &self,
        audit: &mut AuditScope,
        e: Entry<EntryValid, EntryNew>,
    ) -> Result<(), OperationError> {
        // if the thing exists, ensure the set of attributes on
        // Entry A match and are present (but don't delete multivalue, or extended
        // attributes in the situation.
        // If not exist, create from Entry B
        //
        // TODO: WARNING: this requires schema awareness for multivalue types!
        // We need to either do a schema aware merge, or we just overwrite those
        // few attributes.
        //
        // This will extra classes an attributes alone!
        let filt = match e.filter_from_attrs(&vec![String::from("uuid")]) {
            Some(f) => f,
            None => return Err(OperationError::FilterGeneration),
        };

        match self.internal_search(audit, filt.clone()) {
            Ok(results) => {
                if results.len() == 0 {
                    // It does not exist. Create it.
                    self.internal_create(audit, vec![e.invalidate()])
                } else if results.len() == 1 {
                    // If the thing is subset, pass
                    match e.gen_modlist_assert(&self.schema) {
                        Ok(modlist) => {
                            // Apply to &results[0]
                            audit_log!(audit, "Generated modlist -> {:?}", modlist);
                            self.internal_modify(audit, filt, modlist)
                        }
                        Err(_e) => {
                            unimplemented!()
                            // No action required.
                        }
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

    // Should this take a be_txn?
    pub fn internal_assert_or_create(
        &self,
        audit: &mut AuditScope,
        e: Entry<EntryValid, EntryNew>,
    ) -> Result<(), OperationError> {
        // If exists, ensure the object is exactly as provided
        // else, if not exists, create it. IE no extra or excess
        // attributes and classes.

        // Create a filter from the entry for assertion.
        let filt = match e.filter_from_attrs(&vec![String::from("uuid")]) {
            Some(f) => f,
            None => return Err(OperationError::FilterGeneration),
        };

        // Does it exist? (TODO: Should be search, not exists ...)
        match self.internal_search(audit, filt.clone()) {
            Ok(results) => {
                if results.len() == 0 {
                    // It does not exist. Create it.
                    self.internal_create(audit, vec![e.invalidate()])
                } else if results.len() == 1 {
                    // it exists. To guarantee content exactly as is, we compare if it's identical.
                    if !e.compare(&results[0]) {
                        self.internal_delete(audit, filt)
                            .and_then(|_| self.internal_create(audit, vec![e.invalidate()]))
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

    pub fn initialise_schema_core(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // internal_migrate_or_create.
        let r: Result<_, _> = entries
            .into_iter()
            .map(|e| {
                audit_log!(
                    audit,
                    "init schema -> {}",
                    serde_json::to_string_pretty(&e).unwrap()
                );
                self.internal_migrate_or_create(audit, e)
            })
            .collect();
        assert!(r.is_ok());
        r
    }

    pub fn initialise_schema_idm(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // List of IDM schemas to init.
        let idm_schema: Vec<&str> = vec![
            JSON_SCHEMA_ATTR_DISPLAYNAME,
            JSON_SCHEMA_ATTR_MAIL,
            JSON_SCHEMA_ATTR_SSH_PUBLICKEY,
            JSON_SCHEMA_ATTR_PASSWORD,
            JSON_SCHEMA_CLASS_PERSON,
            JSON_SCHEMA_CLASS_GROUP,
            JSON_SCHEMA_CLASS_ACCOUNT,
        ];

        let mut audit_si = AuditScope::new("start_initialise_schema_idm");
        let r: Result<Vec<()>, _> = idm_schema
            .iter()
            .map(|e_str| self.internal_migrate_or_create_str(&mut audit_si, e_str))
            .collect();
        audit.append_scope(audit_si);
        assert!(r.is_ok());

        // TODO: Should we log the set of failures some how?
        r.map(|_| ())
    }

    // This function is idempotent
    pub fn initialise_idm(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty static thing.
        let mut audit_si = AuditScope::new("start_system_info");
        let res = audit_segment!(audit_si, || serde_json::from_str(JSON_SYSTEM_INFO_V1)
            .map_err(|_| OperationError::SerdeJsonError)
            .and_then(
                |e: Entry<EntryValid, EntryNew>| self.internal_assert_or_create(audit, e)
            ));
        audit_log!(audit_si, "start_system_info -> result {:?}", res);
        audit.append_scope(audit_si);
        assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // Check the anonymous object exists (migrations).
        let mut audit_an = AuditScope::new("start_anonymous");
        let res = audit_segment!(audit_an, || serde_json::from_str(JSON_ANONYMOUS_V1)
            .map_err(|_| OperationError::SerdeJsonError)
            .and_then(
                |e: Entry<EntryValid, EntryNew>| self.internal_migrate_or_create(audit, e)
            ));
        audit_log!(audit_an, "start_anonymous -> result {:?}", res);
        audit.append_scope(audit_an);
        assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // Check the admin object exists (migrations).
        // Create the default idm_admin group.
        let mut audit_an = AuditScope::new("start_idm_admin_migrations");
        let res = self
            .internal_migrate_or_create_str(&mut audit_an, JSON_ADMIN_V1)
            .and_then(|_| self.internal_migrate_or_create_str(&mut audit_an, JSON_IDM_ADMINS_V1));
        audit.append_scope(audit_an);
        if res.is_err() {
            return res;
        }

        // Create any system default schema entries.

        // Create any system default access profile entries.
        let mut audit_an = AuditScope::new("start_idm_migrations_internal");
        let res = self
            .internal_migrate_or_create_str(&mut audit_an, JSON_IDM_ADMINS_ACP_SEARCH_V1)
            .and_then(|_| {
                self.internal_migrate_or_create_str(&mut audit_an, JSON_IDM_ADMINS_ACP_REVIVE_V1)
            })
            .and_then(|_| {
                self.internal_migrate_or_create_str(&mut audit_an, JSON_IDM_SELF_ACP_READ_V1)
            });
        audit.append_scope(audit_an);
        if res.is_err() {
            return res;
        }

        Ok(())
    }

    fn reload_schema(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // supply entries to the writable schema to reload from.
        // find all attributes.
        let filt = filter!(f_eq("class", "attributetype"));
        let res = try_audit!(audit, self.internal_search(audit, filt));
        // load them.
        let attributetypes: Result<Vec<_>, _> = res
            .iter()
            .map(|e| SchemaAttribute::try_from(audit, e))
            .collect();
        let attributetypes = try_audit!(audit, attributetypes);

        try_audit!(audit, self.schema.update_attributes(attributetypes));

        // find all classes
        let filt = filter!(f_eq("class", "classtype"));
        let res = try_audit!(audit, self.internal_search(audit, filt));
        // load them.
        let classtypes: Result<Vec<_>, _> = res
            .iter()
            .map(|e| SchemaClass::try_from(audit, e))
            .collect();
        let classtypes = try_audit!(audit, classtypes);

        try_audit!(audit, self.schema.update_classes(classtypes));

        // validate.
        let valid_r = self.schema.validate(audit);

        // Translate the result.
        if valid_r.len() == 0 {
            Ok(())
        } else {
            // Log the failures?
            unimplemented!();
        }
    }

    fn reload_accesscontrols(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // supply entries to the writable access controls to reload from.
        // This has to be done in FOUR passes - one for each type!
        //
        // Note, we have to do the search, parse, then submit here, because of the
        // requirement to have the write query server reference in the parse stage - this
        // would cause a rust double-borrow if we had AccessControls to try to handle
        // the entry lists themself.

        // Update search
        let filt = filter!(f_and!([
            f_eq("class", "access_control_profile"),
            f_eq("class", "access_control_search"),
            f_eq("acp_enable", "true"),
        ]));

        let res = try_audit!(audit, self.internal_search(audit, filt));
        let search_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlSearch::try_from(audit, self, e))
            .collect();

        let search_acps = try_audit!(audit, search_acps);

        try_audit!(audit, self.accesscontrols.update_search(search_acps));
        // Update create
        let filt = filter!(f_and!([
            f_eq("class", "access_control_profile"),
            f_eq("class", "access_control_create"),
            f_eq("acp_enable", "true"),
        ]));

        let res = try_audit!(audit, self.internal_search(audit, filt));
        let create_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlCreate::try_from(audit, self, e))
            .collect();

        let create_acps = try_audit!(audit, create_acps);

        try_audit!(audit, self.accesscontrols.update_create(create_acps));
        // Update modify
        let filt = filter!(f_and!([
            f_eq("class", "access_control_profile"),
            f_eq("class", "access_control_modify"),
            f_eq("acp_enable", "true"),
        ]));

        let res = try_audit!(audit, self.internal_search(audit, filt));
        let modify_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlModify::try_from(audit, self, e))
            .collect();

        let modify_acps = try_audit!(audit, modify_acps);

        try_audit!(audit, self.accesscontrols.update_modify(modify_acps));
        // Update delete
        let filt = filter!(f_and!([
            f_eq("class", "access_control_profile"),
            f_eq("class", "access_control_delete"),
            f_eq("acp_enable", "true"),
        ]));

        let res = try_audit!(audit, self.internal_search(audit, filt));
        let delete_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlDelete::try_from(audit, self, e))
            .collect();

        let delete_acps = try_audit!(audit, delete_acps);

        try_audit!(audit, self.accesscontrols.update_delete(delete_acps));
        // Alternately, we just get ACP class, and just let acctrl work it out ...
        Ok(())
    }

    pub fn commit(mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // TODO: This could be faster if we cache the set of classes changed
        // in an operation so we can check if we need to do the reload or not
        //
        // Reload the schema from qs.
        self.reload_schema(audit)?;
        // Determine if we need to update access control profiles
        // based on any modifications that have occured.
        // IF SCHEMA CHANGED WE MUST ALSO RELOAD!!! IE if schema had an attr removed
        // that we rely on we MUST fail this!
        self.reload_accesscontrols(audit)?;

        // Now destructure the transaction ready to reset it.
        let QueryServerWriteTransaction {
            committed,
            be_txn,
            schema,
            accesscontrols,
        } = self;
        assert!(!committed);
        // Begin an audit.
        // Validate the schema as we just loaded it.
        let r = schema.validate(audit);

        if r.len() == 0 {
            // TODO: At this point, if validate passes, we probably actually want
            // to perform a schema reload BEFORE we be commit. Because the be holds
            // all the data, we need everything to be consistent *first* as the be
            // is the last point we can really backout!
            // Alternate, we attempt to reload during batch ops, but this seems
            // costly.
            schema
                .commit()
                .and_then(|_| accesscontrols.commit().and_then(|_| be_txn.commit()))
        } else {
            Err(OperationError::ConsistencyError(r))
        }
        // Audit done
    }
}

// Auth requests? How do we structure these ...

#[cfg(test)]
mod tests {
    use crate::constants::{JSON_ADMIN_V1, UUID_ADMIN};
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::{OperationError, SchemaError};
    use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, ReviveRecycledEvent, SearchEvent};
    use crate::modify::{Modify, ModifyList};
    use crate::proto::v1::Filter as ProtoFilter;
    use crate::proto::v1::Modify as ProtoModify;
    use crate::proto::v1::ModifyList as ProtoModifyList;
    use crate::proto::v1::{DeleteRequest, ModifyRequest, ReviveRecycledRequest};
    use crate::server::QueryServerTransaction;

    #[test]
    fn test_qs_create_user() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();
            let filt = filter!(f_eq("name", "testperson"));
            let admin = server_txn
                .internal_search_uuid(audit, UUID_ADMIN)
                .expect("failed");

            let se1 = unsafe { SearchEvent::new_impersonate_entry(admin.clone(), filt.clone()) };
            let se2 = unsafe { SearchEvent::new_impersonate_entry(admin, filt) };

            let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson"]
                }
            }"#,
            )
            .expect("json failure");

            let ce = CreateEvent::new_internal(vec![e.clone()]);

            let r1 = server_txn.search(audit, &se1).expect("search failure");
            assert!(r1.len() == 0);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            let r2 = server_txn.search(audit, &se2).expect("search failure");
            println!("--> {:?}", r2);
            assert!(r2.len() == 1);

            let expected = unsafe { vec![e.to_valid_committed()] };

            assert_eq!(r2, expected);

            assert!(server_txn.commit(audit).is_ok());
        });
    }

    #[test]
    fn test_qs_init_idempotent_schema_core() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            {
                // Setup and abort.
                let server_txn = server.write();
                assert!(server_txn.initialise_schema_core(audit).is_ok());
            }
            {
                let server_txn = server.write();
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
            {
                // Now do it again in a new txn, but abort
                let server_txn = server.write();
                assert!(server_txn.initialise_schema_core(audit).is_ok());
            }
            {
                // Now do it again in a new txn.
                let server_txn = server.write();
                assert!(server_txn.initialise_schema_core(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
            // TODO: Check the content is as expected
        });
    }

    #[test]
    fn test_qs_modify() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create an object
            let server_txn = server.write();

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson1"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");

            let e2: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson2"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63932"],
                    "description": ["testperson2"],
                    "displayname": ["testperson2"]
                }
            }"#,
            )
            .expect("json failure");

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
                    filter!(f_eq("name", "flarbalgarble")),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("description"),
                        String::from("anusaosu"),
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
                filter!(f_eq("tnanuanou", "Flarbalgarble")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("description"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(
                r_inv_1
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute
                    ))
            );

            // Mod is invalid to schema
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_pres("class")),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("htnaonu"),
                        String::from("anusaosu"),
                    )]),
                )
            };
            assert!(
                server_txn.modify(audit, &me_inv_m)
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute
                    ))
            );

            // Mod single object
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", "testperson2")),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("description"),
                        String::from("anusaosu"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Mod multiple object
            let me_mult = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_or!([
                        f_eq("name", "testperson1"),
                        f_eq("name", "testperson2"),
                    ])),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("description"),
                        String::from("anusaosu"),
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
            let server_txn = server.write();

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson1"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");

            let ce = CreateEvent::new_internal(vec![e1.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Add class but no values
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", "testperson1")),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("class"),
                        String::from("system_info"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // Add multivalue where not valid
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", "testperson1")),
                    ModifyList::new_list(vec![Modify::Present(
                        String::from("name"),
                        String::from("testpersonx"),
                    )]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // add class and valid values?
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", "testperson1")),
                    ModifyList::new_list(vec![
                        Modify::Present(String::from("class"), String::from("system_info")),
                        Modify::Present(String::from("domain"), String::from("domain.name")),
                        Modify::Present(String::from("version"), String::from("1")),
                    ]),
                )
            };
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Replace a value
            let me_sin = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", "testperson1")),
                    ModifyList::new_list(vec![
                        Modify::Purged("name".to_string()),
                        Modify::Present(String::from("name"), String::from("testpersonx")),
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
            let server_txn = server.write();

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");

            let e2: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson2"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63932"],
                    "description": ["testperson"],
                    "displayname": ["testperson2"]
                }
            }"#,
            )
            .expect("json failure");

            let e3: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson3"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63933"],
                    "description": ["testperson"],
                    "displayname": ["testperson3"]
                }
            }"#,
            )
            .expect("json failure");

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
                    "cc8e95b4-c24f-4d68-ba54-000000000000"
                )))
            };
            assert!(server_txn.delete(audit, &de_empty).is_err());

            // Delete matches one
            let de_sin =
                unsafe { DeleteEvent::new_internal_invalid(filter!(f_eq("name", "testperson3"))) };
            assert!(server_txn.delete(audit, &de_sin).is_ok());

            // Delete matches many
            let de_mult = unsafe {
                DeleteEvent::new_internal_invalid(filter!(f_eq("description", "testperson")))
            };
            assert!(server_txn.delete(audit, &de_mult).is_ok());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_tombstone() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();
            let admin = server_txn
                .internal_search_uuid(audit, UUID_ADMIN)
                .expect("failed");

            let filt_ts = ProtoFilter::Eq(String::from("class"), String::from("tombstone"));

            let filt_i_ts = filter_all!(f_eq("class", "tombstone"));

            // Create fake external requests. Probably from admin later
            // Should we do this with impersonate instead of using the external
            let me_ts = ModifyEvent::from_request(
                audit,
                ModifyRequest::new(
                    filt_ts.clone(),
                    ProtoModifyList::new_list(vec![ProtoModify::Present(
                        String::from("class"),
                        String::from("tombstone"),
                    )]),
                    UUID_ADMIN,
                ),
                &server_txn,
            )
            .expect("modify event create failed");
            let de_ts = DeleteEvent::from_request(
                audit,
                DeleteRequest::new(filt_ts.clone(), UUID_ADMIN),
                &server_txn,
            )
            .expect("delete event create failed");
            let se_ts = unsafe { SearchEvent::new_ext_impersonate_entry(admin, filt_i_ts.clone()) };

            // First, create a tombstone
            let e_ts: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["tombstone", "object"],
                    "uuid": ["9557f49c-97a5-4277-a9a5-097d17eb8317"]
                }
            }"#,
            )
            .expect("json failure");

            let ce = CreateEvent::new_internal(vec![e_ts]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_ts).expect("search failed");
            assert!(r1.len() == 0);

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

            // Now purge
            assert!(server_txn.purge_tombstones(audit).is_ok());

            // Assert it's gone
            // Internal search should not see it.
            let r3 = server_txn
                .internal_search(audit, filt_i_ts)
                .expect("internal search failed");
            assert!(r3.len() == 0);

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_recycle_simple() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();
            let admin = server_txn
                .internal_search_uuid(audit, UUID_ADMIN)
                .expect("failed");

            let filt_rc = ProtoFilter::Eq(String::from("class"), String::from("recycled"));

            let filt_i_rc = filter_all!(f_eq("class", "recycled"));

            let filt_i_ts = filter_all!(f_eq("class", "tombstone"));

            let filt_i_per = filter_all!(f_eq("class", "person"));

            // Create fake external requests. Probably from admin later
            let me_rc = ModifyEvent::from_request(
                audit,
                ModifyRequest::new(
                    filt_rc.clone(),
                    ProtoModifyList::new_list(vec![ProtoModify::Present(
                        String::from("class"),
                        String::from("recycled"),
                    )]),
                    UUID_ADMIN,
                ),
                &server_txn,
            )
            .expect("modify event create failed");
            let de_rc = DeleteEvent::from_request(
                audit,
                DeleteRequest::new(filt_rc.clone(), UUID_ADMIN),
                &server_txn,
            )
            .expect("delete event create failed");
            let se_rc =
                unsafe { SearchEvent::new_ext_impersonate_entry(admin.clone(), filt_i_rc.clone()) };

            let sre_rc =
                unsafe { SearchEvent::new_rec_impersonate_entry(admin, filt_i_rc.clone()) };

            let rre_rc = ReviveRecycledEvent::from_request(
                audit,
                ReviveRecycledRequest::new(
                    ProtoFilter::Eq("name".to_string(), "testperson1".to_string()),
                    UUID_ADMIN,
                ),
                &server_txn,
            )
            .expect("revive recycled create failed");

            // Create some recycled objects
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person", "recycled"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");

            let e2: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person", "recycled"],
                    "name": ["testperson2"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63932"],
                    "description": ["testperson"],
                    "displayname": ["testperson2"]
                }
            }"#,
            )
            .expect("json failure");

            let ce = CreateEvent::new_internal(vec![e1, e2]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_rc).expect("search failed");
            assert!(r1.len() == 0);

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

            // There are now two options
            //  revival
            assert!(server_txn.revive_recycled(audit, &rre_rc).is_ok());

            //  purge to tombstone
            assert!(server_txn.purge_recycled(audit).is_ok());

            // Should be no recycled objects.
            let r3 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .expect("internal search failed");
            assert!(r3.len() == 0);

            // There should be one tombstone
            let r4 = server_txn
                .internal_search(audit, filt_i_ts.clone())
                .expect("internal search failed");
            assert!(r4.len() == 1);

            // There should be one entry
            let r5 = server_txn
                .internal_search(audit, filt_i_per.clone())
                .expect("internal search failed");
            assert!(r5.len() == 1);

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    // The delete test above should be unaffected by recycle anyway
    #[test]
    fn test_qs_recycle_advanced() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            // Create items
            let server_txn = server.write();
            let admin = server_txn
                .internal_search_uuid(audit, UUID_ADMIN)
                .expect("failed");

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");
            let ce = CreateEvent::new_internal(vec![e1]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());
            // Delete and ensure they became recycled.
            let de_sin =
                unsafe { DeleteEvent::new_internal_invalid(filter!(f_eq("name", "testperson1"))) };
            assert!(server_txn.delete(audit, &de_sin).is_ok());
            // Can in be seen by special search? (external recycle search)
            let filt_rc = filter_all!(f_eq("class", "recycled"));
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
            let server_txn = server.write();

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
                }"#,
            )
            .expect("json failure");
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Name doesn't exist
            let r1 = server_txn.name_to_uuid(audit, &String::from("testpers"));
            assert!(r1.is_err());
            // Name doesn't exist (not syntax normalised)
            let r2 = server_txn.name_to_uuid(audit, &String::from("tEsTpErS"));
            assert!(r2.is_err());
            // Name does exist
            let r3 = server_txn.name_to_uuid(audit, &String::from("testperson1"));
            assert!(r3.is_ok());
            // Name is not syntax normalised (but exists)
            let r4 = server_txn.name_to_uuid(audit, &String::from("tEsTpErSoN1"));
            assert!(r4.is_ok());
        })
    }

    #[test]
    fn test_qs_uuid_to_name() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();

            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Name doesn't exist
            let r1 = server_txn
                .uuid_to_name(audit, &String::from("bae3f507-e6c3-44ba-ad01-f8ff1083534a"));
            assert!(r1.is_err());
            // Name doesn't exist (not syntax normalised)
            let r2 = server_txn.uuid_to_name(audit, &String::from("bae3f507-e6c3-44ba-ad01"));
            assert!(r2.is_err());
            // Name does exist
            let r3 = server_txn
                .uuid_to_name(audit, &String::from("cc8e95b4-c24f-4d68-ba54-8bed76f63930"));
            assert!(r3.is_ok());
            // Name is not syntax normalised (but exists)
            let r4 = server_txn
                .uuid_to_name(audit, &String::from("CC8E95B4-C24F-4D68-BA54-8BED76F63930"));
            assert!(r4.is_ok());
        })
    }

    #[test]
    fn test_qs_clone_value() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson1"]
                }
            }"#,
            )
            .expect("json failure");
            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // test attr not exist
            let r1 =
                server_txn.clone_value(audit, &"tausau".to_string(), &"naoeutnhaou".to_string());

            assert!(r1 == Ok("naoeutnhaou".to_string()));

            // test attr not-normalised
            // test attr not-reference
            let r2 = server_txn.clone_value(audit, &"NaMe".to_string(), &"NaMe".to_string());

            assert!(r2 == Ok("NaMe".to_string()));

            // test attr reference
            let r3 =
                server_txn.clone_value(audit, &"member".to_string(), &"testperson1".to_string());

            assert!(r3 == Ok("cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string()));

            // test attr reference already resolved.
            let r4 = server_txn.clone_value(
                audit,
                &"member".to_string(),
                &"cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string(),
            );

            println!("{:?}", r4);
            assert!(r4 == Ok("cc8e95b4-c24f-4d68-ba54-8bed76f63930".to_string()));
        })
    }

    #[test]
    fn test_qs_dynamic_schema_class() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "testclass"],
                    "name": ["testobj1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                }
            }"#,
            )
            .expect("json failure");

            // Class definition
            let e_cd: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "classtype"],
                    "name": ["testclass"],
                    "uuid": ["cfcae205-31c3-484b-8ced-667d1709c5e3"],
                    "description": ["Test Class"]
                }
            }"#,
            )
            .expect("json failure");

            let server_txn = server.write();
            // Add a new class.
            let ce_class = CreateEvent::new_internal(vec![e_cd.clone()]);
            assert!(server_txn.create(audit, &ce_class).is_ok());
            // Trying to add it now should fail.
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // Add the class to an object
            // should work
            let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_work).is_ok());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // delete the class
            let de_class =
                unsafe { DeleteEvent::new_internal_invalid(filter!(f_eq("name", "testclass"))) };
            assert!(server_txn.delete(audit, &de_class).is_ok());
            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // Trying to add now should fail
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());
            // Search our entry
            let testobj1 = server_txn
                .internal_search_uuid(audit, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                .expect("failed");
            assert!(testobj1.attribute_value_pres("class", "testclass"));

            // Should still be good
            server_txn.commit(audit).expect("should not fail");
            // Commit.
        })
    }

    #[test]
    fn test_qs_dynamic_schema_attr() {
        run_test!(|server: &QueryServer, audit: &mut AuditScope| {
            let e1: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "extensibleobject"],
                    "name": ["testobj1"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "testattr": ["test"]
                }
            }"#,
            )
            .expect("json failure");

            // Attribute definition
            let e_ad: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
                r#"{
                "valid": null,
                "state": null,
                "attrs": {
                    "class": ["object", "attributetype"],
                    "name": ["testattr"],
                    "uuid": ["cfcae205-31c3-484b-8ced-667d1709c5e3"],
                    "description": ["Test Attribute"],
                    "multivalue": ["false"],
                    "secret": ["false"],
                    "syntax": ["UTF8STRING"]
                }
            }"#,
            )
            .expect("json failure");

            let server_txn = server.write();
            // Add a new attribute.
            let ce_attr = CreateEvent::new_internal(vec![e_ad.clone()]);
            assert!(server_txn.create(audit, &ce_attr).is_ok());
            // Trying to add it now should fail. (use extensible object)
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // Add the attr to an object
            // should work
            let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_work).is_ok());

            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // delete the attr
            let de_attr =
                unsafe { DeleteEvent::new_internal_invalid(filter!(f_eq("name", "testattr"))) };
            assert!(server_txn.delete(audit, &de_attr).is_ok());
            // Commit
            server_txn.commit(audit).expect("should not fail");

            // Start a new write
            let server_txn = server.write();
            // Trying to add now should fail
            let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
            assert!(server_txn.create(audit, &ce_fail).is_err());
            // Search our attribute - should FAIL
            let filt = filter!(f_eq("testattr", "test"));
            assert!(server_txn.internal_search(audit, filt).is_err());
            // Search the entry - the attribute will still be present
            // even if we can't search on it.
            let testobj1 = server_txn
                .internal_search_uuid(audit, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                .expect("failed");
            assert!(testobj1.attribute_value_pres("testattr", "test"));

            server_txn.commit(audit).expect("should not fail");
            // Commit.
        })
    }
}
