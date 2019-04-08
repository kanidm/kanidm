// This is really only used for long lived, high level types that need clone
// that otherwise can't be cloned. Think Mutex.
// use actix::prelude::*;
use std::sync::Arc;

use audit::AuditScope;
use be::{
    Backend, BackendError, BackendReadTransaction, BackendTransaction, BackendWriteTransaction,
};

use constants::{JSON_ANONYMOUS_V1, JSON_SYSTEM_INFO_V1};
use entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use error::{ConsistencyError, OperationError, SchemaError};
use event::{CreateEvent, DeleteEvent, ExistsEvent, ModifyEvent, ReviveRecycledEvent, SearchEvent};
use filter::{Filter, FilterInvalid};
use modify::{Modify, ModifyInvalid, ModifyList};
use plugins::Plugins;
use schema::{
    Schema, SchemaReadTransaction, SchemaTransaction, SchemaWriteTransaction, SyntaxType,
};

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code
pub trait QueryServerReadTransaction {
    type BackendTransactionType: BackendReadTransaction;
    fn get_be_txn(&self) -> &Self::BackendTransactionType;

    type SchemaTransactionType: SchemaReadTransaction;
    fn get_schema(&self) -> &Self::SchemaTransactionType;

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
        let vf = match se.filter.validate(self.get_schema()) {
            Ok(f) => f,
            // TODO: Do something with this error
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        audit_log!(au, "search: valid filter -> {:?}", vf);

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
            .search(&mut audit_be, &vf)
            .map(|r| r)
            .map_err(|_| OperationError::Backend);
        au.append_scope(audit_be);

        if res.is_err() {
            return res;
        }

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

        // TODO: We'll add ACI here. I think ACI should transform from
        // internal -> proto entries since we have to anyway ...
        // alternately, we can just clone again ...
        res
    }

    fn exists(&self, au: &mut AuditScope, ee: &ExistsEvent) -> Result<bool, OperationError> {
        let mut audit_be = AuditScope::new("backend_exists");

        // How to get schema?
        let vf = match ee.filter.validate(self.get_schema()) {
            Ok(f) => f,
            // TODO: Do something with this error
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        let res = self
            .get_be_txn()
            .exists(&mut audit_be, &vf)
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
        let filt = Filter::new_ignore_hidden(Filter::Eq("name".to_string(), name.clone()));
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

        // TODO: Is there a better solution here than this?
        // Perhaps we could res.first, then unwrap the some
        // for 0/1 case, but check len for >= 2 to eliminate that case.
        let e = res.first().unwrap();
        // Get the uuid from the entry. Again, check it exists, and only one.
        let uuid_res = match e.get_ava(&String::from("uuid")) {
            Some(vas) => match vas.first() {
                Some(u) => u.clone(),
                None => return Err(OperationError::InvalidEntryState),
            },
            None => return Err(OperationError::InvalidEntryState),
        };

        audit_log!(audit, "name_to_uuid: uuid <- {:?}", uuid_res);

        Ok(uuid_res)
    }

    fn uuid_to_name(
        &self,
        audit: &mut AuditScope,
        uuid: &String,
    ) -> Result<String, OperationError> {
        // construct the filter
        let filt = Filter::new_ignore_hidden(Filter::Eq("uuid".to_string(), uuid.clone()));
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

        // TODO: Is there a better solution here than this?
        // Perhaps we could res.first, then unwrap the some
        // for 0/1 case, but check len for >= 2 to eliminate that case.
        let e = res.first().unwrap();
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
        let mut audit_int = AuditScope::new("internal_exists");
        // Build an exists event
        let ee = ExistsEvent::new_internal(filter);
        // Submit it
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
        let mut audit_int = AuditScope::new("internal_search");
        let se = SearchEvent::new_internal(filter);
        let res = self.search(&mut audit_int, &se);
        audit.append_scope(audit_int);
        res
    }

    // Who they are will go here
    fn impersonate_search(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
    ) -> Result<Vec<Entry<EntryValid, EntryCommitted>>, OperationError> {
        let mut audit_int = AuditScope::new("impersonate_search");
        let se = SearchEvent::new_impersonate(filter);
        let res = self.search(&mut audit_int, &se);
        audit.append_scope(audit_int);
        res
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
    fn resolve_value(&self, attr: &String, value: &String) -> Result<String, OperationError> {
        Ok(value.clone())
    }
}

pub struct QueryServerTransaction {
    be_txn: BackendTransaction,
    // Anything else? In the future, we'll need to have a schema transaction
    // type, maybe others?
    schema: SchemaTransaction,
}

// Actually conduct a search request
// This is the core of the server, as it processes the entire event
// applies all parts required in order and more.
impl QueryServerReadTransaction for QueryServerTransaction {
    type BackendTransactionType = BackendTransaction;

    fn get_be_txn(&self) -> &BackendTransaction {
        &self.be_txn
    }

    type SchemaTransactionType = SchemaTransaction;

    fn get_schema(&self) -> &SchemaTransaction {
        &self.schema
    }
}

impl QueryServerTransaction {
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
    // read: QueryServerTransaction,
    be_txn: BackendWriteTransaction,
    schema: SchemaWriteTransaction<'a>,
}

impl<'a> QueryServerReadTransaction for QueryServerWriteTransaction<'a> {
    type BackendTransactionType = BackendWriteTransaction;

    fn get_be_txn(&self) -> &BackendWriteTransaction {
        &self.be_txn
    }

    type SchemaTransactionType = SchemaWriteTransaction<'a>;

    fn get_schema(&self) -> &SchemaWriteTransaction<'a> {
        &self.schema
    }
}

pub struct QueryServer {
    // log: actix::Addr<EventLog>,
    be: Backend,
    schema: Arc<Schema>,
}

impl QueryServer {
    pub fn new(be: Backend, schema: Arc<Schema>) -> Self {
        // log_event!(log, "Starting query worker ...");
        QueryServer {
            be: be,
            schema: schema,
        }
    }

    pub fn read(&self) -> QueryServerTransaction {
        QueryServerTransaction {
            be_txn: self.be.read(),
            schema: self.schema.read(),
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
        }
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
        let mut candidates: Vec<Entry<EntryInvalid, EntryNew>> =
            ce.entries.iter().map(|er| er.clone()).collect();

        // run any pre plugins, giving them the list of mutable candidates.
        // pre-plugins are defined here in their correct order of calling!
        // I have no intent to make these dynamic or configurable.

        let mut audit_plugin_pre = AuditScope::new("plugin_pre_create");
        let plug_pre_res =
            Plugins::run_pre_create(&mut audit_plugin_pre, &self, &mut candidates, ce);
        au.append_scope(audit_plugin_pre);

        if plug_pre_res.is_err() {
            audit_log!(au, "Create operation failed (plugin), {:?}", plug_pre_res);
            return plug_pre_res;
        }

        // NOTE: This is how you map from Vec<Result<T>> to Result<Vec<T>>
        // remember, that you only get the first error and the iter terminates.

        let res: Result<Vec<Entry<EntryValid, EntryNew>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema))
            .collect();

        let norm_cand: Vec<Entry<EntryValid, EntryNew>> = match res {
            Ok(v) => v,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        let mut audit_be = AuditScope::new("backend_create");
        // We may change from ce.entries later to something else?
        let res = self
            .be_txn
            .create(&mut audit_be, &norm_cand)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                BackendError::EntryMissingId => OperationError::InvalidRequestState,
            });
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

        // Commit the txn
        // let commit, commit!
        // be_txn.commit();

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
        let pre_candidates = match self.impersonate_search(au, de.filter.clone()) {
            Ok(results) => results,
            Err(e) => {
                audit_log!(au, "delete: error in pre-candidate selection {:?}", e);
                return Err(e);
            }
        };

        // Apply access controls to reduce the set if required.

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
            .into_iter()
            .map(|er| {
                // TODO: Deal with this properly william
                er.invalidate().apply_modlist(&modlist).unwrap()
            })
            .collect();

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

        let res = self
            .be_txn
            // Change this to an update, not delete.
            .modify(&mut audit_be, &del_cand)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                BackendError::EntryMissingId => OperationError::InvalidRequestState,
            });
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
        let ts = match self
            .internal_search(au, Filter::Eq("class".to_string(), "tombstone".to_string()))
        {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        // TODO: Has an appropriate amount of time/condition past (ie replication events?)

        // Delete them
        let mut audit_be = AuditScope::new("backend_delete");

        let res = self
            .be_txn
            // Change this to an update, not delete.
            .delete(&mut audit_be, &ts)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                BackendError::EntryMissingId => OperationError::InvalidRequestState,
            });
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
        let rc = match self
            .internal_search(au, Filter::Eq("class".to_string(), "recycled".to_string()))
        {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        // Modify them to strip all avas except uuid
        let tombstone_cand = rc.iter().map(|e| e.to_tombstone()).collect();

        // Backend Modify
        let mut audit_be = AuditScope::new("backend_modify");

        let res = self
            .be_txn
            .modify(&mut audit_be, &tombstone_cand)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                BackendError::EntryMissingId => OperationError::InvalidRequestState,
            });
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

        // Now impersonate the modify
        self.impersonate_modify(au, re.filter.clone(), modlist)
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
        let modlist = match me.modlist.validate(&self.schema) {
            Ok(ml) => ml,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        // Is the filter invalid to schema?

        // WARNING! Check access controls here!!!!
        // How can we do the search with the permissions of the caller?

        // TODO: Fix this filter clone ....
        // Likely this will be fixed if search takes &filter, and then clone
        // to normalise, instead of attempting to mut the filter on norm.
        let pre_candidates = match self.impersonate_search(au, me.filter.clone()) {
            Ok(results) => results,
            Err(e) => {
                audit_log!(au, "modify: error in pre-candidate selection {:?}", e);
                return Err(e);
            }
        };

        if pre_candidates.len() == 0 {
            audit_log!(au, "modify: no candidates match filter {:?}", me.filter);
            return Err(OperationError::NoMatchingEntries);
        };

        // Clone a set of writeables.
        // Apply the modlist -> Remember, we have a set of origs
        // and the new modified ents.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .into_iter()
            .map(|er| {
                // TODO: Deal with this properly william
                er.invalidate().apply_modlist(&modlist).unwrap()
            })
            .collect();

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

        let res: Result<Vec<Entry<EntryValid, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema))
            .collect();

        let norm_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => return Err(OperationError::SchemaViolation(e)),
        };

        // Now map out the Oks?

        // Backend Modify
        let mut audit_be = AuditScope::new("backend_modify");

        let res = self
            .be_txn
            .modify(&mut audit_be, &norm_cand)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                BackendError::EntryMissingId => OperationError::InvalidRequestState,
            });
        au.append_scope(audit_be);

        if res.is_err() {
            // be_txn is dropped, ie aborted here.
            audit_log!(au, "Modify operation failed (backend), {:?}", res);
            return res;
        }

        // Post Plugins
        let mut audit_plugin_post = AuditScope::new("plugin_post_modify");
        let plug_post_res = Plugins::run_post_modify(&mut audit_plugin_post, &self, &norm_cand, me);
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
        let mut audit_int = AuditScope::new("internal_delete");
        let de = DeleteEvent::new_internal(filter);
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
        let mut audit_int = AuditScope::new("internal_modify");
        let me = ModifyEvent::new_internal(filter, modlist);
        let res = self.modify(&mut audit_int, &me);
        audit.append_scope(audit_int);
        res
    }

    pub fn impersonate_modify(
        &self,
        audit: &mut AuditScope,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let mut audit_int = AuditScope::new("impersonate_modify");
        let me = ModifyEvent::new_internal(filter, modlist);
        let res = self.modify(&mut audit_int, &me);
        audit.append_scope(audit_int);
        res
    }

    // internal server operation types.
    // These just wrap the fn create/search etc, but they allow
    // creating the needed create event with the correct internal flags
    // and markers. They act as though they have the highest level privilege
    // IE there are no access control checks.

    pub fn internal_exists_or_create(
        &self,
        e: Entry<EntryValid, EntryNew>,
    ) -> Result<(), OperationError> {
        // If the thing exists, stop.
        // if not, create from Entry.
        unimplemented!()
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
        // WARNING: this requires schema awareness for multivalue types!
        // We need to either do a schema aware merge, or we just overwrite those
        // few attributes.
        //
        // This will extra classes an attributes alone!
        let filt = match e.filter_from_attrs(&vec![String::from("uuid")]) {
            Some(f) => f.invalidate(),
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
            Some(f) => f.invalidate(),
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

    // This function is idempotent
    pub fn initialise(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty static thing.
        let mut audit_si = AuditScope::new("start_system_info");
        let res = audit_segment!(audit_si, || {
            let e: Entry<EntryValid, EntryNew> = serde_json::from_str(JSON_SYSTEM_INFO_V1).unwrap();
            self.internal_assert_or_create(audit, e)
        });
        audit_log!(audit_si, "start_system_info -> result {:?}", res);
        audit.append_scope(audit_si);
        assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // Check the anonymous object exists (migrations).
        let mut audit_an = AuditScope::new("start_anonymous");
        let res = audit_segment!(audit_an, || {
            let e: Entry<EntryValid, EntryNew> = serde_json::from_str(JSON_ANONYMOUS_V1).unwrap();
            self.internal_migrate_or_create(audit, e)
        });
        audit_log!(audit_an, "start_anonymous -> result {:?}", res);
        audit.append_scope(audit_an);
        assert!(res.is_ok());
        if res.is_err() {
            return res;
        }

        // Check the admin object exists (migrations).

        // Load access profiles and configure them.
        Ok(())
    }

    pub fn commit(self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let QueryServerWriteTransaction {
            committed,
            be_txn,
            schema,
        } = self;
        assert!(!committed);
        // Begin an audit.
        // Validate the schema,

        let r = schema.validate(audit);
        if r.len() == 0 {
            // TODO: At this point, if validate passes, we probably actually want
            // to perform a reload BEFORE we commit.
            // Alternate, we attempt to reload during batch ops, but this seems
            // costly.
            be_txn.commit().and_then(|_| {
                // Schema commit: Since validate passed and be is good, this
                // must now also be good.
                schema.commit()
            })
        } else {
            Err(OperationError::ConsistencyError(r))
        }
        // Audit done
    }
}

// Auth requests? How do we structure these ...

#[cfg(test)]
mod tests {
    /*
    extern crate actix;
    use actix::prelude::*;

    extern crate futures;
    use futures::future;
    use futures::future::Future;

    extern crate tokio;
    */
    use std::sync::Arc;

    use super::super::audit::AuditScope;
    use super::super::be::Backend;
    use super::super::entry::{Entry, EntryInvalid, EntryNew};
    use super::super::error::{OperationError, SchemaError};
    use super::super::event::{
        CreateEvent, DeleteEvent, ModifyEvent, ReviveRecycledEvent, SearchEvent,
    };
    use super::super::filter::Filter;
    use super::super::modify::{Modify, ModifyList};
    use super::super::proto_v1::Filter as ProtoFilter;
    use super::super::proto_v1::Modify as ProtoModify;
    use super::super::proto_v1::ModifyList as ProtoModifyList;
    use super::super::proto_v1::{
        DeleteRequest, ModifyRequest, ReviveRecycledRequest, SearchRecycledRequest, SearchRequest,
    };
    use super::super::schema::Schema;
    use super::super::server::{QueryServer, QueryServerReadTransaction};

    macro_rules! run_test {
        ($test_fn:expr) => {{
            let mut audit = AuditScope::new("run_test");

            let be = Backend::new(&mut audit, "").unwrap();
            let schema_outer = Schema::new(&mut audit).unwrap();
            {
                let mut schema = schema_outer.write();
                schema.bootstrap_core(&mut audit).unwrap();
                schema.commit().unwrap();
            }
            let test_server = QueryServer::new(be, Arc::new(schema_outer));

            $test_fn(test_server, &mut audit);
            // Any needed teardown?
        }};
    }

    #[test]
    fn test_qs_create_user() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();
            let filt = Filter::Pres(String::from("name"));

            let se1 = SearchEvent::new_impersonate(filt.clone());
            let se2 = SearchEvent::new_impersonate(filt);

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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e.clone()]);

            let r1 = server_txn.search(audit, &se1).unwrap();
            assert!(r1.len() == 0);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            let r2 = server_txn.search(audit, &se2).unwrap();
            println!("--> {:?}", r2);
            assert!(r2.len() == 1);

            let expected = unsafe { vec![e.to_valid_committed()] };

            assert_eq!(r2, expected);

            assert!(server_txn.commit(audit).is_ok());
        });
    }

    #[test]
    fn test_qs_init_idempotent_1() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
            {
                // Setup and abort.
                let server_txn = server.write();
                assert!(server_txn.initialise(audit).is_ok());
            }
            {
                let server_txn = server.write();
                assert!(server_txn.initialise(audit).is_ok());
                assert!(server_txn.initialise(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
            {
                // Now do it again in a new txn, but abort
                let server_txn = server.write();
                assert!(server_txn.initialise(audit).is_ok());
            }
            {
                // Now do it again in a new txn.
                let server_txn = server.write();
                assert!(server_txn.initialise(audit).is_ok());
                assert!(server_txn.commit(audit).is_ok());
            }
        });
    }

    #[test]
    fn test_qs_modify() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();

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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e1.clone(), e2.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Empty Modlist (filter is valid)
            let me_emp = ModifyEvent::from_filter(
                Filter::Pres(String::from("class")),
                ModifyList::new_list(vec![]),
            );
            assert!(server_txn.modify(audit, &me_emp) == Err(OperationError::EmptyRequest));

            // Mod changes no objects
            let me_nochg = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("flarbalgarble")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("description"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(server_txn.modify(audit, &me_nochg) == Err(OperationError::NoMatchingEntries));

            // Filter is invalid to schema
            let me_inv_f = ModifyEvent::from_filter(
                Filter::Eq(String::from("tnanuanou"), String::from("Flarbalgarble")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("description"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(
                server_txn.modify(audit, &me_inv_f)
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute
                    ))
            );

            // Mod is invalid to schema
            let me_inv_m = ModifyEvent::from_filter(
                Filter::Pres(String::from("class")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("htnaonu"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(
                server_txn.modify(audit, &me_inv_m)
                    == Err(OperationError::SchemaViolation(
                        SchemaError::InvalidAttribute
                    ))
            );

            // Mod single object
            let me_sin = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("testperson2")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("description"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Mod multiple object
            let me_mult = ModifyEvent::from_filter(
                Filter::Or(vec![
                    Filter::Eq(String::from("name"), String::from("testperson1")),
                    Filter::Eq(String::from("name"), String::from("testperson2")),
                ]),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("description"),
                    String::from("anusaosu"),
                )]),
            );
            assert!(server_txn.modify(audit, &me_mult).is_ok());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_modify_invalid_class() {
        // Test modifying an entry and adding an extra class, that would cause the entry
        // to no longer conform to schema.
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e1.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Add class but no values
            let me_sin = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("testperson1")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("class"),
                    String::from("system_info"),
                )]),
            );
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // Add multivalue where not valid
            let me_sin = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("testperson1")),
                ModifyList::new_list(vec![Modify::Present(
                    String::from("name"),
                    String::from("testpersonx"),
                )]),
            );
            assert!(server_txn.modify(audit, &me_sin).is_err());

            // add class and valid values?
            let me_sin = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("testperson1")),
                ModifyList::new_list(vec![
                    Modify::Present(String::from("class"), String::from("system_info")),
                    Modify::Present(String::from("domain"), String::from("domain.name")),
                    Modify::Present(String::from("version"), String::from("1")),
                ]),
            );
            assert!(server_txn.modify(audit, &me_sin).is_ok());

            // Replace a value
            let me_sin = ModifyEvent::from_filter(
                Filter::Eq(String::from("name"), String::from("testperson1")),
                ModifyList::new_list(vec![
                    Modify::Purged("name".to_string()),
                    Modify::Present(String::from("name"), String::from("testpersonx")),
                ]),
            );
            assert!(server_txn.modify(audit, &me_sin).is_ok());
        })
    }

    #[test]
    fn test_qs_delete() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();

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
            .unwrap();

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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e1.clone(), e2.clone(), e3.clone()]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Delete filter is syntax invalid
            let de_inv = DeleteEvent::from_filter(Filter::Pres(String::from("nhtoaunaoehtnu")));
            assert!(server_txn.delete(audit, &de_inv).is_err());

            // Delete deletes nothing
            let de_empty = DeleteEvent::from_filter(Filter::Eq(
                String::from("uuid"),
                String::from("cc8e95b4-c24f-4d68-ba54-000000000000"),
            ));
            assert!(server_txn.delete(audit, &de_empty).is_err());

            // Delete matches one
            let de_sin = DeleteEvent::from_filter(Filter::Eq(
                String::from("name"),
                String::from("testperson3"),
            ));
            assert!(server_txn.delete(audit, &de_sin).is_ok());

            // Delete matches many
            let de_mult = DeleteEvent::from_filter(Filter::Eq(
                String::from("description"),
                String::from("testperson"),
            ));
            assert!(server_txn.delete(audit, &de_mult).is_ok());

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_tombstone() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();

            let filt_ts = ProtoFilter::Eq(String::from("class"), String::from("tombstone"));

            let filt_i_ts = Filter::Eq(String::from("class"), String::from("tombstone"));

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
                ),
                &server_txn,
            )
            .unwrap();
            let de_ts =
                DeleteEvent::from_request(audit, DeleteRequest::new(filt_ts.clone()), &server_txn)
                    .unwrap();
            let se_ts = SearchEvent::new_ext_impersonate(filt_i_ts.clone());

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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e_ts]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_ts).unwrap();
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
                .unwrap();
            assert!(r2.len() == 1);

            // Now purge
            assert!(server_txn.purge_tombstones(audit).is_ok());

            // Assert it's gone
            // Internal search should not see it.
            let r3 = server_txn.internal_search(audit, filt_i_ts).unwrap();
            assert!(r3.len() == 0);

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    #[test]
    fn test_qs_recycle_simple() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
            let server_txn = server.write();

            let filt_rc = ProtoFilter::Eq(String::from("class"), String::from("recycled"));

            let filt_i_rc = Filter::Eq(String::from("class"), String::from("recycled"));

            let filt_i_ts = Filter::Eq(String::from("class"), String::from("tombstone"));

            let filt_i_per = Filter::Eq(String::from("class"), String::from("person"));

            // Create fake external requests. Probably from admin later
            let me_rc = ModifyEvent::from_request(
                audit,
                ModifyRequest::new(
                    filt_rc.clone(),
                    ProtoModifyList::new_list(vec![ProtoModify::Present(
                        String::from("class"),
                        String::from("recycled"),
                    )]),
                ),
                &server_txn,
            )
            .unwrap();
            let de_rc =
                DeleteEvent::from_request(audit, DeleteRequest::new(filt_rc.clone()), &server_txn)
                    .unwrap();
            let se_rc = SearchEvent::new_ext_impersonate(filt_i_rc.clone());

            let sre_rc = SearchEvent::new_rec_impersonate(filt_i_rc.clone());

            let rre_rc = ReviveRecycledEvent::from_request(
                audit,
                ReviveRecycledRequest::new(ProtoFilter::Eq(
                    "name".to_string(),
                    "testperson1".to_string(),
                )),
                &server_txn,
            )
            .unwrap();

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
            .unwrap();

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
            .unwrap();

            let ce = CreateEvent::from_vec(vec![e1, e2]);
            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());

            // Can it be seen (external search)
            let r1 = server_txn.search(audit, &se_rc).unwrap();
            assert!(r1.len() == 0);

            // Can it be deleted (external delete)
            // Should be err-no candidates.
            assert!(server_txn.delete(audit, &de_rc).is_err());

            // Can it be modified? (external modify)
            // Should be err-no candidates
            assert!(server_txn.modify(audit, &me_rc).is_err());

            // Can in be seen by special search? (external recycle search)
            let r2 = server_txn.search(audit, &sre_rc).unwrap();
            assert!(r2.len() == 2);

            // Can it be seen (internal search)
            // Internal search should see it.
            let r2 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .unwrap();
            assert!(r2.len() == 2);

            // There are now two options
            //  revival
            assert!(server_txn.revive_recycled(audit, &rre_rc).is_ok());

            //  purge to tombstone
            assert!(server_txn.purge_recycled(audit).is_ok());

            // Should be no recycled objects.
            let r3 = server_txn
                .internal_search(audit, filt_i_rc.clone())
                .unwrap();
            assert!(r3.len() == 0);

            // There should be one tombstone
            let r4 = server_txn
                .internal_search(audit, filt_i_ts.clone())
                .unwrap();
            assert!(r4.len() == 1);

            // There should be one entry
            let r5 = server_txn
                .internal_search(audit, filt_i_per.clone())
                .unwrap();
            assert!(r5.len() == 1);

            assert!(server_txn.commit(audit).is_ok());
        })
    }

    // The delete test above should be unaffected by recycle anyway
    #[test]
    fn test_qs_recycle_advanced() {
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
            // Create items
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
            .unwrap();
            let ce = CreateEvent::from_vec(vec![e1]);

            let cr = server_txn.create(audit, &ce);
            assert!(cr.is_ok());
            // Delete and ensure they became recycled.
            let de_sin = DeleteEvent::from_filter(Filter::Eq(
                String::from("name"),
                String::from("testperson1"),
            ));
            assert!(server_txn.delete(audit, &de_sin).is_ok());
            // Can in be seen by special search? (external recycle search)
            let filt_rc = Filter::Eq(String::from("class"), String::from("recycled"));
            let sre_rc = SearchEvent::new_rec_impersonate(filt_rc.clone());
            let r2 = server_txn.search(audit, &sre_rc).unwrap();
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
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();
            let ce = CreateEvent::from_vec(vec![e1]);
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
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();
            let ce = CreateEvent::from_vec(vec![e1]);
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
        run_test!(|server: QueryServer, audit: &mut AuditScope| {
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
            .unwrap();
            let ce = CreateEvent::from_vec(vec![e1]);
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
}
