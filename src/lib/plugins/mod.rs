use audit::AuditScope;
use be::BackendReadTransaction;
use entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use error::{ConsistencyError, OperationError};
use event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use schema::SchemaReadTransaction;
use server::{QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction};

#[macro_use]
mod macros;

mod base;
mod failure;
mod protected;
mod recycle;
mod refint;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create(
        // TODO: I think this is wrong, it should be a query server.
        // Narators voice: He was wrong ... it must be a query server.
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    fn post_create(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we commited that was validate?
        _cand: &Vec<Entry<EntryValid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    fn pre_modify() -> Result<(), OperationError> {
        Ok(())
    }

    fn post_modify(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    fn pre_delete() -> Result<(), OperationError> {
        Ok(())
    }

    fn post_delete(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    fn verify(
        _au: &mut AuditScope,
        _qs: &QueryServerTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        Vec::new()
    }
}

pub struct Plugins {}

// TODO: Should this be a function instead, to allow inlining and better debug?

macro_rules! run_pre_create_plugin {
    (
        $au:ident,
        $qs:ident,
        $cand:ident,
        $ce:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<($target_plugin)>::id());
        let mut r = audit_segment!(audit_scope, || <($target_plugin)>::pre_create(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

macro_rules! run_verify_plugin {
    (
        $au:ident,
        $qs:ident,
        $results:expr,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<($target_plugin)>::id());
        let mut r = audit_segment!(audit_scope, || <($target_plugin)>::verify(
            &mut audit_scope,
            $qs,
        ));
        $results.append(&mut r);
        $au.append_scope(audit_scope);
    }};
}

impl Plugins {
    pub fn run_pre_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            // map chain?
            let res = run_pre_create_plugin!(au, qs, cand, ce, base::Base).and_then(|_| {
                run_pre_create_plugin!(au, qs, cand, ce, refint::ReferentialIntegrity)
            });

            // TODO, actually return the right thing ...
            res
        })
    }

    pub fn run_post_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_pre_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_post_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_pre_delete(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_post_delete(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_verify(
        au: &mut AuditScope,
        qs: &QueryServerTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        let mut results = Vec::new();
        run_verify_plugin!(au, qs, &mut results, base::Base);
        run_verify_plugin!(au, qs, &mut results, refint::ReferentialIntegrity);
        results
    }
}
