use audit::AuditScope;
use entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use error::OperationError;
use event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use server::QueryServerWriteTransaction;

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

    fn pre_search() -> Result<(), OperationError> {
        Ok(())
    }

    fn post_search() -> Result<(), OperationError> {
        Ok(())
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
        let r = audit_segment!(audit_scope, || <($target_plugin)>::pre_create(
            &mut audit_scope,
            $qs,
            $cand,
            $ce,
        ));
        $au.append_scope(audit_scope);
        r
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

    pub fn run_pre_search(au: &mut AuditScope) -> Result<(), OperationError> {
        Ok(())
    }

    pub fn run_post_search(au: &mut AuditScope) -> Result<(), OperationError> {
        Ok(())
    }
}

// We should define the order that plugins should run

// How do we deal with plugin activation? Config?
// What do plugins default to?
