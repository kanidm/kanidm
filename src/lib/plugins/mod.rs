use audit::AuditScope;
use entry::{Entry, EntryInvalid, EntryNew};
use error::OperationError;
use event::CreateEvent;
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

    fn post_create() -> Result<(), OperationError> {
        Ok(())
    }

    fn pre_modify() -> Result<(), OperationError> {
        Ok(())
    }

    fn post_modify() -> Result<(), OperationError> {
        Ok(())
    }

    fn pre_delete() -> Result<(), OperationError> {
        Ok(())
    }

    fn post_delete() -> Result<(), OperationError> {
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
}

// We should define the order that plugins should run

// How do we deal with plugin activation? Config?
// What do plugins default to?
