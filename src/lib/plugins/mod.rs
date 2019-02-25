use audit::AuditScope;
use be::BackendWriteTransaction;
use entry::{Entry, EntryInvalid, EntryNew};
use error::OperationError;
use event::CreateEvent;
use schema::SchemaWriteTransaction;

mod base;
mod protected;
mod recycle;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create(
        // TODO: I think this is wrong, it should be a query server
        _be: &BackendWriteTransaction,
        _au: &mut AuditScope,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
        _schema: &SchemaWriteTransaction,
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
        $be_txn:ident,
        $au:ident,
        $cand:ident,
        $ce:ident,
        $schema:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<($target_plugin)>::id());
        let r = audit_segment!(audit_scope, || <($target_plugin)>::pre_create(
            $be_txn,
            &mut audit_scope,
            $cand,
            $ce,
            $schema
        ));
        $au.append_scope(audit_scope);
        r
    }};
}

impl Plugins {
    pub fn run_pre_create(
        be_txn: &BackendWriteTransaction,
        au: &mut AuditScope,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
        schema: &SchemaWriteTransaction,
    ) -> Result<(), OperationError> {
        audit_segment!(au, || {
            // map chain?
            let base_res = run_pre_create_plugin!(be_txn, au, cand, ce, schema, base::Base);

            // TODO, actually return the right thing ...
            base_res
        })
    }
}

// We should define the order that plugins should run

// How do we deal with plugin activation? Config?
// What do plugins default to?
