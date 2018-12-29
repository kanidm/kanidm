use audit::AuditScope;
use be::Backend;
use entry::Entry;
use error::OperationError;
use event::CreateEvent;
use schema::Schema;

mod uuid;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create(
        be: &mut Backend,
        au: &mut AuditScope,
        cand: &mut Vec<Entry>,
        ce: &CreateEvent,
        schema: &Schema,
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
        $be:ident,
        $au:ident,
        $cand:ident,
        $ce:ident,
        $schema:ident,
        $target_plugin:ty
    ) => {{
        let mut audit_scope = AuditScope::new(<($target_plugin)>::id());
        let r = audit_segment!(audit_scope, || <($target_plugin)>::pre_create(
            $be,
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
        be: &mut Backend,
        au: &mut AuditScope,
        cand: &mut Vec<Entry>,
        ce: &CreateEvent,
        schema: &Schema,
    ) -> Result<(), OperationError> {
        audit_segment!(audit_plugin_pre, || {
            // map chain?
            let uuid_res = run_pre_create_plugin!(be, au, cand, ce, schema, uuid::UUID);

            // TODO, actually return the right thing ...
            uuid_res
        })
    }
}

// We should define the order that plugins should run

// How do we deal with plugin activation? Config?
// What do plugins default to?
