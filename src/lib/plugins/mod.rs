use audit::AuditScope;
use be::Backend;
use entry::Entry;
use error::OperationError;
use event::CreateEvent;
use schema::Schema;

trait Plugin {
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

mod uuid;

// We should define the order that plugins should run

// How do we deal with plugin activation? Config?
// What do plugins default to?
