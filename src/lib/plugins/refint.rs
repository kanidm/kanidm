// Referential Integrity
//
// Given an entry, modification or change, ensure that all referential links
// in the database are maintained. IE there are no dangling references that
// are unable to be resolved, as this may cause errors in Item -> ProtoItem
// translation.
//
// It will be important to understand the interaction of this plugin with memberof
// when that is written, as they *both* manipulate and alter entry reference
// data, so we should be careful not to step on each other.

use plugins::Plugin;
use audit::AuditScope;
use entry::{Entry, EntryCommitted, EntryNew, EntryValid};
use error::OperationError;
use event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use server::QueryServerWriteTransaction;

pub struct ReferentialIntegrity;

impl Plugin for ReferentialIntegrity {
    fn id() -> &'static str {
        "referential_integrity"
    }

    fn post_create(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &Vec<Entry<EntryValid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
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

    fn post_delete(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }
}
