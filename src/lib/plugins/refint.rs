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

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryNew, EntryValid};
use crate::error::OperationError;
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::server::QueryServerWriteTransaction;

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

#[cfg(test)]
mod tests {
    // The create references a uuid that doesn't exist - reject

    // The create references a uuid that does exist - validate

    // The create references itself - allow

    // The create reference a different object - allow

    // Modify references a different object - allow

    // Modify reference something that doesn't exist - must be rejected

    // Modify removes an entry that something else pointed to. - must remove ref in other

    // Modify removes the reference to an entry - doesn't need a test

    // Modify adds reference to self - allow

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)

    // Delete of something that holds references - doesn't need a test
}
