
// == ⚠️  Template, not used yet.


//! This plugin is responsible for pre-extraction of access related elements onto
//! entries. This is a "trade" where we sacrifice time in the write path to pre-calculate
//! a number of access related elements, and we benefit in read/write paths due to
//! optimised application of access controls.
//!
//! Additionally, this also extracts and applies a number of access adjacent elements
//! to accounts - An example being UI hints that are tied in with the ability to
//! perform an action in the webui.


pub struct AccessExtract {}

impl Plugin for AccessExtract {
    fn id() -> &'static str {
        "plugin_session_consistency"
    }

    #[instrument(
        level = "debug",
        name = "accessextract_pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
    }

    #[instrument(level = "debug", name = "accessextract_pre_modify", skip(_qs, cand, _me))]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
    }

    #[instrument(level = "debug", name = "accessextract_pre_delete", skip(_qs, cand, de))]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntrySealed
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Clear all extracted values.
    }
}

// This is outside the normal plugin interface, but when access controls are reloaded, we
// re-run to update the needed attributes on entries.
impl AccessExtract {
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

}

