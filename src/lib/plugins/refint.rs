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
    #[macro_use]
    use crate::plugins::Plugin;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::OperationError;
    use crate::server::{QueryServerWriteTransaction, QueryServerReadTransaction};
    use crate::filter::Filter;

    // The create references a uuid that doesn't exist - reject
    #[test]
    fn test_create_uuid_reference_not_exist() {
        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "description": ["testperson"],
                "member": ["ca85168c-91b7-49a8-b7bb-a3d5bb40e97e"]
            }
        }"#,
        )
        .unwrap();

        let create = vec![e.clone()];
        let preload = vec![e];
        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            false,
            |_, _| {}
        );
    }

    // The create references a uuid that does exist - validate
    #[test]
    fn test_create_uuid_reference_exist() {
        let ea: Entry<EntryInvalid, EntryNew> =
        serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        )
        .unwrap();

        let eb: Entry<EntryInvalid, EntryNew> =
        serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        )
        .unwrap();

        let preload = vec![ea];
        let create = vec![eb];

        run_create_test!(
            Ok(()),
            preload,
            create,
            false,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(au, Filter::Eq("name".to_string(), "testgroup_b".to_string()))
                    .unwrap();
                let ue = cands.first().unwrap();
            }
        );
    }

    // The create references itself - allow
    #[test]
    fn test_create_uuid_reference_self() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "description": ["testgroup"],
                "uuid": ["8cef42bc-2cac-43e4-96b3-8f54561885ca"],
                "member": ["8cef42bc-2cac-43e4-96b3-8f54561885ca"]
            }
        }"#,
        )
        .unwrap();

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            false,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(au, Filter::Eq("name".to_string(), "testgroup".to_string()))
                    .unwrap();
                let ue = cands.first().unwrap();
            }
        );
    }

    // Modify references a different object - allow
    #[test]
    fn test_modify_uuid_reference_exist() {
        unimplemented!();
    }

    // Modify reference something that doesn't exist - must be rejected
    #[test]
    fn test_modify_uuid_reference_not_exist() {
        unimplemented!();
    }

    // Modify removes an entry that something else pointed to. - must remove ref in other
    #[test]
    fn test_modify_remove_referent() {
        unimplemented!();
    }

    // Modify removes the reference to an entry - doesn't need a test
    #[test]
    fn test_modify_remove_referee() {
        unimplemented!();
    }

    // Modify adds reference to self - allow
    #[test]
    fn test_modify_uuid_reference_self() {
        unimplemented!();
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    #[test]
    fn test_delete_remove_referent() {
        unimplemented!();
    }

    // Delete of something that holds references - doesn't need a test
    #[test]
    fn test_delete_remove_referee() {
        unimplemented!();
    }

    // Delete something that has a self reference
    #[test]
    fn test_delete_remove_reference_self() {
        unimplemented!();
    }
}
