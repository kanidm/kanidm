use crate::prelude::*;
use crate::plugins::Plugin;
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use std::sync::Arc;

pub struct DynGroup;

impl Plugin for DynGroup {
    fn id() -> &'static str {
        "dyngroup"
    }

    fn post_create(
        _qs: &QueryServerWriteTransaction,
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // If we created any dyn groups, populate them now.
        //    if the event is not internal, reject (for now)

        // For any other entries, check if they SHOULD trigger
        // a dyn group inclusion.

        Ok(())
    }

    fn post_modify(
        _qs: &QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {

        // If we modified a dyngroups member or filter, re-trigger it here.
        //    if the event is not internal, reject (for now)

        // If we modified anything else, check if a dyngroup is affected by it's change
        // if it was a member.

        Ok(())
    }

    fn post_delete(
        _qs: &QueryServerWriteTransaction,
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {

        // I don't think anything is needed on delete. If we delete a dyngroup, we've
        // already done the clean up and memberof does the rest.
        //    if the event is not internal, reject (for now)

        // if we delete a refering entry, then refint takes care of it.
        Ok(())
    }

    fn verify(_qs: &QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use kanidm_proto::v1::Filter as ProtoFilter;

    #[test]
    fn test_create_dyngroup_add_new_group() {
        let ea = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            ("dyngroup_filter", Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "admin".to_string())))
        );

        // No need to preload.
        let preload = vec![];
        let create = vec![ea];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group.get_ava_set("member").expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(*UUID_ADMIN));
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry() {
    }

    #[test]
    fn test_create_dyngroup_add_non_matching_entry() {
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry_and_group() {
    }

    #[test]
    fn test_create_dyngroup_modify_existing_dyngroup_filter() {
    }

    #[test]
    fn test_create_dyngroup_modify_existing_dyngroup_member_add() {
    }

    #[test]
    fn test_create_dyngroup_modify_existing_dyngroup_member_remove() {
    }

    #[test]
    fn test_create_dyngroup_modify_into_matching_entry() {
    }

    #[test]
    fn test_create_dyngroup_modify_into_non_matching_entry() {
    }

    #[test]
    fn test_create_dyngroup_delete_matching_entry() {
    }

    #[test]
    fn test_create_dyngroup_delete_group() {
    }
}
