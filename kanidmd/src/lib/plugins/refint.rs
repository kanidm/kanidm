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

use std::collections::BTreeSet;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryValid};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::{Modify, ModifyInvalid, ModifyList};
use crate::plugins::Plugin;
use crate::schema::SchemaTransaction;
use crate::server::QueryServerTransaction;
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::{ConsistencyError, OperationError};
use uuid::Uuid;

// NOTE: This *must* be after base.rs!!!

pub struct ReferentialIntegrity;

impl ReferentialIntegrity {
    fn check_uuid_exists(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        rtype: &String,
        uuid_value: &Value,
    ) -> Result<(), OperationError> {
        debug!("{:?}", uuid_value);
        let uuid = try_audit!(au, uuid_value.to_ref_uuid().ok_or(OperationError::Plugin));
        let mut au_qs = AuditScope::new("qs_exist");
        // NOTE: This only checks LIVE entries (not using filter_all)
        let filt_in = filter!(f_eq("uuid", PartialValue::new_uuid(uuid.clone())));
        let r = qs.internal_exists(&mut au_qs, filt_in);
        au.append_scope(au_qs);

        let b = try_audit!(au, r);
        // Is the reference in the result set?
        if b {
            Ok(())
        } else {
            audit_log!(
                au,
                "{:?}:{:?} UUID reference not found in database",
                rtype,
                uuid
            );
            Err(OperationError::Plugin)
        }
    }
}

impl Plugin for ReferentialIntegrity {
    fn id() -> &'static str {
        "referential_integrity"
    }

    // Why are these checks all in post?
    //
    // There is a situation to account for which is that a create or mod
    // may introduce the entry which is also to be referenced in the same
    // transaction. Rather than have seperate verification paths - one to
    // check the UUID is in the cand set, and one to check the UUID exists
    // in the DB, we do the "correct" thing, write to the DB, and then assert
    // that the DB content is complete and valid instead.
    //
    // Yes, this does mean we do more work to add/index/rollback in an error
    // condition, *but* it means we only have developed a single verification
    // so we can assert stronger trust in it's correct operation and interaction
    // in complex scenarioes - It actually simplifies the check from "could
    // be in cand AND db" to simply "is it in the DB?".
    fn post_create(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        // For all cands
        for c in cand {
            // For all reference in each cand.
            for rtype in ref_types.values() {
                match c.get_ava(&rtype.name) {
                    // If the attribute is present
                    Some(vs) => {
                        // For each value in the set.
                        for v in vs {
                            Self::check_uuid_exists(au, qs, &rtype.name, v)?
                        }
                    }
                    None => {}
                }
            }
        }
        Ok(())
    }

    fn post_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        // For all mods
        for modify in me.modlist.into_iter() {
            match &modify {
                // If the mod affects a reference type and being ADDED.
                Modify::Present(a, v) => {
                    match ref_types.get(a) {
                        Some(a_type) => {
                            // So it is a reference type, now check it.
                            Self::check_uuid_exists(au, qs, &a_type.name, v)?
                        }
                        None => {}
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn post_delete(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Delete is pretty different to the other pre checks. This is
        // actually the bulk of the work we'll do to clean up references
        // when they are deleted.

        // Find all reference types in the schema
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();
        // Get the UUID of all entries we are deleting
        let uuids: Vec<&Uuid> = cand.iter().map(|e| e.get_uuid()).collect();

        // Generate a filter which is the set of all schema reference types
        // as EQ to all uuid of all entries in delete. - this INCLUDES recycled
        // types too!
        let filt = filter_all!(FC::Or(
            uuids
                .iter()
                .map(|u| ref_types.values().map(move |r_type| {
                    // For everything that references the uuid's in the deleted set.
                    f_eq(r_type.name.as_str(), PartialValue::new_refer(*u.clone()))
                }))
                .flatten()
                .collect(),
        ));

        audit_log!(au, "refint post_delete filter {:?}", filt);

        // Create a modlist:
        //    In each, create a "removed" for each attr:uuid pair
        let modlist: ModifyList<ModifyInvalid> = ModifyList::new_list(
            uuids
                .iter()
                .map(|u| {
                    ref_types.values().map(move |r_type| {
                        Modify::Removed(r_type.name.clone(), PartialValue::new_refer(*u.clone()))
                    })
                })
                .flatten()
                .collect(),
        );

        audit_log!(au, "refint post_delete modlist {:?}", modlist);

        // Do an internal modify to apply the modlist and filter.

        qs.internal_modify(au, filt, modlist)
    }

    fn verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        // Get all entries as cand
        //      build a cand-uuid set
        let filt_in = filter_all!(f_pres("class"));

        let all_cand = match qs
            .internal_search(au, filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let acu_map: BTreeSet<&Uuid> = all_cand.iter().map(|e| e.get_uuid()).collect();

        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let mut res = Vec::new();
        // For all cands
        for c in &all_cand {
            // For all reference in each cand.
            for rtype in ref_types.values() {
                match c.get_ava(&rtype.name) {
                    // If the attribute is present
                    Some(vs) => {
                        // For each value in the set.
                        for v in vs {
                            match v.to_ref_uuid() {
                                Some(vu) => {
                                    if acu_map.get(vu).is_none() {
                                        res.push(Err(ConsistencyError::RefintNotUpheld(c.get_id())))
                                    }
                                }
                                None => res.push(Err(ConsistencyError::InvalidAttributeType(
                                    "A non-value-ref type was found.",
                                ))),
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    // #[macro_use]
    // use crate::plugins::Plugin;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use crate::value::{PartialValue, Value};
    use kanidm_proto::v1::OperationError;

    // The create references a uuid that doesn't exist - reject
    #[test]
    fn test_create_uuid_reference_not_exist() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let create = vec![e.clone()];
        let preload = Vec::new();
        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    // The create references a uuid that does exist - validate
    #[test]
    fn test_create_uuid_reference_exist() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let preload = vec![ea];
        let create = vec![eb];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(
                        au,
                        filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
                    )
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // The create references itself - allow
    #[test]
    fn test_create_uuid_reference_self() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(
                        au,
                        filter!(f_eq("name", PartialValue::new_iutf8s("testgroup"))),
                    )
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // Modify references a different object - allow
    #[test]
    fn test_modify_uuid_reference_exist() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_, _| {}
        );
    }

    // Modify reference something that doesn't exist - must be rejected
    #[test]
    fn test_modify_uuid_reference_not_exist() {
        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![eb];

        run_modify_test!(
            Err(OperationError::Plugin),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_, _| {}
        );
    }

    // Modify removes the reference to an entry
    #[test]
    fn test_modify_remove_referee() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Purged("member".to_string())]),
            None,
            |_, _| {}
        );
    }

    // Modify adds reference to self - allow
    #[test]
    fn test_modify_uuid_reference_self() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_, _| {}
        );
    }

    // Test that deleted entries can not be referenced
    #[test]
    fn test_modify_reference_deleted() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group", "recycled"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_, _| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // This is the valid case, where the reference is MAY.
    #[test]
    fn test_delete_remove_referent_valid() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_a"))),
            None,
            |_au: &mut AuditScope, _qs: &QueryServerWriteTransaction| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // this is the invalid case, where the reference is MUST.
    #[test]
    fn test_delete_remove_referent_invalid() {}

    // Delete of something that holds references.
    #[test]
    fn test_delete_remove_referee() {
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            None,
            |_au: &mut AuditScope, _qs: &QueryServerWriteTransaction| {}
        );
    }

    // Delete something that has a self reference.
    #[test]
    fn test_delete_remove_reference_self() {
        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_b"))),
            None,
            |_au: &mut AuditScope, _qs: &QueryServerWriteTransaction| {}
        );
    }
}
