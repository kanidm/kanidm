use crate::plugins::Plugin;
use std::collections::BTreeSet;
// TODO: Should be able to generate all uuid's via Value.
use uuid::Uuid;

use crate::audit::AuditScope;
// use crate::constants::{STR_UUID_ADMIN, STR_UUID_ANONYMOUS, STR_UUID_DOES_NOT_EXIST};
use crate::constants::{UUID_ADMIN, UUID_ANONYMOUS, UUID_DOES_NOT_EXIST};
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew};
use crate::error::{ConsistencyError, OperationError};
use crate::event::{CreateEvent, ModifyEvent};
use crate::modify::Modify;
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};
use crate::value::{PartialValue, Value};

lazy_static! {
    static ref CLASS_OBJECT: Value = Value::new_class("object");
}

// This module has some special properties around it's operation, namely that it
// has to make a certain number of assertions *early* in the entry lifecycle around
// names and uuids since these have such signifigance to every other part of the
// servers operation. As a result, this is the ONLY PLUGIN that does validation in the
// pre_create_transform step, where every other SHOULD use the post_* hooks for all
// validation operations.
//
// Additionally, this plugin WILL block and deny certain modifications to uuids and
// more to prevent intentional DB damage.

pub struct Base {}

impl Plugin for Base {
    fn id() -> &'static str {
        "plugin_base"
    }
    // Need to be given the backend(for testing ease)
    // audit
    // the mut set of entries to create
    // the create event itself (immutable, for checking originals)
    //     contains who is creating them
    // the schema of the running instance

    fn pre_create_transform(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // For each candidate
        for entry in cand.iter_mut() {
            audit_log!(au, "Base check on entry: {:?}", entry);

            // First, ensure we have the 'object', class in the class set.
            entry.add_ava("class", &CLASS_OBJECT);

            audit_log!(au, "Object should now be in entry: {:?}", entry);

            // If they have a name, but no principal name, derive it.

            // if they don't have uuid, create it.
            let c_uuid: Value = match entry.get_ava("uuid") {
                Some(u) => {
                    // Actually check we have a value, could be empty array ...
                    if u.len() > 1 {
                        audit_log!(au, "Entry defines uuid attr, but multiple values.");
                        return Err(OperationError::Plugin);
                    };

                    // Schema of the value v, is checked in the filter generation. Neat!
                    // That way we don't need to check it here either.

                    // Should this be forgiving and just generate the UUID?
                    // NO! If you tried to specify it, but didn't give it, then you made
                    // a mistake and your intent is unknown.
                    let v: Value = try_audit!(
                        au,
                        u.first()
                            .ok_or(OperationError::Plugin)
                            .map(|v| (*v).clone())
                    );
                    v
                }
                None => Value::new_uuid(Uuid::new_v4()),
            };

            audit_log!(au, "Setting temporary UUID {:?} to entry", c_uuid);
            let ava_uuid: Vec<Value> = vec![c_uuid];

            entry.set_avas("uuid", ava_uuid);
            audit_log!(au, "Temporary entry state: {:?}", entry);
        }

        // Now, every cand has a UUID - create a cand uuid set from it.
        let mut cand_uuid: BTreeSet<&Uuid> = BTreeSet::new();

        // As we insert into the set, if a duplicate is found, return an error
        // that a duplicate exists.
        //
        // Remember, we have to use the ava here, not the get_uuid types because
        // we may not have filled in the uuid field yet.
        for entry in cand.iter() {
            let uuid_ref: &Uuid = entry
                .get_ava_single("uuid")
                .ok_or(OperationError::Plugin)?
                .to_uuid()
                .ok_or(OperationError::Plugin)?;
            audit_log!(au, "Entry valid UUID: {:?}", entry);
            match cand_uuid.insert(uuid_ref) {
                false => {
                    audit_log!(au, "uuid duplicate found in create set! {:?}", uuid_ref);
                    return Err(OperationError::Plugin);
                }
                true => {}
            }
        }

        // Setup UUIDS because lazy_static can't create a type valid for range.
        let uuid_admin = UUID_ADMIN.clone();
        let uuid_anonymous = UUID_ANONYMOUS.clone();
        let uuid_does_not_exist = UUID_DOES_NOT_EXIST.clone();

        // Check that the system-protected range is not in the cand_uuid, unless we are
        // an internal operation.
        if !ce.event.is_internal() {
            // TODO: We can't lazy static this as you can't borrow the type down to what
            // range and contains on btreeset need, but can we possibly make these staticly
            // part of the struct somehow at init. rather than needing to parse a lot?
            // The internal set is bounded by: UUID_ADMIN -> UUID_ANONYMOUS
            // Sadly we need to allocate these to strings to make references, sigh.
            let overlap: usize = cand_uuid.range(uuid_admin..uuid_anonymous).count();
            if overlap != 0 {
                audit_log!(
                    au,
                    "uuid from protected system UUID range found in create set! {:?}",
                    overlap
                );
                return Err(OperationError::Plugin);
            }
        }

        if cand_uuid.contains(&uuid_does_not_exist) {
            audit_log!(
                au,
                "uuid \"does not exist\" found in create set! {:?}",
                uuid_does_not_exist
            );
            return Err(OperationError::Plugin);
        }

        // Now from each element, generate a filter to search for all of them
        //
        // IMPORTANT: We don't exclude recycled or tombstones here!
        let filt_in = filter_all!(FC::Or(
            cand_uuid
                .iter()
                .map(|u| FC::Eq("uuid", PartialValue::new_uuid(*u.clone())))
                .collect(),
        ));

        // If any results exist, fail as a duplicate UUID is present.
        // TODO #69: Can we report which UUID exists? Probably yes, we do
        // internal search and report the UUID *OR* we alter internal_exists
        // to return UUID sets. This can be done as an extension to #69 where the
        // internal exists is actually a wrapper around a search for uuid internally
        //
        // But does it add value? How many people will try to custom define/add uuid?
        let mut au_qs = AuditScope::new("qs_exist");
        let r = qs.internal_exists(&mut au_qs, filt_in);
        au.append_scope(au_qs);

        match r {
            Ok(b) => {
                if b == true {
                    audit_log!(au, "A UUID already exists, rejecting.");
                    return Err(OperationError::Plugin);
                }
            }
            Err(e) => {
                audit_log!(au, "Error occured checking UUID existance. {:?}", e);
                return Err(OperationError::Plugin);
            }
        }

        Ok(())
    }

    fn pre_modify(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        for modify in me.modlist.into_iter() {
            let attr = match &modify {
                Modify::Present(a, _) => a,
                Modify::Removed(a, _) => a,
                Modify::Purged(a) => a,
            };
            if attr == "uuid" {
                audit_log!(au, "Modifications to UUID's are NOT ALLOWED");
                return Err(OperationError::Plugin);
            }
        }
        Ok(())
    }

    fn verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        // Verify all uuid's are unique?
        // Probably the literally worst thing ...

        // Search for class = *
        let entries = match qs.internal_search(au, filter!(f_pres("class"))) {
            Ok(v) => v,
            Err(e) => {
                audit_log!(au, "Internal Search Failure: {:?}", e);
                return vec![Err(ConsistencyError::QueryServerSearchFailure)];
            }
        };

        let r_uniq = entries
            .iter()
            // do an exists checks on the uuid
            .map(|e| {
                // To get the entry deserialised, a UUID MUST EXIST, else an expect
                // will be thrown in the deserialise (possibly it will be better
                // handled later). But it means this check only needs to validate
                // uniqueness!
                let uuid: &Uuid = e.get_uuid();

                let filt = filter!(FC::Eq("uuid", PartialValue::new_uuid(uuid.clone())));
                match qs.internal_search(au, filt) {
                    Ok(r) => {
                        if r.len() == 0 {
                            Err(ConsistencyError::UuidIndexCorrupt(uuid.to_string()))
                        } else if r.len() == 1 {
                            Ok(())
                        } else {
                            Err(ConsistencyError::UuidNotUnique(uuid.to_string()))
                        }
                    }
                    Err(_) => Err(ConsistencyError::QueryServerSearchFailure),
                }
            })
            .filter(|v| v.is_err())
            .collect();

        /*
        let mut r_name = entries.iter()
            // do an eq internal search and validate == 1 (ignore ts + rc)
            .map(|e| {
            })
            .filter(|v| {
                v.is_err()
            })
            .collect();

        r_uniq.append(r_name);
        */

        r_uniq
    }
}

#[cfg(test)]
mod tests {
    // #[macro_use]
    // use crate::plugins::Plugin;
    use crate::constants::JSON_ADMIN_V1;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::OperationError;
    use crate::modify::{Modify, ModifyList};
    use crate::server::QueryServerTransaction;
    use crate::server::QueryServerWriteTransaction;
    use crate::value::{PartialValue, Value};

    static JSON_ADMIN_ALLOW_ALL: &'static str = r#"{
        "valid": null,
        "state": null,
        "attrs": {
            "class": [
                "object",
                "access_control_profile",
                "access_control_modify",
                "access_control_create",
                "access_control_delete",
                "access_control_search"
            ],
            "name": ["idm_admins_acp_allow_all_test"],
            "uuid": ["bb18f746-a409-497d-928c-5455d4aef4f7"],
            "description": ["Builtin IDM Administrators Access Controls."],
            "acp_enable": ["true"],
            "acp_receiver": [
                "{\"Eq\":[\"uuid\",\"00000000-0000-0000-0000-000000000000\"]}"
            ],
            "acp_targetscope": [
                "{\"Pres\":\"class\"}"
            ],
            "acp_search_attr": ["name", "class", "uuid"],
            "acp_modify_class": ["system"],
            "acp_modify_removedattr": ["class", "displayname", "may", "must"],
            "acp_modify_presentattr": ["class", "displayname", "may", "must"],
            "acp_create_class": ["object", "person", "system"],
            "acp_create_attr": ["name", "class", "description", "displayname", "uuid"]
        }
    }"#;

    // check create where no uuid
    #[test]
    fn test_pre_create_no_uuid() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

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
                        filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
                    )
                    .expect("Internal search failure");
                let ue = cands.first().expect("No cand");
                assert!(ue.attribute_pres("uuid"));
            }
        );
    }

    // check unparseable uuid
    #[test]
    fn test_pre_create_uuid_invalid() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["xxxxxx"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    // check entry where uuid is empty list
    #[test]
    fn test_pre_create_uuid_empty() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": []
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    // check create where provided uuid is valid. It should be unchanged.
    #[test]
    fn test_pre_create_uuid_valid() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(
                        au,
                        filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
                    )
                    .expect("Internal search failure");
                let ue = cands.first().expect("No cand");
                assert!(ue.attribute_equality(
                    "uuid",
                    &PartialValue::new_uuids("79724141-3603-4060-b6bb-35c72772611d").unwrap()
                ));
            }
        );
    }

    #[test]
    fn test_pre_create_uuid_valid_multi() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d", "79724141-3603-4060-b6bb-35c72772611e"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    // check create where uuid already exists.
    // -- check create where uuid is a well-known
    // This second case is technically handled as well-known
    // types are created "at startup" so it's not possible
    // to create one.
    //
    // To solidify this, we could make a range of min-max well knowns
    // to ensure we always have a name space to draw from?
    #[test]
    fn test_pre_create_uuid_exist() {
        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];
        let preload = vec![e];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_create_double_uuid() {
        // Test adding two entries with the same uuid
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();

        let ea: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson_a"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        )
        .expect("json parse failure");

        let eb: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person"],
                "name": ["testperson_a"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![ea, eb];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }

    // All of these *SHOULD* be blocked?
    #[test]
    fn test_modify_uuid_present() {
        // Add another uuid to a type
        let ea: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
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
        .expect("json parse failure");

        let preload = vec![ea];

        run_modify_test!(
            Err(OperationError::Plugin),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Present(
                "uuid".to_string(),
                Value::from("f15a7219-1d15-44e3-a7b4-bec899c07788")
            )]),
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_modify_uuid_removed() {
        // Test attempting to remove a uuid
        let ea: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
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
        .expect("json parse failure");

        let preload = vec![ea];

        run_modify_test!(
            Err(OperationError::Plugin),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Removed(
                "uuid".to_string(),
                PartialValue::new_uuids("f15a7219-1d15-44e3-a7b4-bec899c07788").unwrap()
            )]),
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_modify_uuid_purged() {
        // Test attempting to purge uuid
        let ea: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
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
        .expect("json parse failure");

        let preload = vec![ea];

        run_modify_test!(
            Err(OperationError::Plugin),
            preload,
            filter!(f_eq("name", PartialValue::new_iutf8s("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Purged("uuid".to_string())]),
            None,
            |_, _| {}
        );
    }

    #[test]
    fn test_protected_uuid_range() {
        // Test an external create, it should fail.
        // Testing internal create is not super needed, due to migrations at start
        // up testing this every time we run :P
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");

        let preload = vec![acp];

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "uuid": ["00000000-0000-0000-0000-f0f0f0f0f0f0"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_protected_uuid_does_not_exist() {
        // Test that internal create of "does not exist" will fail.
        let preload = Vec::new();

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "uuid": ["00000000-0000-0000-0000-fffffffffffe"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            None,
            |_, _| {}
        );
    }
}
