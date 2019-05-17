use crate::plugins::Plugin;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew};
use crate::error::{ConsistencyError, OperationError};
use crate::event::{CreateEvent, ModifyEvent};
use crate::filter::{Filter, FilterInvalid};
use crate::modify::{Modify, ModifyList, ModifyValid};
use crate::server::{
    QueryServerTransaction, QueryServerReadTransaction, QueryServerWriteTransaction,
};

// TO FINISH
/*
Add normalisation step
Add filter normaliser to search.
Add principal name generation
*/

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
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // For each candidate
        for entry in cand.iter_mut() {
            audit_log!(au, "Base check on entry: {:?}", entry);

            // First, ensure we have the 'object', class in the class set.
            entry.add_ava("class", "object");

            audit_log!(au, "Object should now be in entry: {:?}", entry);

            // If they have a name, but no principal name, derive it.

            // if they don't have uuid, create it.
            // TODO: get_ava should have a str version for effeciency?
            let c_uuid: String = match entry.get_ava("uuid") {
                Some(u) => {
                    // Actually check we have a value, could be empty array ...
                    // TODO: Should this be left to schema to assert the value?
                    if u.len() > 1 {
                        audit_log!(au, "Entry defines uuid attr, but multiple values.");
                        return Err(OperationError::Plugin);
                    };

                    // Schema of the value v, is checked in the filter generation. Neat!

                    // Should this be forgiving and just generate the UUID?
                    // NO! If you tried to specify it, but didn't give it, then you made
                    // a mistake and your intent is unknown.
                    try_audit!(
                        au,
                        u.first().ok_or(OperationError::Plugin).map(|v| v.clone())
                    )
                }
                None => Uuid::new_v4().to_hyphenated().to_string(),
            };

            audit_log!(au, "Setting temporary UUID {} to entry", c_uuid);
            let ava_uuid: Vec<String> = vec![c_uuid];

            entry.set_avas("uuid", ava_uuid);
            audit_log!(au, "Temporary entry state: {:?}", entry);
        }

        // Now, every cand has a UUID - create a cand uuid set from it.
        let mut cand_uuid: BTreeMap<&String, ()> = BTreeMap::new();

        // As we insert into the set, if a duplicate is found, return an error
        // that a duplicate exists.
        for entry in cand.iter() {
            let uuid_ref = entry
                .get_ava("uuid")
                .ok_or(OperationError::Plugin)?
                .first()
                .ok_or(OperationError::Plugin)?;
            audit_log!(au, "Entry valid UUID: {:?}", entry);
            match cand_uuid.insert(uuid_ref, ()) {
                Some(v) => {
                    audit_log!(au, "uuid duplicate found in create set! {:?}", v);
                    return Err(OperationError::Plugin);
                }
                None => {}
            }
        }

        // Now from each element, generate a filter to search for all of them
        //
        // NOTE: We don't exclude recycled or tombstones here!

        let filt_in: Filter<FilterInvalid> = Filter::Or(
            cand_uuid
                .keys()
                .map(|u| Filter::Eq("uuid".to_string(), u.to_string()))
                .collect(),
        );

        // If any results exist, fail as a duplicate UUID is present.
        // TODO: Can we report which UUID exists? Probably yes, we do
        // internal searh and report the UUID *OR* we alter internal_exists
        // to return UUID sets.

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
        _qs: &QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
        modlist: &ModifyList<ModifyValid>,
    ) -> Result<(), OperationError> {
        for modify in modlist.into_iter() {
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
        let entries = match qs.internal_search(au, Filter::Pres("class".to_string())) {
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
                let uuid: &String = e.get_uuid();

                let filt = Filter::Eq("uuid".to_string(), uuid.to_string());
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
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::OperationError;
    use crate::filter::Filter;
    use crate::modify::{Modify, ModifyList};
    use crate::server::QueryServerTransaction;
    use crate::server::QueryServerWriteTransaction;

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
                    .internal_search(au, Filter::Eq("name".to_string(), "testperson".to_string()))
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
                    .internal_search(au, Filter::Eq("name".to_string(), "testperson".to_string()))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No cand");
                assert!(ue.attribute_equality("uuid", "79724141-3603-4060-b6bb-35c72772611d"));
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
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d", "79724141-3603-4060-b6bb-35c72772611d"]
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
            Filter::Eq("name".to_string(), "testgroup_a".to_string()),
            ModifyList::new_list(vec![Modify::Present(
                "uuid".to_string(),
                "f15a7219-1d15-44e3-a7b4-bec899c07788".to_string()
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
            Filter::Eq("name".to_string(), "testgroup_a".to_string()),
            ModifyList::new_list(vec![Modify::Removed(
                "uuid".to_string(),
                "f15a7219-1d15-44e3-a7b4-bec899c07788".to_string()
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
            Filter::Eq("name".to_string(), "testgroup_a".to_string()),
            ModifyList::new_list(vec![Modify::Purged("uuid".to_string())]),
            None,
            |_, _| {}
        );
    }
}
