use crate::plugins::Plugin;
use uuid::Uuid;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryInvalid, EntryNew};
use crate::error::{ConsistencyError, OperationError};
use crate::event::CreateEvent;
use crate::filter::{Filter, FilterInvalid};
use crate::server::{
    QueryServerReadTransaction, QueryServerTransaction, QueryServerWriteTransaction,
};

// TO FINISH
/*
Add normalisation step
Add filter normaliser to search.
Add principal name generation
*/

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

    fn pre_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // For each candidate
        for entry in cand.iter_mut() {
            let name_uuid = String::from("uuid");

            audit_log!(au, "Base check on entry: {:?}", entry);

            // First, ensure we have the 'object', class in the class set.
            entry.add_ava(String::from("class"), String::from("object"));

            audit_log!(au, "Object should now be in entry: {:?}", entry);

            // If they have a name, but no principal name, derive it.

            // if they don't have uuid, create it.
            // TODO: get_ava should have a str version for effeciency?
            let c_uuid: String = match entry.get_ava(&name_uuid) {
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

            // Make it a string, so we can filter.
            let mut au_qs = AuditScope::new("qs_exist");

            // We need to clone to the filter because it owns the content
            // Now, str_uuid could we invalid, but the filter validation step here will check
            // that for us *and* if we fails, we return because the value was not valid. If it
            // works, great, we can check for duplication.
            let filt_in: Filter<FilterInvalid> = Filter::Eq(name_uuid.clone(), c_uuid.clone());
            // let schema_ro = qs.get_schema();
            // let filt = try_audit!(au, filt_in.validate(schema_ro));

            let r = qs.internal_exists(&mut au_qs, filt_in);

            au.append_scope(au_qs);
            // end the scope for the be operation.

            match r {
                Ok(b) => {
                    if b == true {
                        audit_log!(au, "Base already exists, rejecting.");
                        return Err(OperationError::Plugin);
                    }
                }
                Err(e) => {
                    audit_log!(au, "Error occured checking Base existance. {:?}", e);
                    return Err(OperationError::Plugin);
                }
            }

            audit_log!(au, "Setting UUID {} to entry", c_uuid);
            let ava_uuid: Vec<String> = vec![c_uuid];

            entry.set_avas(name_uuid, ava_uuid);
            audit_log!(au, "Final entry state: {:?}", entry);
        }
        // done!

        Ok(())
    }

    fn verify(
        au: &mut AuditScope,
        qs: &QueryServerTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        let name_uuid = String::from("uuid");
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
                // TODO: Could this be better?
                let uuid = match e.get_ava(&name_uuid) {
                    Some(u) => {
                        if u.len() == 1 {
                            Ok(u.first().expect("Ohh ffs, really?").clone())
                        } else {
                            Err(ConsistencyError::EntryUuidCorrupt(e.get_id()))
                        }
                    }
                    None => Err(ConsistencyError::EntryUuidCorrupt(e.get_id())),
                };

                match uuid {
                    Ok(u) => {
                        let filt = Filter::Eq(name_uuid.clone(), u.clone());
                        match qs.internal_search(au, filt) {
                            Ok(r) => {
                                if r.len() == 0 {
                                    Err(ConsistencyError::UuidIndexCorrupt(u))
                                } else if r.len() == 1 {
                                    Ok(())
                                } else {
                                    Err(ConsistencyError::UuidNotUnique(u))
                                }
                            }
                            Err(_) => Err(ConsistencyError::QueryServerSearchFailure),
                        }
                    }
                    Err(e) => Err(e),
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
    #[macro_use]
    use crate::plugins::Plugin;
    use std::sync::Arc;

    use crate::audit::AuditScope;
    use crate::be::Backend;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::OperationError;
    use crate::event::CreateEvent;
    use crate::filter::Filter;
    use crate::schema::Schema;
    use crate::server::QueryServerReadTransaction;
    use crate::server::{QueryServer, QueryServerWriteTransaction};

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
        .unwrap();

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            false,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(au, Filter::Eq("name".to_string(), "testperson".to_string()))
                    .unwrap();
                let ue = cands.first().unwrap();
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
        .unwrap();

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            false,
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
        .unwrap();

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            false,
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
        .unwrap();

        let create = vec![e.clone()];

        run_create_test!(
            Ok(()),
            preload,
            create,
            false,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(au, Filter::Eq("name".to_string(), "testperson".to_string()))
                    .unwrap();
                let ue = cands.first().unwrap();
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
        .unwrap();

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin),
            preload,
            create,
            false,
            |_, _| {}
        );
    }

    // check create where uuid already exists.
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

    // check create where uuid is a well-known
    // WARNING: This actually requires me to implement backend migrations and
    // creation of default objects in the DB on new() if they don't exist, and
    // to potentially support migrations of said objects.
}
