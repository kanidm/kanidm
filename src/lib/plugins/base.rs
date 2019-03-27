use plugins::Plugin;
use uuid::Uuid;

use audit::AuditScope;
use be::{BackendReadTransaction, BackendWriteTransaction};
use entry::{Entry, EntryInvalid, EntryNew};
use error::OperationError;
use event::CreateEvent;
use filter::Filter;
use schema::SchemaWriteTransaction;
use server::{QueryServerReadTransaction, QueryServerWriteTransaction};

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
            let mut c_uuid = match entry.get_ava(&name_uuid) {
                Some(u) => {
                    // Actually check we have a value, could be empty array ...
                    // TODO: Should this be left to schema to assert the value?
                    if u.len() > 1 {
                        audit_log!(au, "Entry defines uuid attr, but multiple values.");
                        return Err(OperationError::Plugin);
                    };

                    let v = match u.first() {
                        Some(v) => v,
                        None => {
                            // TODO: Should this be forgiving and just generate the UUID?
                            audit_log!(au, "Entry defines uuid attr, but no value.");
                            return Err(OperationError::Plugin);
                        }
                    };

                    // This could actually fail, so we probably need to handle
                    // this better ....
                    // TODO: Make this a SCHEMA check, not a manual one.
                    //
                    match Uuid::parse_str(v.as_str()) {
                        Ok(up) => up,
                        Err(_) => {
                            audit_log!(
                                au,
                                "Entry contains invalid Base content, rejecting out of principle."
                            );
                            return Err(OperationError::Plugin);
                        }
                    }
                }
                None => Uuid::new_v4(),
            };

            // Make it a string, so we can filter.
            let str_uuid = format!("{}", c_uuid);

            let mut au_qs = AuditScope::new("qs_exist");

            // We need to clone to the filter because it owns the content
            let filt = Filter::Eq(name_uuid.clone(), str_uuid.clone());

            let r = qs.internal_exists(&mut au_qs, filt);

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

            let str_uuid = format!("{}", c_uuid);
            audit_log!(au, "Setting UUID {} to entry", str_uuid);
            let ava_uuid: Vec<String> = vec![str_uuid];

            entry.set_avas(name_uuid, ava_uuid);
            audit_log!(au, "Final entry state: {:?}", entry);
        }
        // done!

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plugin;
    use super::Base;
    use std::sync::Arc;

    use audit::AuditScope;
    use be::Backend;
    use entry::{Entry, EntryInvalid, EntryNew};
    use event::CreateEvent;
    use schema::Schema;
    use server::{QueryServer, QueryServerWriteTransaction};

    macro_rules! run_pre_create_test {
        (
            $preload_entries:ident,
            $create_entries:ident,
            $ident:ident,
            $internal:ident,
            $test_fn:expr
        ) => {{
            let mut au = AuditScope::new("run_pre_create_test");
            audit_segment!(au, || {
                // Create an in memory BE
                let be = Backend::new(&mut au, "").unwrap();

                let schema_outer = Schema::new(&mut au).unwrap();
                {
                    let mut schema = schema_outer.write();
                    schema.bootstrap_core(&mut au).unwrap();
                    schema.commit().unwrap();
                }
                let qs = QueryServer::new(be, Arc::new(schema_outer));

                if !$preload_entries.is_empty() {
                    let qs_write = qs.write();
                    qs_write.internal_create(&mut au, $preload_entries);
                    assert!(qs_write.commit(&mut au).is_ok());
                }

                let ce = CreateEvent::from_vec($create_entries.clone());

                let mut au_test = AuditScope::new("pre_create_test");
                {
                    let qs_write = qs.write();
                    audit_segment!(au_test, || $test_fn(
                        &mut au_test,
                        &qs_write,
                        &mut $create_entries,
                        &ce,
                    ));
                    assert!(qs_write.commit(&mut au).is_ok());
                }

                au.append_scope(au_test);
            });
            // Dump the raw audit log.
            println!("{}", au);
        }};
    }

    // Check empty create
    #[test]
    fn test_pre_create_empty() {
        let preload: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();
        let mut create: Vec<Entry<EntryInvalid, EntryNew>> = Vec::new();
        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);

                assert!(r.is_ok());
                // Nothing should have changed.
                assert!(cand.len() == 0);
            }
        );
    }

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

        let mut create = vec![e];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_ok());
                // Assert that the entry contains the attr "uuid" now.
                let ue = cand.first().unwrap();
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

        let mut create = vec![e.clone()];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_err());
            }
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

        let mut create = vec![e.clone()];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_err());
            }
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

        let mut create = vec![e.clone()];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_ok());
                let ue = cand.first().unwrap();
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

        let mut create = vec![e.clone()];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_err());
            }
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

        let mut create = vec![e.clone()];
        let preload = vec![e];

        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |au: &mut AuditScope,
             qs: &QueryServerWriteTransaction,
             cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
             ce: &CreateEvent| {
                let r = Base::pre_create(au, qs, cand, ce);
                assert!(r.is_err());
            }
        );
    }

    // check create where uuid is a well-known
    // WARNING: This actually requires me to implement backend migrations and
    // creation of default objects in the DB on new() if they don't exist, and
    // to potentially support migrations of said objects.
}
