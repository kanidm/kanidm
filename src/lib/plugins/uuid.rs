use plugins::Plugin;
use uuid::Uuid;

use audit::AuditScope;
use be::Backend;
use entry::Entry;
use error::OperationError;
use event::CreateEvent;
use filter::Filter;
use schema::Schema;

// TO FINISH
/*
Add UUID type
Add base system class to all incoming objects (so we can add our values)
Add normalisation step
Add filter normaliser to search.
*/

pub struct UUID {}

impl Plugin for UUID {
    fn id() -> &'static str {
        "UUID"
    }
    // Need to be given the backend(for testing ease)
    // audit
    // the mut set of entries to create
    // the create event itself (immutable, for checking originals)
    //     contains who is creating them
    // the schema of the running instance

    fn pre_create(
        be: &mut Backend,
        au: &mut AuditScope,
        cand: &mut Vec<Entry>,
        ce: &CreateEvent,
        schema: &Schema,
    ) -> Result<(), OperationError> {
        // For each candidate
        for entry in cand.iter_mut() {
            let name_uuid = String::from("uuid");

            audit_log!(au, "UUID check on entry: {:?}", entry);

            // if they don't have uuid, create it.
            // TODO: get_ava should have a str version for effeciency?
            let mut c_uuid = match entry.get_ava(&name_uuid) {
                Some(u) => {
                    // Actually check we have a value, could be empty array ...
                    if u.len() > 1 {
                        audit_log!(au, "Entry defines uuid attr, but multiple values.");
                        return Err(OperationError::Plugin);
                    };

                    let v = match u.first() {
                        Some(v) => v,
                        None => {
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
                                "Entry contains invalid UUID content, rejecting out of principle."
                            );
                            return Err(OperationError::Plugin);
                        }
                    }
                }
                None => Uuid::new_v4(),
            };

            // Make it a string, so we can filter.
            let str_uuid = format!("{}", c_uuid);

            let mut au_be = AuditScope::new("be_exist");

            // We need to clone to the filter because it owns the content
            let filt = Filter::Eq(name_uuid.clone(), str_uuid.clone());

            let r = be.exists(&mut au_be, &filt);

            au.append_scope(au_be);
            // end the scope for the be operation.

            match r {
                Ok(b) => {
                    if b == true {
                        audit_log!(au, "UUID already exists, rejecting.");
                        return Err(OperationError::Plugin);
                    }
                }
                Err(e) => {
                    audit_log!(au, "Backend error occured checking UUID existance.");
                    return Err(OperationError::Plugin);
                }
            }

            let str_uuid = format!("{}", c_uuid);
            audit_log!(au, "Set UUID {} to entry", str_uuid);
            let ava_uuid: Vec<String> = vec![str_uuid];

            entry.set_avas(name_uuid, ava_uuid);
        }
        // done!

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plugin;
    use super::UUID;

    use audit::AuditScope;
    use be::Backend;
    use entry::Entry;
    use event::CreateEvent;
    use schema::Schema;

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
                let mut be = Backend::new(&mut au, "");

                // TODO: Preload entries here!
                if !$preload_entries.is_empty() {
                    assert!(be.create(&mut au, &$preload_entries).is_ok());
                };

                let ce = CreateEvent::from_vec($create_entries.clone());
                let mut schema = Schema::new();
                schema.bootstrap_core();

                let mut au_test = AuditScope::new("pre_create_test");
                audit_segment!(au_test, || $test_fn(
                    &mut be,
                    &mut au_test,
                    &mut $create_entries,
                    &ce,
                    &schema,
                ));

                au.append_scope(au_test);
            });
            // Dump the raw audit log.
            println!("{}", au);
        }};
    }

    // Check empty create
    #[test]
    fn test_pre_create_empty() {
        let preload: Vec<Entry> = Vec::new();
        let mut create: Vec<Entry> = Vec::new();
        run_pre_create_test!(
            preload,
            create,
            false,
            false,
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);

                assert!(r.is_ok());
                // Nothing should have changed.
                assert!(cand.len() == 0);
            }
        );
    }

    // check create where no uuid
    #[test]
    fn test_pre_create_no_uuid() {
        let preload: Vec<Entry> = Vec::new();

        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
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
        let preload: Vec<Entry> = Vec::new();

        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
                assert!(r.is_err());
            }
        );
    }

    // check entry where uuid is empty list
    #[test]
    fn test_pre_create_uuid_empty() {
        let preload: Vec<Entry> = Vec::new();

        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
                assert!(r.is_err());
            }
        );
    }

    // check create where provided uuid is valid. It should be unchanged.
    #[test]
    fn test_pre_create_uuid_valid() {
        let preload: Vec<Entry> = Vec::new();

        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
                assert!(r.is_ok());
                let ue = cand.first().unwrap();
                assert!(ue.attribute_equality("uuid", "79724141-3603-4060-b6bb-35c72772611d"));
            }
        );
    }

    #[test]
    fn test_pre_create_uuid_valid_multi() {
        let preload: Vec<Entry> = Vec::new();

        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
                assert!(r.is_err());
            }
        );
    }

    // check create where uuid already exists.
    #[test]
    fn test_pre_create_uuid_exist() {
        let e: Entry = serde_json::from_str(
            r#"{
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
            |be: &mut Backend,
             au: &mut AuditScope,
             cand: &mut Vec<Entry>,
             ce: &CreateEvent,
             schema: &Schema| {
                let r = UUID::pre_create(be, au, cand, ce, schema);
                assert!(r.is_err());
            }
        );
    }

    // check create where uuid is a well-known
    // WARNING: This actually requires me to implement backend migrations and
    // creation of default objects in the DB on new() if they don't exist, and
    // to potentially support migrations of said objects.
}
