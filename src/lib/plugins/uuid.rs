use plugins::Plugin;
use uuid::Uuid;

use audit::AuditScope;
use be::Backend;
use entry::Entry;
use event::CreateEvent;
use schema::Schema;
use error::OperationError;

struct UUID {}

impl Plugin for UUID {
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

            // if they don't have uuid, create it.
            // TODO: get_ava should have a str version for effeciency?
            let mut c_uuid = match entry.get_ava(&name_uuid) {
                Some(u) => {
                    // Actually check we have a value, could be empty array ...
                    let v = u.first().unwrap();
                    // This could actually fail, so we probably need to handle
                    // this better ....
                    match Uuid::parse_str(v.as_str()) {
                        Ok(up) => up,
                        Err(_) => {
                            return Err(
                                OperationError::Plugin
                            )
                        }
                    }
                }
                None => Uuid::new_v4()
            };

            // Make it a string, so we can filter.
            println!("uuid: {}", c_uuid);


            // check that the uuid is unique in the be (even if one is provided
            //  we especially need to check that)

            // if not unique, generate another, and try again.

            // If it's okay, now put it into the entry.
            // we may need to inject the base OC required for all objects in our
            // server to support this?
            let str_uuid = format!("{}", c_uuid);
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
            // Dump the raw audit. Perhaps we should serialise this pretty?
            println!("{:?}", au);
        }};
    }

    // Check empty create
    #[test]
    fn test_pre_create_empty() {
        // Need a macro to create all the bits here ...
        // Macro needs preload entries, the create entries
        // schema, identity for create event (later)
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
        // Need a macro to create all the bits here ...
        // Macro needs preload entries, the create entries
        // schema, identity for create event (later)
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
    // check entry where uuid is empty list

    // check create where provided uuid is valid. It should be unchanged.

    // check create where uuid already exists.

    // check create where uuid is a well-known
    // WARNING: This actually requires me to implement backend migrations and
    // creation of default objects in the DB on new() if they don't exist, and
    // to potentially support migrations of said objects.
}
