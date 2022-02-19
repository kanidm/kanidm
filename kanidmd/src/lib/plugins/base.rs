use crate::plugins::Plugin;
use hashbrown::HashSet;
use std::collections::BTreeSet;
use std::iter::once;

use crate::event::{CreateEvent, ModifyEvent};
use crate::modify::Modify;
use crate::prelude::*;
use kanidm_proto::v1::{ConsistencyError, PluginError};

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

    // TODO: Can this be improved?
    #[allow(clippy::cognitive_complexity)]
    fn pre_create_transform(
        qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // debug!("Entering base pre_create_transform");
        // For each candidate
        for entry in cand.iter_mut() {
            trace!("Base check on entry: {:?}", entry);

            // First, ensure we have the 'object', class in the class set.
            entry.add_ava("class", CLASS_OBJECT.clone());

            trace!("Object should now be in entry: {:?}", entry);

            // If they have a name, but no principal name, derive it.

            // if they don't have uuid, create it.
            match entry.get_ava_set("uuid").map(|s| s.len()) {
                None => {
                    // Generate
                    let ava_uuid = Value::new_uuid(Uuid::new_v4());
                    trace!("Setting temporary UUID {:?} to entry", ava_uuid);
                    entry.set_ava("uuid", once(ava_uuid));
                }
                Some(1) => {
                    // Do nothing
                }
                Some(x) => {
                    // If we get some it MUST be 2 +
                    admin_error!("Entry defines uuid attr, but has multiple ({}) values.", x);
                    return Err(OperationError::Plugin(PluginError::Base(
                        "Uuid has multiple values".to_string(),
                    )));
                }
            };
        }

        // Now, every cand has a UUID - create a cand uuid set from it.
        let mut cand_uuid: BTreeSet<Uuid> = BTreeSet::new();

        // As we insert into the set, if a duplicate is found, return an error
        // that a duplicate exists.
        //
        // Remember, we have to use the ava here, not the get_uuid types because
        // we may not have filled in the uuid field yet.
        for entry in cand.iter() {
            let uuid_ref: Uuid = entry
                .get_ava_single_uuid("uuid")
                .copied()
                .ok_or_else(|| OperationError::InvalidAttribute("uuid".to_string()))?;
            trace!("Entry valid UUID: {:?}", entry);
            if !cand_uuid.insert(uuid_ref) {
                trace!("uuid duplicate found in create set! {:?}", uuid_ref);
                return Err(OperationError::Plugin(PluginError::Base(
                    "Uuid duplicate detected in request".to_string(),
                )));
            }
        }

        //? [Quinn] Now that we have raw UUID constants, can we fix improve this part??
        // Setup UUIDS because lazy_static can't create a type valid for range.
        let uuid_admin = *UUID_ADMIN;
        let uuid_anonymous = UUID_ANONYMOUS;
        let uuid_does_not_exist = UUID_DOES_NOT_EXIST;

        // Check that the system-protected range is not in the cand_uuid, unless we are
        // an internal operation.
        if !ce.ident.is_internal() {
            // TODO: We can't lazy const this as you can't borrow the type down to what
            // range and contains on btreeset need, but can we possibly make these constly
            // part of the struct somehow at init. rather than needing to parse a lot?
            // The internal set is bounded by: UUID_ADMIN -> UUID_ANONYMOUS
            // Sadly we need to allocate these to strings to make references, sigh.
            let overlap: usize = cand_uuid.range(uuid_admin..uuid_anonymous).count();
            if overlap != 0 {
                admin_error!(
                    "uuid from protected system UUID range found in create set! {:?}",
                    overlap
                );
                return Err(OperationError::Plugin(PluginError::Base(
                    "Uuid must not be in protected range".to_string(),
                )));
            }
        }

        if cand_uuid.contains(&uuid_does_not_exist) {
            admin_error!(
                "uuid \"does not exist\" found in create set! {:?}",
                uuid_does_not_exist
            );
            return Err(OperationError::Plugin(PluginError::Base(
                "UUID_DOES_NOT_EXIST may not exist!".to_string(),
            )));
        }

        // Now from each element, generate a filter to search for all of them
        //
        // IMPORTANT: We don't exclude recycled or tombstones here!
        let filt_in = filter_all!(FC::Or(
            cand_uuid
                .into_iter()
                .map(|u| FC::Eq("uuid", PartialValue::new_uuid(u)))
                .collect(),
        ));

        // If any results exist, fail as a duplicate UUID is present.
        // TODO #69: Can we report which UUID exists? Probably yes, we do
        // internal search and report the UUID *OR* we alter internal_exists
        // to return UUID sets. This can be done as an extension to #69 where the
        // internal exists is actually a wrapper around a search for uuid internally
        //
        // But does it add value? How many people will try to custom define/add uuid?
        let r = qs.internal_exists(filt_in);

        match r {
            Ok(b) => {
                if b {
                    admin_error!("A UUID already exists, rejecting.");
                    return Err(OperationError::Plugin(PluginError::Base(
                        "Uuid duplicate found in database".to_string(),
                    )));
                }
            }
            Err(e) => {
                admin_error!("Error occured checking UUID existance. {:?}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    fn pre_modify(
        _qs: &QueryServerWriteTransaction,
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
                request_error!("Modifications to UUID's are NOT ALLOWED");
                return Err(OperationError::SystemProtectedAttribute);
            }
        }
        Ok(())
    }

    fn verify(qs: &QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Search for class = *
        let entries = match qs.internal_search(filter!(f_pres("class"))) {
            Ok(v) => v,
            Err(e) => {
                admin_error!("Internal Search Failure: {:?}", e);
                return vec![Err(ConsistencyError::QueryServerSearchFailure)];
            }
        };

        let mut uuid_seen: HashSet<Uuid> = HashSet::with_capacity(entries.len());

        entries
            .iter()
            // do an exists checks on the uuid
            .map(|e| {
                // To get the entry deserialised, a UUID MUST EXIST, else an expect
                // will be thrown in the deserialise (possibly it will be better
                // handled later). But it means this check only needs to validate
                // uniqueness!
                let uuid = e.get_uuid();

                if uuid_seen.insert(*uuid) {
                    // Insert returns true if the item was unique.
                    Ok(())
                } else {
                    Err(ConsistencyError::UuidNotUnique(uuid.to_string()))
                }
            })
            .filter(|v| v.is_err())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use kanidm_proto::v1::PluginError;

    const JSON_ADMIN_ALLOW_ALL: &'static str = r#"{
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
                "{\"eq\":[\"uuid\",\"00000000-0000-0000-0000-000000000000\"]}"
            ],
            "acp_targetscope": [
                "{\"pres\":\"class\"}"
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
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("testperson"))))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No cand");
                assert!(ue.attribute_pres("uuid"));
            }
        );
    }

    // check unparseable uuid
    #[test]
    fn test_pre_create_uuid_invalid() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["xxxxxx"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::InvalidAttribute("uuid".to_string())),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // check entry where uuid is empty list
    #[test]
    fn test_pre_create_uuid_empty() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let mut e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        );

        let vs = e.get_ava_mut("uuid").unwrap();
        vs.clear();

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid format invalid".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // check create where provided uuid is valid. It should be unchanged.
    #[test]
    fn test_pre_create_uuid_valid() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("testperson"))))
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
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d", "79724141-3603-4060-b6bb-35c72772611e"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid has multiple values".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
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
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = vec![e];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid duplicate found in database".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    #[test]
    fn test_pre_create_double_uuid() {
        // Test adding two entries with the same uuid
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson_a"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson_a"],
                "description": ["testperson"],
                "displayname": ["testperson"],
                "uuid": ["79724141-3603-4060-b6bb-35c72772611d"]
            }
        }"#,
        );

        let create = vec![ea, eb];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid duplicate detected in request".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // All of these *SHOULD* be blocked?
    #[test]
    fn test_modify_uuid_present() {
        // Add another uuid to a type
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
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
            Err(OperationError::SystemProtectedAttribute),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("uuid"),
                Value::from("f15a7219-1d15-44e3-a7b4-bec899c07788")
            )]),
            None,
            |_| {}
        );
    }

    #[test]
    fn test_modify_uuid_removed() {
        // Test attempting to remove a uuid
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
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
            Err(OperationError::SystemProtectedAttribute),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("uuid"),
                PartialValue::new_uuids("f15a7219-1d15-44e3-a7b4-bec899c07788").unwrap()
            )]),
            None,
            |_| {}
        );
    }

    #[test]
    fn test_modify_uuid_purged() {
        // Test attempting to purge uuid
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
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
            Err(OperationError::SystemProtectedAttribute),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Purged(AttrString::from("uuid"))]),
            None,
            |_| {}
        );
    }

    #[test]
    fn test_protected_uuid_range() {
        // Test an external create, it should fail.
        // Testing internal create is not super needed, due to migrations at start
        // up testing this every time we run :P
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);

        let preload = vec![acp];

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "uuid": ["00000000-0000-0000-0000-f0f0f0f0f0f0"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid must not be in protected range".to_string()
            ))),
            preload,
            create,
            Some(JSON_ADMIN_V1),
            |_| {}
        );
    }

    #[test]
    fn test_protected_uuid_range_2() {
        // Test an external create, it should fail.
        // Testing internal create is not super needed, due to migrations at start
        // up testing this every time we run :P
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);

        let preload = vec![acp];

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "uuid": ["00000000-0000-0000-0000-ffff00000088"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "Uuid must not be in protected range".to_string()
            ))),
            preload,
            create,
            Some(JSON_ADMIN_V1),
            |_| {}
        );
    }

    #[test]
    fn test_protected_uuid_does_not_exist() {
        // Test that internal create of "does not exist" will fail.
        let preload = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "uuid": ["00000000-0000-0000-0000-fffffffffffe"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::Base(
                "UUID_DOES_NOT_EXIST may not exist!".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }
}
