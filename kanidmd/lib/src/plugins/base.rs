use std::collections::BTreeSet;
use std::iter::once;

use hashbrown::HashSet;
use kanidm_proto::v1::{ConsistencyError, PluginError};

use crate::event::{CreateEvent, ModifyEvent};
use crate::modify::Modify;
use crate::plugins::Plugin;
use crate::prelude::*;

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

    #[instrument(
        level = "debug",
        name = "base_pre_create_transform",
        skip(qs, cand, ce)
    )]
    #[allow(clippy::cognitive_complexity)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // debug!("Entering base pre_create_transform");
        // For each candidate
        for entry in cand.iter_mut() {
            // First, ensure we have the 'object', class in the class set.
            entry.add_ava("class", CLASS_OBJECT.clone());

            // if they don't have uuid, create it.
            match entry.get_ava_set("uuid").map(|s| s.len()) {
                None => {
                    // Generate
                    let ava_uuid = Value::Uuid(Uuid::new_v4());
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
                .ok_or_else(|| OperationError::InvalidAttribute("uuid".to_string()))?;
            if !cand_uuid.insert(uuid_ref) {
                trace!("uuid duplicate found in create set! {:?}", uuid_ref);
                return Err(OperationError::Plugin(PluginError::Base(
                    "Uuid duplicate detected in request".to_string(),
                )));
            }
        }

        // Check that the system-protected range is not in the cand_uuid, unless we are
        // an internal operation.
        if !ce.ident.is_internal() {
            // TODO: We can't lazy const this as you can't borrow the type down to what
            // range and contains on btreeset need, but can we possibly make these constly
            // part of the struct somehow at init. rather than needing to parse a lot?
            // The internal set is bounded by: UUID_ADMIN -> UUID_ANONYMOUS
            // Sadly we need to allocate these to strings to make references, sigh.
            let overlap: usize = cand_uuid.range(UUID_ADMIN..UUID_ANONYMOUS).count();
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

        if cand_uuid.contains(&UUID_DOES_NOT_EXIST) {
            admin_error!(
                "uuid \"does not exist\" found in create set! {:?}",
                UUID_DOES_NOT_EXIST
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
                .map(|u| FC::Eq("uuid", PartialValue::Uuid(u)))
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

    #[instrument(level = "debug", name = "base_pre_modify", skip(_qs, _cand, me))]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        me.modlist.iter().try_for_each(|modify| {
            let attr = match &modify {
                Modify::Present(a, _) => Some(a),
                Modify::Removed(a, _) => Some(a),
                Modify::Purged(a) => Some(a),
                Modify::Assert(_, _) => None,
            };
            if attr.map(|s| s.as_str()) == Some("uuid") {
                debug!(?modify, "Modify in violation");
                request_error!("Modifications to UUID's are NOT ALLOWED");
                Err(OperationError::SystemProtectedAttribute)
            } else {
                Ok(())
            }
        })
    }

    #[instrument(level = "debug", name = "base_pre_modify", skip(_qs, _cand, me))]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        me.modset
            .values()
            .flat_map(|ml| ml.iter())
            .try_for_each(|modify| {
                let attr = match &modify {
                    Modify::Present(a, _) => Some(a),
                    Modify::Removed(a, _) => Some(a),
                    Modify::Purged(a) => Some(a),
                    Modify::Assert(_, _) => None,
                };
                if attr.map(|s| s.as_str()) == Some("uuid") {
                    debug!(?modify, "Modify in violation");
                    request_error!("Modifications to UUID's are NOT ALLOWED");
                    Err(OperationError::SystemProtectedAttribute)
                } else {
                    Ok(())
                }
            })
    }

    #[instrument(level = "debug", name = "base_verify", skip(qs))]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
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

                if uuid_seen.insert(uuid) {
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
    use std::sync::Arc;

    const UUID_TEST_ACCOUNT: Uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
    const UUID_TEST_GROUP: Uuid = uuid::uuid!("81ec1640-3637-4a2f-8a52-874fa3c3c92f");
    const UUID_TEST_ACP: Uuid = uuid::uuid!("acae81d6-5ea7-4bd8-8f7f-fcec4c0dd647");

    lazy_static! {
        pub static ref TEST_ACCOUNT: EntryInitNew = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("service_account")),
            ("class", Value::new_class("memberof")),
            ("name", Value::new_iname("test_account_1")),
            ("displayname", Value::new_utf8s("test_account_1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT)),
            ("memberof", Value::Refer(UUID_TEST_GROUP))
        );
        pub static ref TEST_GROUP: EntryInitNew = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("test_group_a")),
            ("uuid", Value::Uuid(UUID_TEST_GROUP)),
            ("member", Value::Refer(UUID_TEST_ACCOUNT))
        );
        pub static ref ALLOW_ALL: EntryInitNew = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("access_control_profile")),
            ("class", Value::new_class("access_control_modify")),
            ("class", Value::new_class("access_control_create")),
            ("class", Value::new_class("access_control_delete")),
            ("class", Value::new_class("access_control_search")),
            ("name", Value::new_iname("idm_admins_acp_allow_all_test")),
            ("uuid", Value::Uuid(UUID_TEST_ACP)),
            ("acp_receiver_group", Value::Refer(UUID_TEST_GROUP)),
            (
                "acp_targetscope",
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            ("acp_search_attr", Value::new_iutf8("name")),
            ("acp_search_attr", Value::new_iutf8("class")),
            ("acp_search_attr", Value::new_iutf8("uuid")),
            ("acp_modify_class", Value::new_iutf8("system")),
            ("acp_modify_removedattr", Value::new_iutf8("class")),
            ("acp_modify_removedattr", Value::new_iutf8("displayname")),
            ("acp_modify_removedattr", Value::new_iutf8("may")),
            ("acp_modify_removedattr", Value::new_iutf8("must")),
            ("acp_modify_presentattr", Value::new_iutf8("class")),
            ("acp_modify_presentattr", Value::new_iutf8("displayname")),
            ("acp_modify_presentattr", Value::new_iutf8("may")),
            ("acp_modify_presentattr", Value::new_iutf8("must")),
            ("acp_create_class", Value::new_iutf8("object")),
            ("acp_create_class", Value::new_iutf8("person")),
            ("acp_create_class", Value::new_iutf8("system")),
            ("acp_create_attr", Value::new_iutf8("name")),
            ("acp_create_attr", Value::new_iutf8("class")),
            ("acp_create_attr", Value::new_iutf8("description")),
            ("acp_create_attr", Value::new_iutf8("displayname")),
            ("acp_create_attr", Value::new_iutf8("uuid"))
        );
        pub static ref PRELOAD: Vec<EntryInitNew> =
            vec![TEST_ACCOUNT.clone(), TEST_GROUP.clone(), ALLOW_ALL.clone()];
        pub static ref E_TEST_ACCOUNT: Arc<EntrySealedCommitted> =
            Arc::new(unsafe { TEST_ACCOUNT.clone().into_sealed_committed() });
    }

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
            |qs: &mut QueryServerWriteTransaction| {
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
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("testperson"))))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No cand");
                assert!(ue.attribute_equality(
                    "uuid",
                    &PartialValue::Uuid(uuid!("79724141-3603-4060-b6bb-35c72772611d"))
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
            |_| {},
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
                PartialValue::Uuid(uuid!("f15a7219-1d15-44e3-a7b4-bec899c07788"))
            )]),
            None,
            |_| {},
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
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_protected_uuid_range() {
        // Test an external create, it should fail.
        // Testing internal create is not super needed, due to migrations at start
        // up testing this every time we run :P
        let preload = PRELOAD.clone();

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
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_protected_uuid_range_2() {
        // Test an external create, it should fail.
        // Testing internal create is not super needed, due to migrations at start
        // up testing this every time we run :P
        let preload = PRELOAD.clone();

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
            Some(E_TEST_ACCOUNT.clone()),
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
