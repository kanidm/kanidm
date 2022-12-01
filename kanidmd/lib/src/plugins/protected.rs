// System protected objects. Items matching specific requirements
// may only have certain modifications performed.

use hashbrown::HashSet;

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::Modify;
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct Protected {}

// Here is the declaration of all the attrs that can be altered by
// a call on a system object. We trust they are allowed because
// schema will have checked this, and we don't allow class changes!

lazy_static! {
    static ref ALLOWED_ATTRS: HashSet<&'static str> = {
        let mut m = HashSet::with_capacity(8);
        // Allow modification of some schema class types to allow local extension
        // of schema types.
        //
        m.insert("must");
        m.insert("may");
        // Allow modification of some domain info types for local configuration.
        m.insert("domain_ssid");
        m.insert("fernet_private_key_str");
        m.insert("es256_private_key_der");
        m.insert("badlist_password");
        m.insert("domain_display_name");
        m
    };
}

impl Plugin for Protected {
    fn id() -> &'static str {
        "plugin_protected"
    }

    #[instrument(level = "debug", name = "protected_pre_create", skip(_qs, cand, ce))]
    fn pre_create(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        cand: &[Entry<EntrySealed, EntryNew>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        if ce.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        cand.iter().try_fold((), |(), cand| {
            if cand.attribute_equality("class", &PVCLASS_SYSTEM)
                || cand.attribute_equality("class", &PVCLASS_DOMAIN_INFO)
                || cand.attribute_equality("class", &PVCLASS_SYSTEM_INFO)
                || cand.attribute_equality("class", &PVCLASS_SYSTEM_CONFIG)
                || cand.attribute_equality("class", &PVCLASS_TOMBSTONE)
                || cand.attribute_equality("class", &PVCLASS_RECYCLED)
                || cand.attribute_equality("class", &PVCLASS_DYNGROUP)
            {
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })
    }

    #[instrument(level = "debug", name = "protected_pre_modify", skip(_qs, cand, me))]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        if me.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }
        // Prevent adding class: system, domain_info, tombstone, or recycled.
        me.modlist.iter().try_fold((), |(), m| match m {
            Modify::Present(a, v) => {
                // TODO: Can we avoid this clone?
                if a == "class"
                    && (v == &(*CLASS_SYSTEM)
                        || v == &(*CLASS_DOMAIN_INFO)
                        || v == &(*CLASS_SYSTEM_INFO)
                        || v == &(*CLASS_SYSTEM_CONFIG)
                        || v == &(*CLASS_DYNGROUP)
                        || v == &(*CLASS_TOMBSTONE)
                        || v == &(*CLASS_RECYCLED))
                {
                    Err(OperationError::SystemProtectedObject)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        })?;

        // HARD block mods on tombstone or recycle. We soft block on the rest as they may
        // have some allowed attrs.
        cand.iter().try_fold((), |(), cand| {
            if cand.attribute_equality("class", &PVCLASS_TOMBSTONE)
                || cand.attribute_equality("class", &PVCLASS_RECYCLED)
                || cand.attribute_equality("class", &PVCLASS_DYNGROUP)
            {
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })?;

        // if class: system, check the mods are "allowed"
        let system_pres = cand.iter().any(|c| {
            // We don't need to check for domain info here because domain_info has a class
            // system also. We just need to block it from being created.
            c.attribute_equality("class", &PVCLASS_SYSTEM)
        });

        trace!("class: system -> {}", system_pres);
        // No system types being altered, return.
        if !system_pres {
            return Ok(());
        }

        // Something altered is system, check if it's allowed.
        me.modlist.iter().try_fold((), |(), m| {
            // Already hit an error, move on.
            let a = match m {
                Modify::Present(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => a,
            };
            match ALLOWED_ATTRS.get(a.as_str()) {
                Some(_) => Ok(()),
                None => Err(OperationError::SystemProtectedObject),
            }
        })
    }

    #[instrument(level = "debug", name = "protected_pre_delete", skip(_qs, cand, de))]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntrySealed
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        if de.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        cand.iter().try_fold((), |(), cand| {
            if cand.attribute_equality("class", &PVCLASS_SYSTEM)
                || cand.attribute_equality("class", &PVCLASS_DOMAIN_INFO)
                || cand.attribute_equality("class", &PVCLASS_SYSTEM_INFO)
                || cand.attribute_equality("class", &PVCLASS_SYSTEM_CONFIG)
                || cand.attribute_equality("class", &PVCLASS_TOMBSTONE)
                || cand.attribute_equality("class", &PVCLASS_RECYCLED)
                || cand.attribute_equality("class", &PVCLASS_DYNGROUP)
            {
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
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
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT)),
            ("memberof", Value::new_refer(UUID_TEST_GROUP))
        );
        pub static ref TEST_GROUP: EntryInitNew = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("test_group_a")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP)),
            ("member", Value::new_refer(UUID_TEST_ACCOUNT))
        );
        pub static ref ALLOW_ALL: EntryInitNew = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("access_control_profile")),
            ("class", Value::new_class("access_control_modify")),
            ("class", Value::new_class("access_control_create")),
            ("class", Value::new_class("access_control_delete")),
            ("class", Value::new_class("access_control_search")),
            ("name", Value::new_iname("idm_admins_acp_allow_all_test")),
            ("uuid", Value::new_uuid(UUID_TEST_ACP)),
            ("acp_receiver_group", Value::Refer(UUID_TEST_GROUP)),
            (
                "acp_targetscope",
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            ("acp_search_attr", Value::new_iutf8("name")),
            ("acp_search_attr", Value::new_iutf8("class")),
            ("acp_search_attr", Value::new_iutf8("uuid")),
            ("acp_search_attr", Value::new_iutf8("classname")),
            ("acp_search_attr", Value::new_iutf8("attributename")),
            ("acp_modify_class", Value::new_iutf8("system")),
            ("acp_modify_class", Value::new_iutf8("domain_info")),
            ("acp_modify_removedattr", Value::new_iutf8("class")),
            ("acp_modify_removedattr", Value::new_iutf8("displayname")),
            ("acp_modify_removedattr", Value::new_iutf8("may")),
            ("acp_modify_removedattr", Value::new_iutf8("must")),
            ("acp_modify_removedattr", Value::new_iutf8("domain_name")),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("domain_display_name")
            ),
            ("acp_modify_removedattr", Value::new_iutf8("domain_uuid")),
            ("acp_modify_removedattr", Value::new_iutf8("domain_ssid")),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("es256_private_key_der")
            ),
            ("acp_modify_presentattr", Value::new_iutf8("class")),
            ("acp_modify_presentattr", Value::new_iutf8("displayname")),
            ("acp_modify_presentattr", Value::new_iutf8("may")),
            ("acp_modify_presentattr", Value::new_iutf8("must")),
            ("acp_modify_presentattr", Value::new_iutf8("domain_name")),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("domain_display_name")
            ),
            ("acp_modify_presentattr", Value::new_iutf8("domain_uuid")),
            ("acp_modify_presentattr", Value::new_iutf8("domain_ssid")),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("es256_private_key_der")
            ),
            ("acp_create_class", Value::new_iutf8("object")),
            ("acp_create_class", Value::new_iutf8("person")),
            ("acp_create_class", Value::new_iutf8("system")),
            ("acp_create_class", Value::new_iutf8("domain_info")),
            ("acp_create_attr", Value::new_iutf8("name")),
            ("acp_create_attr", Value::new_iutf8("class")),
            ("acp_create_attr", Value::new_iutf8("description")),
            ("acp_create_attr", Value::new_iutf8("displayname")),
            ("acp_create_attr", Value::new_iutf8("domain_name")),
            ("acp_create_attr", Value::new_iutf8("domain_display_name")),
            ("acp_create_attr", Value::new_iutf8("domain_uuid")),
            ("acp_create_attr", Value::new_iutf8("domain_ssid")),
            ("acp_create_attr", Value::new_iutf8("uuid")),
            (
                "acp_create_attr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            ("acp_create_attr", Value::new_iutf8("es256_private_key_der")),
            ("acp_create_attr", Value::new_iutf8("version"))
        );
        pub static ref PRELOAD: Vec<EntryInitNew> =
            vec![TEST_ACCOUNT.clone(), TEST_GROUP.clone(), ALLOW_ALL.clone()];
        pub static ref E_TEST_ACCOUNT: Arc<EntrySealedCommitted> =
            Arc::new(unsafe { TEST_ACCOUNT.clone().into_sealed_committed() });
    }

    #[test]
    fn test_pre_create_deny() {
        // Test creating with class: system is rejected.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = PRELOAD.clone();

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_pre_modify_system_deny() {
        // Test modify of class to a system is denied
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e.clone());

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge("displayname"),
                m_pres("displayname", &Value::new_utf8s("system test")),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_pre_modify_class_add_deny() {
        // Show that adding a system class is denied
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["object", "classtype"],
                "classname": ["testclass"],
                "uuid": ["cfcae205-31c3-484b-8ced-667d1709c5e3"],
                "description": ["Test Class"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e.clone());

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("classname", PartialValue::new_class("testclass"))),
            modlist!([
                m_pres("may", &Value::new_iutf8("name")),
                m_pres("must", &Value::new_iutf8("name")),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_pre_delete_deny() {
        // Test deleting with class: system is rejected.
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e.clone());

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_modify_domain() {
        // Can edit *my* domain_ssid and domain_name
        // Show that adding a system class is denied
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generation in test_modify_domain"],
                "domain_name": ["example.net.au"],
                "domain_display_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"],
                "fernet_private_key_str": ["ABCD"],
                "es256_private_key_der" : ["MTIz"],
                "version": ["1"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e.clone());

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                "name",
                PartialValue::new_iname("domain_example.net.au")
            )),
            modlist!([
                m_purge("domain_ssid"),
                m_pres("domain_ssid", &Value::new_utf8s("NewExampleWifi")),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_ext_create_domain() {
        // can not add a domain_info type - note the lack of class: system

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generation in test_ext_create_domain"],
                "domain_name": ["example.net.au"],
                "domain_display_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"],
                "fernet_private_key_str": ["ABCD"],
                "es256_private_key_der" : ["MTIz"],
                "version": ["1"]
            }
        }"#,
        );
        let create = vec![e];
        let preload = PRELOAD.clone();

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_delete_domain() {
        // On the real thing we have a class: system, but to prove the point ...
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generation in test_delete_domain"],
                "domain_name": ["example.net.au"],
                "domain_display_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"],
                "fernet_private_key_str": ["ABCD"],
                "es256_private_key_der" : ["MTIz"],
                "version": ["1"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e.clone());

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(
                "name",
                PartialValue::new_iname("domain_example.net.au")
            )),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }
}
