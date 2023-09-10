// System protected objects. Items matching specific requirements
// may only have certain modifications performed.

use hashbrown::HashSet;
use kanidm_proto::constants::{ATTR_MAY, ATTR_MUST};
use std::sync::Arc;

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
        let mut m = HashSet::with_capacity(16);
        // Allow modification of some schema class types to allow local extension
        // of schema types.
        //
        m.insert(ATTR_MUST);
        m.insert(ATTR_MAY);
        // Allow modification of some domain info types for local configuration.
        m.insert("domain_ssid");
        m.insert("domain_ldap_basedn");
        m.insert("fernet_private_key_str");
        m.insert("es256_private_key_der");
        m.insert("id_verification_eckey");
        m.insert("badlist_password");
        m.insert("domain_display_name");
        m.insert("authsession_expiry");
        m.insert("privilege_expiry");
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
            if cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::System.into())
                || cand.attribute_equality(Attribute::Class.into(), &EntryClass::DomainInfo.into())
                || cand.attribute_equality(Attribute::Class.into(), &EntryClass::SystemInfo.into())
                || cand
                    .attribute_equality(Attribute::Class.into(), &EntryClass::SystemConfig.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Recycled.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::DynGroup.into())
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
        _pre_cand: &[Arc<EntrySealedCommitted>],
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
                if a == "class"
                    && (v == &EntryClass::System.to_value()
                        || v == &EntryClass::DomainInfo.to_value()
                        || v == &EntryClass::SystemInfo.into()
                        || v == &EntryClass::SystemConfig.to_value()
                        || v == &EntryClass::DynGroup.to_value()
                        || v == &EntryClass::SyncObject.to_value()
                        || v == &EntryClass::Tombstone.to_value()
                        || v == &EntryClass::Recycled.to_value())
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
            if cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Recycled.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::DynGroup.into())
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
            c.attribute_equality(Attribute::Class.as_ref(), &EntryClass::System.into())
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
                Modify::Present(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => Some(a),
                Modify::Assert(_, _) => None,
            };
            if let Some(a) = a {
                match ALLOWED_ATTRS.get(a.as_str()) {
                    Some(_) => Ok(()),
                    None => Err(OperationError::SystemProtectedObject),
                }
            } else {
                // Was not a mod needing checking
                Ok(())
            }
        })
    }

    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        if me.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        me.modset
            .values()
            .flat_map(|ml| ml.iter())
            .try_fold((), |(), m| match m {
                Modify::Present(a, v) => {
                    if a == "class"
                        && (v == &EntryClass::System.to_value()
                            || v == &EntryClass::DomainInfo.to_value()
                            || v == &(EntryClass::SystemInfo.to_value())
                            || v == &EntryClass::SystemConfig.to_value()
                            || v == &EntryClass::DynGroup.to_value()
                            || v == &EntryClass::SyncObject.to_value()
                            || v == &EntryClass::Tombstone.to_value()
                            || v == &EntryClass::Recycled.to_value())
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
            if cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Recycled.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::DynGroup.into())
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
            c.attribute_equality(Attribute::Class.as_ref(), &EntryClass::System.into())
        });

        trace!("class: system -> {}", system_pres);
        // No system types being altered, return.
        if !system_pres {
            return Ok(());
        }

        // Something altered is system, check if it's allowed.
        me.modset
            .values()
            .flat_map(|ml| ml.iter())
            .try_fold((), |(), m| {
                // Already hit an error, move on.
                let a = match m {
                    Modify::Present(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => Some(a),
                    Modify::Assert(_, _) => None,
                };
                if let Some(a) = a {
                    match ALLOWED_ATTRS.get(a.as_str()) {
                        Some(_) => Ok(()),
                        None => Err(OperationError::SystemProtectedObject),
                    }
                } else {
                    // Was not a mod needing checking
                    Ok(())
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
            if cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::System.into())
                || cand.attribute_equality(Attribute::Class.into(), &EntryClass::DomainInfo.into())
                || cand.attribute_equality(Attribute::Class.into(), &EntryClass::SystemInfo.into())
                || cand
                    .attribute_equality(Attribute::Class.into(), &EntryClass::SystemConfig.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::Recycled.into())
                || cand.attribute_equality(Attribute::Class.as_ref(), &EntryClass::DynGroup.into())
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
            (Attribute::Class.as_ref(), EntryClass::Account.to_value()),
            (
                Attribute::Class.as_ref(),
                EntryClass::ServiceAccount.to_value()
            ),
            (Attribute::Class.as_ref(), EntryClass::MemberOf.to_value()),
            (Attribute::Name.as_ref(), Value::new_iname("test_account_1")),
            (
                Attribute::DisplayName.as_ref(),
                Value::new_utf8s("test_account_1")
            ),
            (Attribute::Uuid.as_ref(), Value::Uuid(UUID_TEST_ACCOUNT)),
            (Attribute::MemberOf.as_ref(), Value::Refer(UUID_TEST_GROUP))
        );
        pub static ref TEST_GROUP: EntryInitNew = entry_init!(
            (Attribute::Class.as_ref(), EntryClass::Group.to_value()),
            (Attribute::Name.as_ref(), Value::new_iname("test_group_a")),
            (Attribute::Uuid.as_ref(), Value::Uuid(UUID_TEST_GROUP)),
            (Attribute::Member.as_ref(), Value::Refer(UUID_TEST_ACCOUNT))
        );
        pub static ref ALLOW_ALL: EntryInitNew = entry_init!(
            (Attribute::Class.as_ref(), EntryClass::Object.to_value()),
            (
                Attribute::Class.as_ref(),
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class.as_ref(),
                EntryClass::AccessControlModify.to_value()
            ),
            (
                Attribute::Class.as_ref(),
                EntryClass::AccessControlCreate.to_value()
            ),
            (
                Attribute::Class.as_ref(),
                EntryClass::AccessControlDelete.to_value()
            ),
            (
                Attribute::Class.as_ref(),
                EntryClass::AccessControlSearch.to_value()
            ),
            (
                Attribute::Name.as_ref(),
                Value::new_iname("idm_admins_acp_allow_all_test")
            ),
            (Attribute::Uuid.as_ref(), Value::Uuid(UUID_TEST_ACP)),
            (
                Attribute::AcpReceiverGroup.as_ref(),
                Value::Refer(UUID_TEST_GROUP)
            ),
            (
                "acp_targetscope",
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            (
                Attribute::AcpSearchAttr.as_ref(),
                Value::new_iutf8(Attribute::Name.as_ref())
            ),
            (
                Attribute::AcpSearchAttr.as_ref(),
                Attribute::Class.to_value()
            ),
            (Attribute::AcpSearchAttr.as_ref(), Value::new_iutf8("uuid")),
            (
                Attribute::AcpSearchAttr.as_ref(),
                Value::new_iutf8("classname")
            ),
            (
                Attribute::AcpSearchAttr.as_ref(),
                Value::new_iutf8(Attribute::AttributeName.as_ref())
            ),
            (
                Attribute::AcpModifyClass.as_ref(),
                Value::new_iutf8("system")
            ),
            (
                Attribute::AcpModifyClass.as_ref(),
                Value::new_iutf8("domain_info")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Attribute::Class.to_value()
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("displayname")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("may")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("must")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("domain_name")
            ),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("domain_display_name")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                Attribute::AcpModifyRemovedAttr.as_ref(),
                Value::new_iutf8("domain_ssid")
            ),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("es256_private_key_der")
            ),
            (
                "acp_modify_removedattr",
                Attribute::PrivateCookieKey.to_value()
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Attribute::Class.to_value()
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("displayname")
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("may")
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("must")
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("domain_name")
            ),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("domain_display_name")
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                Attribute::AcpModifyPresentAttr.as_ref(),
                Value::new_iutf8("domain_ssid")
            ),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("es256_private_key_der")
            ),
            (
                "acp_modify_presentattr",
                Attribute::PrivateCookieKey.to_value()
            ),
            (
                Attribute::AcpCreateClass.as_ref(),
                EntryClass::Object.to_value()
            ),
            (
                Attribute::AcpCreateClass.as_ref(),
                EntryClass::Person.to_value()
            ),
            (
                Attribute::AcpCreateClass.as_ref(),
                EntryClass::System.to_value()
            ),
            (
                Attribute::AcpCreateClass.as_ref(),
                EntryClass::DomainInfo.to_value()
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Attribute::Name.to_value()
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                EntryClass::Class.to_value(),
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Attribute::Description.to_value(),
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Attribute::DisplayName.to_value(),
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Attribute::DomainName.to_value(),
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Value::new_iutf8("domain_display_name")
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Value::new_iutf8("domain_ssid")
            ),
            (Attribute::AcpCreateAttr.as_ref(), Value::new_iutf8("uuid")),
            (
                "acp_create_attr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Value::new_iutf8("es256_private_key_der")
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Attribute::PrivateCookieKey.to_value()
            ),
            (
                Attribute::AcpCreateAttr.as_ref(),
                Value::new_iutf8("version")
            )
        );
        pub static ref PRELOAD: Vec<EntryInitNew> =
            vec![TEST_ACCOUNT.clone(), TEST_GROUP.clone(), ALLOW_ALL.clone()];
        pub static ref E_TEST_ACCOUNT: Arc<EntrySealedCommitted> =
            Arc::new(TEST_ACCOUNT.clone().into_sealed_committed());
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
        preload.push(e);

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
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
        // TODO: replace this with a `SchemaClass` object
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
        preload.push(e);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::ClassName, EntryClass::TestClass.into())),
            modlist!([
                m_pres("may", &Value::new_iutf8(Attribute::Name.as_ref())),
                m_pres("must", &Value::new_iutf8(Attribute::Name.as_ref())),
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
        preload.push(e);

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
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
                "private_cookie_key" : ["MTIz"],
                "version": ["1"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
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
                "private_cookie_key" : ["MTIz"],
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
                "private_cookie_key" : ["MTIz"],
                "version": ["1"]
            }
        }"#,
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("domain_example.net.au")
            )),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }
}
