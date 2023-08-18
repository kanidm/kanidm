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
            if cand.attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::System.into())
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::DomainInfo.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::SystemInfo.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::SystemConfig.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::Tombstone.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::Recycled.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::DynGroup.into(),
                )
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
                    && (v == &ValueClass::System.to_value()
                        || v == &ValueClass::DomainInfo.to_value()
                        || v == &ValueClass::SystemInfo.into()
                        || v == &ValueClass::SystemConfig.to_value()
                        || v == &ValueClass::DynGroup.to_value()
                        || v == &ValueClass::SyncObject.to_value()
                        || v == &ValueClass::Tombstone.to_value()
                        || v == &ValueClass::Recycled.to_value())
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
            if cand.attribute_equality(
                ValueAttribute::Class.as_str(),
                &ValueClass::Tombstone.into(),
            ) || cand
                .attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::Recycled.into())
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::DynGroup.into(),
                )
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
            c.attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::System.into())
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
                        && (v == &ValueClass::System.to_value()
                            || v == &ValueClass::DomainInfo.to_value()
                            || v == &(ValueClass::SystemInfo.to_value())
                            || v == &ValueClass::SystemConfig.to_value()
                            || v == &ValueClass::DynGroup.to_value()
                            || v == &ValueClass::SyncObject.to_value()
                            || v == &ValueClass::Tombstone.to_value()
                            || v == &ValueClass::Recycled.to_value())
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
            if cand.attribute_equality(
                ValueAttribute::Class.as_str(),
                &ValueClass::Tombstone.into(),
            ) || cand
                .attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::Recycled.into())
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::DynGroup.into(),
                )
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
            c.attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::System.into())
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
            if cand.attribute_equality(ValueAttribute::Class.as_str(), &ValueClass::System.into())
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::DomainInfo.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::SystemInfo.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.into(),
                    &ValueClass::SystemConfig.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::Tombstone.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::Recycled.into(),
                )
                || cand.attribute_equality(
                    ValueAttribute::Class.as_str(),
                    &ValueClass::DynGroup.into(),
                )
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
            (
                ValueAttribute::Class.as_str(),
                ValueClass::Account.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::ServiceAccount.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::MemberOf.to_value()
            ),
            (
                ValueAttribute::Name.as_str(),
                Value::new_iname("test_account_1")
            ),
            (
                ValueAttribute::DisplayName.as_str(),
                Value::new_utf8s("test_account_1")
            ),
            (
                ValueAttribute::Uuid.as_str(),
                Value::Uuid(UUID_TEST_ACCOUNT)
            ),
            (
                ValueAttribute::MemberOf.as_str(),
                Value::Refer(UUID_TEST_GROUP)
            )
        );
        pub static ref TEST_GROUP: EntryInitNew = entry_init!(
            (ValueAttribute::Class.as_str(), ValueClass::Group.to_value()),
            (
                ValueAttribute::Name.as_str(),
                Value::new_iname("test_group_a")
            ),
            (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_TEST_GROUP)),
            (
                ValueAttribute::Member.as_str(),
                Value::Refer(UUID_TEST_ACCOUNT)
            )
        );
        pub static ref ALLOW_ALL: EntryInitNew = entry_init!(
            (
                ValueAttribute::Class.as_str(),
                ValueClass::Object.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::AccessControlProfile.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::AccessControlModify.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::AccessControlCreate.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::AccessControlDelete.to_value()
            ),
            (
                ValueAttribute::Class.as_str(),
                ValueClass::AccessControlSearch.to_value()
            ),
            (
                ValueAttribute::Name.as_str(),
                Value::new_iname("idm_admins_acp_allow_all_test")
            ),
            (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_TEST_ACP)),
            (
                ValueAttribute::AcpReceiverGroup.as_str(),
                Value::Refer(UUID_TEST_GROUP)
            ),
            (
                "acp_targetscope",
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            (
                ValueAttribute::AcpSearchAttr.as_str(),
                Value::new_iutf8("name")
            ),
            (
                ValueAttribute::AcpSearchAttr.as_str(),
                ValueAttribute::Class.to_value()
            ),
            (
                ValueAttribute::AcpSearchAttr.as_str(),
                Value::new_iutf8("uuid")
            ),
            (
                ValueAttribute::AcpSearchAttr.as_str(),
                Value::new_iutf8("classname")
            ),
            (
                ValueAttribute::AcpSearchAttr.as_str(),
                Value::new_iutf8("attributename")
            ),
            (
                ValueAttribute::AcpModifyClass.as_str(),
                Value::new_iutf8("system")
            ),
            (
                ValueAttribute::AcpModifyClass.as_str(),
                Value::new_iutf8("domain_info")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                ValueAttribute::Class.to_value()
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                Value::new_iutf8("displayname")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                Value::new_iutf8("may")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                Value::new_iutf8("must")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                Value::new_iutf8("domain_name")
            ),
            (
                "acp_modify_removedattr",
                Value::new_iutf8("domain_display_name")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                ValueAttribute::AcpModifyRemovedAttr.as_str(),
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
                ValueAttribute::PrivateCookieKey.to_value()
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                ValueAttribute::Class.to_value()
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                Value::new_iutf8("displayname")
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                Value::new_iutf8("may")
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                Value::new_iutf8("must")
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                Value::new_iutf8("domain_name")
            ),
            (
                "acp_modify_presentattr",
                Value::new_iutf8("domain_display_name")
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                ValueAttribute::AcpModifyPresentAttr.as_str(),
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
                ValueAttribute::PrivateCookieKey.to_value()
            ),
            (
                ValueAttribute::AcpCreateClass.as_str(),
                ValueClass::Object.to_value()
            ),
            (
                ValueAttribute::AcpCreateClass.as_str(),
                ValueClass::Person.to_value()
            ),
            (
                ValueAttribute::AcpCreateClass.as_str(),
                ValueClass::System.to_value()
            ),
            (
                ValueAttribute::AcpCreateClass.as_str(),
                ValueClass::DomainInfo.to_value()
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueAttribute::Name.to_value()
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueClass::Class.to_value(),
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueAttribute::Description.to_value(),
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueAttribute::DisplayName.to_value(),
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueAttribute::DomainName.to_value(),
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                Value::new_iutf8("domain_display_name")
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                Value::new_iutf8("domain_uuid")
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                Value::new_iutf8("domain_ssid")
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                Value::new_iutf8("uuid")
            ),
            (
                "acp_create_attr",
                Value::new_iutf8("fernet_private_key_str")
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                Value::new_iutf8("es256_private_key_der")
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
                ValueAttribute::PrivateCookieKey.to_value()
            ),
            (
                ValueAttribute::AcpCreateAttr.as_str(),
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
            filter!(f_eq(
                ValueAttribute::Name,
                PartialValue::new_iname("testperson")
            )),
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
            filter!(f_eq(
                ValueAttribute::ClassName,
                ValueClass::TestClass.into()
            )),
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
        preload.push(e);

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(
                ValueAttribute::Name,
                PartialValue::new_iname("testperson")
            )),
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
                ValueAttribute::Name,
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
                ValueAttribute::Name,
                PartialValue::new_iname("domain_example.net.au")
            )),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }
}
