// System protected objects. Items matching specific requirements
// may only have certain modifications performed.
use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::Modify;
use crate::server::QueryServerWriteTransaction;
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;
use std::collections::HashSet;

pub struct Protected {}

// Here is the declaration of all the attrs that can be altered by
// a call on a system object. We trust they are allowed because
// schema will have checked this, and we don't allow class changes!

lazy_static! {
    static ref ALLOWED_ATTRS: HashSet<&'static str> = {
        let mut m = HashSet::with_capacity(8);
        // Allow modification of some schema class types to allow local extension
        // of schema types.
        m.insert("must");
        m.insert("may");
        // Allow modification of some domain info types for local configuration.
        m.insert("domain_ssid");
        m.insert("badlist_password");
        m
    };
    static ref PVCLASS_SYSTEM: PartialValue = PartialValue::new_class("system");
    static ref PVCLASS_TOMBSTONE: PartialValue = PartialValue::new_class("tombstone");
    static ref PVCLASS_RECYCLED: PartialValue = PartialValue::new_class("recycled");
    static ref PVCLASS_DOMAIN_INFO: PartialValue = PartialValue::new_class("domain_info");
    static ref PVCLASS_SYSTEM_INFO: PartialValue = PartialValue::new_class("system_info");
    static ref PVCLASS_SYSTEM_CONFIG: PartialValue = PartialValue::new_class("system_config");
    static ref VCLASS_SYSTEM: Value = Value::new_class("system");
    static ref VCLASS_TOMBSTONE: Value = Value::new_class("tombstone");
    static ref VCLASS_RECYCLED: Value = Value::new_class("recycled");
    static ref VCLASS_DOMAIN_INFO: Value = Value::new_class("domain_info");
    static ref VCLASS_SYSTEM_INFO: Value = Value::new_class("system_info");
    static ref VCLASS_SYSTEM_CONFIG: Value = Value::new_class("system_config");
}

impl Plugin for Protected {
    fn id() -> &'static str {
        "plugin_protected"
    }

    fn pre_create(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        cand: &[Entry<EntrySealed, EntryNew>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        if ce.event.is_internal() {
            ltrace!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }

        cand.iter().fold(Ok(()), |acc, cand| match acc {
            Err(_) => acc,
            Ok(_) => {
                if cand.attribute_value_pres("class", &PVCLASS_SYSTEM)
                    || cand.attribute_value_pres("class", &PVCLASS_DOMAIN_INFO)
                    || cand.attribute_value_pres("class", &PVCLASS_SYSTEM_INFO)
                    || cand.attribute_value_pres("class", &PVCLASS_SYSTEM_CONFIG)
                    || cand.attribute_value_pres("class", &PVCLASS_TOMBSTONE)
                    || cand.attribute_value_pres("class", &PVCLASS_RECYCLED)
                {
                    Err(OperationError::SystemProtectedObject)
                } else {
                    acc
                }
            }
        })
    }

    fn pre_modify(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // Should these be EntrySealed?
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        if me.event.is_internal() {
            ltrace!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }
        // Prevent adding class: system, domain_info, tombstone, or recycled.
        me.modlist.iter().fold(Ok(()), |acc, m| {
            if acc.is_err() {
                acc
            } else {
                match m {
                    Modify::Present(a, v) => {
                        // TODO: Can we avoid this clone?
                        if a == "class"
                            && (v == &(*VCLASS_SYSTEM)
                                || v == &(*VCLASS_DOMAIN_INFO)
                                || v == &(*VCLASS_SYSTEM_INFO)
                                || v == &(*VCLASS_SYSTEM_CONFIG)
                                || v == &(*VCLASS_TOMBSTONE)
                                || v == &(*VCLASS_RECYCLED))
                        {
                            Err(OperationError::SystemProtectedObject)
                        } else {
                            Ok(())
                        }
                    }
                    _ => Ok(()),
                }
            }
        })?;

        // HARD block mods on tombstone or recycle. We soft block on the rest as they may
        // have some allowed attrs.
        cand.iter().fold(Ok(()), |acc, cand| match acc {
            Err(_) => acc,
            Ok(_) => {
                if cand.attribute_value_pres("class", &PVCLASS_TOMBSTONE)
                    || cand.attribute_value_pres("class", &PVCLASS_RECYCLED)
                {
                    Err(OperationError::SystemProtectedObject)
                } else {
                    acc
                }
            }
        })?;

        // if class: system, check the mods are "allowed"
        let system_pres = cand.iter().fold(false, |acc, c| {
            if acc {
                acc
            } else {
                // We don't need to check for domain info here because domain_info has a class
                // system also. We just need to block it from being created.
                c.attribute_value_pres("class", &PVCLASS_SYSTEM)
            }
        });

        ltrace!(au, "class: system -> {}", system_pres);
        // No system types being altered, return.
        if !system_pres {
            return Ok(());
        }

        // Something altered is system, check if it's allowed.
        me.modlist.iter().fold(Ok(()), |acc, m| {
            // Already hit an error, move on.
            if acc.is_err() {
                acc
            } else {
                let a = match m {
                    Modify::Present(a, _) => a,
                    Modify::Removed(a, _) => a,
                    Modify::Purged(a) => a,
                };
                match ALLOWED_ATTRS.get(a.as_str()) {
                    Some(_) => Ok(()),
                    None => Err(OperationError::SystemProtectedObject),
                }
            }
        })
    }

    fn pre_delete(
        au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
        // Should these be EntrySealed
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        if de.event.is_internal() {
            ltrace!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }

        cand.iter().fold(Ok(()), |acc, cand| match acc {
            Err(_) => acc,
            Ok(_) => {
                if cand.attribute_value_pres("class", &PVCLASS_SYSTEM)
                    || cand.attribute_value_pres("class", &PVCLASS_DOMAIN_INFO)
                    || cand.attribute_value_pres("class", &PVCLASS_SYSTEM_INFO)
                    || cand.attribute_value_pres("class", &PVCLASS_SYSTEM_CONFIG)
                    || cand.attribute_value_pres("class", &PVCLASS_TOMBSTONE)
                    || cand.attribute_value_pres("class", &PVCLASS_RECYCLED)
                {
                    Err(OperationError::SystemProtectedObject)
                } else {
                    acc
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::JSON_ADMIN_V1;
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::value::{PartialValue, Value};
    use kanidm_proto::v1::OperationError;

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
            "description": ["Builtin IDM Administrators Access Controls for TESTING."],
            "acp_enable": ["true"],
            "acp_receiver": [
                "{\"eq\":[\"uuid\",\"00000000-0000-0000-0000-000000000000\"]}"
            ],
            "acp_targetscope": [
                "{\"pres\":\"class\"}"
            ],
            "acp_search_attr": ["name", "class", "uuid", "classname", "attributename"],
            "acp_modify_class": ["system", "domain_info"],
            "acp_modify_removedattr": ["class", "displayname", "may", "must", "domain_name", "domain_uuid", "domain_ssid"],
            "acp_modify_presentattr": ["class", "displayname", "may", "must", "domain_name", "domain_uuid", "domain_ssid"],
            "acp_create_class": ["object", "person", "system", "domain_info"],
            "acp_create_attr": ["name", "class", "description", "displayname", "domain_name", "domain_uuid", "domain_ssid", "uuid"]
        }
    }"#;

    #[test]
    fn test_pre_create_deny() {
        // Test creating with class: system is rejected.
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);

        let preload = vec![acp];

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

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_modify_system_deny() {
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
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

        let preload = vec![acp, e.clone()];

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge("displayname"),
                m_pres("displayname", &Value::new_utf8s("system test")),
            ]),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_modify_class_add_deny() {
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
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

        let preload = vec![acp, e.clone()];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("classname", PartialValue::new_class("testclass"))),
            modlist!([
                m_pres("may", &Value::new_iutf8s("name")),
                m_pres("must", &Value::new_iutf8s("name")),
            ]),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_delete_deny() {
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
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

        let preload = vec![acp, e.clone()];

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_modify_domain() {
        // Can edit *my* domain_ssid and domain_name
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
        // Show that adding a system class is denied
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generaiton"],
                "domain_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"]
            }
        }"#,
        );

        let preload = vec![acp, e.clone()];

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
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_ext_create_domain() {
        // can not add a domain_info type - note the lack of class: system
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
        let preload = vec![acp];
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generaiton"],
                "domain_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"]
            }
        }"#,
        );
        let create = vec![e];

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_delete_domain() {
        let acp: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_ADMIN_ALLOW_ALL);
        // On the real thing we have a class: system, but to prove the point ...
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["domain_info"],
                "name": ["domain_example.net.au"],
                "uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "domain_uuid": ["96fd1112-28bc-48ae-9dda-5acb4719aaba"],
                "description": ["Demonstration of a remote domain's info being created for uuid generaiton"],
                "domain_name": ["example.net.au"],
                "domain_ssid": ["Example_Wifi"]
            }
        }"#,
        );

        let preload = vec![acp, e.clone()];

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(
                "name",
                PartialValue::new_iname("domain_example.net.au")
            )),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }
}
