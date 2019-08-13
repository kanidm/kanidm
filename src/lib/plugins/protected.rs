// System protected objects. Items matching specific requirements
// may only have certain modifications performed.
use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use crate::error::OperationError;
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::Modify;
use crate::server::QueryServerWriteTransaction;
use crate::value::{Value, PartialValue};
use std::collections::HashSet;

pub struct Protected {}

// Here is the declaration of all the attrs that can be altered by
// a call on a system object. We trust they are allowed because
// schema will have checked this, and we don't allow class changes!

lazy_static! {
    static ref ALLOWED_ATTRS: HashSet<&'static str> = {
        let mut m = HashSet::new();
        m.insert("must");
        m.insert("may");
        m
    };
    static ref VCLASS_SYSTEM: Value = Value::new_class("system");
    static ref PVCLASS_SYSTEM: PartialValue = PartialValue::new_class("system");
}

impl Plugin for Protected {
    fn id() -> &'static str {
        "plugin_protected"
    }

    fn pre_create(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        cand: &Vec<Entry<EntryValid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        if ce.event.is_internal() {
            audit_log!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }

        cand.iter().fold(Ok(()), |acc, cand| match acc {
            Err(_) => acc,
            Ok(_) => {
                if cand.attribute_value_pres("class", &PVCLASS_SYSTEM) {
                    Err(OperationError::SystemProtectedObject)
                } else {
                    acc
                }
            }
        })
    }

    fn pre_modify(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntryValid?
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        if me.event.is_internal() {
            audit_log!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }
        // Prevent adding class: system
        me.modlist.iter().fold(Ok(()), |acc, m| {
            if acc.is_err() {
                acc
            } else {
                match m {
                    Modify::Present(a, v) => {
                        if a == "class" && &v == &VCLASS_SYSTEM {
                            Err(OperationError::SystemProtectedObject)
                        } else {
                            Ok(())
                        }
                    }
                    _ => Ok(()),
                }
            }
        })?;
        // if class: system, check the mods are "allowed"

        let system_pres = cand.iter().fold(false, |acc, c| {
            if acc {
                acc
            } else {
                c.attribute_value_pres("class", &PVCLASS_SYSTEM)
            }
        });

        audit_log!(au, "class: system -> {}", system_pres);
        // No system types being altered, return.
        if system_pres == false {
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
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntryValid
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        if de.event.is_internal() {
            audit_log!(
                au,
                "Internal operation, not enforcing system object protection"
            );
            return Ok(());
        }

        cand.iter().fold(Ok(()), |acc, cand| match acc {
            Err(_) => acc,
            Ok(_) => {
                if cand.attribute_value_pres("class", &PVCLASS_SYSTEM) {
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
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::error::OperationError;

    static JSON_ADMIN_ALLOW_ALL: &'static str = r#"{
        "valid": null,
        "state": null,
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
                "{\"Eq\":[\"uuid\",\"00000000-0000-0000-0000-000000000000\"]}"
            ],
            "acp_targetscope": [
                "{\"Pres\":\"class\"}"
            ],
            "acp_search_attr": ["name", "class", "uuid"],
            "acp_modify_class": ["system"],
            "acp_modify_removedattr": ["class", "displayname", "may", "must"],
            "acp_modify_presentattr": ["class", "displayname", "may", "must"],
            "acp_create_class": ["object", "person", "system"],
            "acp_create_attr": ["name", "class", "description", "displayname"]
        }
    }"#;

    #[test]
    fn test_pre_create_deny() {
        // Test creating with class: system is rejected.
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");

        let preload = vec![acp];

        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

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
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");
        // Test modify of class to a system is denied
        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

        let preload = vec![acp, e.clone()];

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", "testperson")),
            modlist!([m_purge("displayname"), m_pres("displayname", "system test"),]),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_modify_class_add_deny() {
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");
        // Show that adding a system class is denied
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
        .expect("json parse failure");

        let preload = vec![acp, e.clone()];

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", "testperson")),
            modlist!([m_pres("class", "system"),]),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_modify_attr_must_may_allow() {
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");
        // Show that adding a system class is denied
        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["object", "classtype"],
                "name": ["testclass"],
                "uuid": ["cfcae205-31c3-484b-8ced-667d1709c5e3"],
                "description": ["Test Class"]
            }
        }"#,
        )
        .expect("json parse failure");

        let preload = vec![acp, e.clone()];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", "testclass")),
            modlist!([m_pres("may", "name"), m_pres("must", "name"),]),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }

    #[test]
    fn test_pre_delete_deny() {
        let acp: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(JSON_ADMIN_ALLOW_ALL).expect("json parse failure");
        // Test deleting with class: system is rejected.
        let e: Entry<EntryInvalid, EntryNew> = serde_json::from_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["person", "system"],
                "name": ["testperson"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .expect("json parse failure");

        let preload = vec![acp, e.clone()];

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq("name", "testperson")),
            Some(JSON_ADMIN_V1),
            |_, _| {}
        );
    }
}
