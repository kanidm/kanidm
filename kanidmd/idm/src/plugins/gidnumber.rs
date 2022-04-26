// A plugin that generates gid numbers on types that require them for posix
// support.

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::utils::uuid_to_gid_u32;
use std::iter::once;

/// Systemd dynamic units allocate between 61184–65519, most distros allocate
/// system uids from 0 - 1000, and many others give user ids between 1000 to
/// 2000. This whole numberspace is cursed, lets assume it's not ours. :(
const GID_SYSTEM_NUMBER_MIN: u32 = 65536;

/// This is the normal system range, we MUST NOT allow it to be allocated.
const GID_SAFETY_NUMBER_MIN: u32 = 1000;

lazy_static! {
    static ref CLASS_POSIXGROUP: PartialValue = PartialValue::new_class("posixgroup");
    static ref CLASS_POSIXACCOUNT: PartialValue = PartialValue::new_class("posixaccount");
}

pub struct GidNumber {}

fn apply_gidnumber<T: Clone>(e: &mut Entry<EntryInvalid, T>) -> Result<(), OperationError> {
    if (e.attribute_equality("class", &CLASS_POSIXGROUP)
        || e.attribute_equality("class", &CLASS_POSIXACCOUNT))
        && !e.attribute_pres("gidnumber")
    {
        let u_ref = e
            .get_uuid()
            .ok_or(OperationError::InvalidEntryState)
            .map_err(|e| {
                admin_error!("Invalid Entry State - Missing UUID");
                e
            })?;

        let gid = uuid_to_gid_u32(u_ref);
        // assert the value is greater than the system range.
        if gid < GID_SYSTEM_NUMBER_MIN {
            return Err(OperationError::InvalidAttribute(format!(
                "gidnumber {} may overlap with system range {}",
                gid, GID_SYSTEM_NUMBER_MIN
            )));
        }

        let gid_v = Value::new_uint32(gid);
        admin_info!("Generated {} for {:?}", gid, u_ref);
        e.set_ava("gidnumber", once(gid_v));
        Ok(())
    } else if let Some(gid) = e.get_ava_single_uint32("gidnumber") {
        // If they provided us with a gid number, ensure it's in a safe range.
        if gid <= GID_SAFETY_NUMBER_MIN {
            Err(OperationError::InvalidAttribute(format!(
                "gidnumber {} overlaps into system secure range {}",
                gid, GID_SAFETY_NUMBER_MIN
            )))
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

impl Plugin for GidNumber {
    fn id() -> &'static str {
        "plugin_gidnumber"
    }

    fn pre_create_transform(
        _qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        for e in cand.iter_mut() {
            apply_gidnumber(e)?;
        }

        Ok(())
    }

    fn pre_modify(
        _qs: &QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        for e in cand.iter_mut() {
            apply_gidnumber(e)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    fn check_gid(qs_write: &QueryServerWriteTransaction, uuid: &str, gid: u32) {
        let u = Uuid::parse_str(uuid).unwrap();
        let e = qs_write.internal_search_uuid(&u).unwrap();
        let gidnumber = e.get_ava_single("gidnumber").unwrap();
        let ex_gid = Value::new_uint32(gid);
        assert!(ex_gid == gidnumber);
    }

    #[test]
    fn test_gidnumber_create_generate() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs_write: &QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test that gid is not altered if provided on create.
    #[test]
    fn test_gidnumber_create_noaction() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "gidnumber": ["10001"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs_write: &QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                10001
            )
        );
    }

    // Test generated if not on mod (ie adding posixaccount to something)
    #[test]
    fn test_gidnumber_modify_generate() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([m_pres("class", &Value::new_class("posixgroup"))]),
            None,
            |qs_write: &QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test generated if DELETED on mod
    #[test]
    fn test_gidnumber_modify_regenerate() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "gidnumber": ["2000"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([m_purge("gidnumber")]),
            None,
            |qs_write: &QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // Test NOT regenerated if given on mod
    #[test]
    fn test_gidnumber_modify_noregen() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "gidnumber": ["3999"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge("gidnumber"),
                m_pres("gidnumber", &Value::new_uint32(2000))
            ]),
            None,
            |qs_write: &QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                2000
            )
        );
    }

    #[test]
    fn test_gidnumber_create_system_reject() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b00000244"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Err(OperationError::InvalidAttribute(
                "gidnumber 580 may overlap with system range 65536".to_string()
            )),
            preload,
            create,
            None,
            |_| {}
        );
    }

    #[test]
    fn test_gidnumber_create_secure_reject() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "gidnumber": ["500"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Err(OperationError::InvalidAttribute(
                "gidnumber 500 overlaps into system secure range 1000".to_string()
            )),
            preload,
            create,
            None,
            |_| {}
        );
    }

    #[test]
    fn test_gidnumber_create_secure_root_reject() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "gidnumber": ["0"],
                "description": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        );

        let create = vec![e.clone()];
        let preload = Vec::new();

        run_create_test!(
            Err(OperationError::InvalidAttribute(
                "gidnumber 0 overlaps into system secure range 1000".to_string()
            )),
            preload,
            create,
            None,
            |_| {}
        );
    }
}
