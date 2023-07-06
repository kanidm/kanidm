// A plugin that generates gid numbers on types that require them for posix
// support.

use std::iter::once;
use std::sync::Arc;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::utils::uuid_to_gid_u32;

/// Systemd dynamic units allocate between 61184–65519, most distros allocate
/// system uids from 0 - 1000, and many others give user ids between 1000 to
/// 2000. This whole numberspace is cursed, lets assume it's not ours. :(
const GID_SYSTEM_NUMBER_MIN: u32 = 65536;

/// This is the normal system range, we MUST NOT allow it to be allocated.
const GID_SAFETY_NUMBER_MIN: u32 = 1000;

pub struct GidNumber {}

fn apply_gidnumber<T: Clone>(e: &mut Entry<EntryInvalid, T>) -> Result<(), OperationError> {
    if (e.attribute_equality("class", &PVCLASS_POSIXGROUP)
        || e.attribute_equality("class", &PVCLASS_POSIXACCOUNT))
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
                "gidnumber {gid} may overlap with system range {GID_SYSTEM_NUMBER_MIN}"
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
                "gidnumber {gid} overlaps into system secure range {GID_SAFETY_NUMBER_MIN}"
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

    #[instrument(level = "debug", name = "gidnumber_pre_create_transform", skip_all)]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(apply_gidnumber)
    }

    #[instrument(level = "debug", name = "gidnumber_pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(apply_gidnumber)
    }

    #[instrument(level = "debug", name = "gidnumber_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(apply_gidnumber)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    fn check_gid(qs_write: &mut QueryServerWriteTransaction, uuid: &str, gid: u32) {
        let u = Uuid::parse_str(uuid).unwrap();
        let e = qs_write.internal_search_uuid(u).unwrap();
        let gidnumber = e.get_ava_single("gidnumber").unwrap();
        let ex_gid = Value::new_uint32(gid);
        assert!(ex_gid == gidnumber);
    }

    #[test]
    fn test_gidnumber_create_generate() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            (
                "uuid",
                Value::Uuid(uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let create = vec![e];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs_write: &mut QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test that gid is not altered if provided on create.
    #[test]
    fn test_gidnumber_create_noaction() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            ("gidnumber", Value::Uint32(10001)),
            (
                "uuid",
                Value::Uuid(uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let create = vec![e];
        let preload = Vec::new();

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs_write: &mut QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                10001
            )
        );
    }

    // Test generated if not on mod (ie adding posixaccount to something)
    #[test]
    fn test_gidnumber_modify_generate() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            (
                "uuid",
                Value::Uuid(uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([m_pres("class", &Value::new_class("posixgroup"))]),
            None,
            |_| {},
            |qs_write: &mut QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test generated if DELETED on mod
    #[test]
    fn test_gidnumber_modify_regenerate() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            (
                "uuid",
                Value::Uuid(uuid::uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let preload = vec![e];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testperson"))),
            modlist!([m_purge("gidnumber")]),
            None,
            |_| {},
            |qs_write: &mut QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // Test NOT regenerated if given on mod
    #[test]
    fn test_gidnumber_modify_noregen() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            (
                "uuid",
                Value::Uuid(uuid::uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
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
            |_| {},
            |qs_write: &mut QueryServerWriteTransaction| check_gid(
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                2000
            )
        );
    }

    #[test]
    fn test_gidnumber_create_system_reject() {
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            (
                "uuid",
                Value::Uuid(uuid::uuid!("83a0927f-3de1-45ec-bea0-000000000244"))
            ),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let create = vec![e];
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
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            ("gidnumber", Value::Uint32(500)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let create = vec![e];
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
        let e = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("posixaccount")),
            ("name", Value::new_iname("testperson")),
            ("gidnumber", Value::Uint32(0)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let create = vec![e];
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
