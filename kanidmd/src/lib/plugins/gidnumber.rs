// A plugin that generates gid numbers on types that require them for posix
// support.

use crate::plugins::Plugin;

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew};
use crate::event::{CreateEvent, ModifyEvent};
// use crate::server::QueryServerTransaction;
use crate::server::QueryServerWriteTransaction;
use crate::utils::uuid_to_gid_u32;
use crate::value::{PartialValue, Value};

use kanidm_proto::v1::OperationError;

static GIDNUMBER_MIN: u32 = 2000;

lazy_static! {
    static ref CLASS_POSIXGROUP: PartialValue = PartialValue::new_iutf8s("posixgroup");
    static ref CLASS_POSIXACCOUNT: PartialValue = PartialValue::new_iutf8s("posixaccount");
}

pub struct GidNumber {}

fn apply_gidnumber<T: Copy>(
    au: &mut AuditScope,
    e: &mut Entry<EntryInvalid, T>,
) -> Result<(), OperationError> {
    if (e.attribute_value_pres("class", &CLASS_POSIXGROUP)
        || e.attribute_value_pres("class", &CLASS_POSIXACCOUNT))
        && !e.attribute_pres("gidnumber")
    {
        let u_ref = try_audit!(au, e.get_uuid().ok_or(OperationError::InvalidEntryState));
        let gid = uuid_to_gid_u32(u_ref);
        // assert the value is greater than 2000
        if gid < GIDNUMBER_MIN {
            return Err(OperationError::InvalidAttribute(format!(
                "gidnumber {} may overlap with system range {}",
                gid, GIDNUMBER_MIN
            )));
        }

        let gid_v = Value::new_uint32(gid);
        audit_log!(au, "Generated {} for {:?}", gid, u_ref);
        e.set_avas("gidnumber", vec![gid_v]);
        Ok(())
    } else {
        Ok(())
    }
}

impl Plugin for GidNumber {
    fn id() -> &'static str {
        "plugin_gidnumber"
    }

    fn pre_create_transform(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        for e in cand.iter_mut() {
            apply_gidnumber(au, e)?;
        }

        Ok(())
    }

    fn pre_modify(
        au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        for e in cand.iter_mut() {
            apply_gidnumber(au, e)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use crate::value::{PartialValue, Value};
    use uuid::Uuid;

    fn check_gid(
        au: &mut AuditScope,
        qs_write: &QueryServerWriteTransaction,
        uuid: &str,
        gid: u32,
    ) {
        let u = Uuid::parse_str(uuid).unwrap();
        let e = qs_write.internal_search_uuid(au, &u).unwrap();
        let gidnumber = e.get_ava_single("gidnumber").unwrap();
        let ex_gid = Value::new_uint32(gid);
        assert!(&ex_gid == gidnumber);
    }

    #[test]
    fn test_gidnumber_create_generate() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            |au, qs_write: &QueryServerWriteTransaction| check_gid(
                au,
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test that gid is not altered if provided on create.
    #[test]
    fn test_gidnumber_create_noaction() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["account", "posixaccount"],
                "name": ["testperson"],
                "uuid": ["83a0927f-3de1-45ec-bea0-2f7b997ef244"],
                "gidnumber": ["1000"],
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
            |au, qs_write: &QueryServerWriteTransaction| check_gid(
                au,
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                1000
            )
        );
    }

    // Test generated if not on mod (ie adding posixaccount to something)
    #[test]
    fn test_gidnumber_modify_generate() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            modlist!([m_pres("class", &Value::new_class("posixgroup"))]),
            None,
            |au, qs_write: &QueryServerWriteTransaction| check_gid(
                au,
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // test generated if DELETED on mod
    #[test]
    fn test_gidnumber_modify_regenerate() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
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
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            modlist!([m_purge("gidnumber")]),
            None,
            |au, qs_write: &QueryServerWriteTransaction| check_gid(
                au,
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                0x997ef244
            )
        );
    }

    // Test NOT altered if given on mod
    #[test]
    fn test_gidnumber_modify_noaction() {
        let e: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "valid": null,
            "state": null,
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
            filter!(f_eq("name", PartialValue::new_iutf8s("testperson"))),
            modlist!([
                m_purge("gidnumber"),
                m_pres("gidnumber", &Value::new_uint32(2000))
            ]),
            None,
            |au, qs_write: &QueryServerWriteTransaction| check_gid(
                au,
                qs_write,
                "83a0927f-3de1-45ec-bea0-2f7b997ef244",
                2000
            )
        );
    }
}
