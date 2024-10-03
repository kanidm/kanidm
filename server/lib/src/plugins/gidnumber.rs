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
///
/// Per <https://systemd.io/UIDS-GIDS/>, systemd claims a huge chunk of this
/// space to itself. As a result we can't allocate between 65536 and u32 max
/// because systemd takes most of the usable range for its own containers,
/// and half the range is probably going to trigger linux kernel issues.
///
/// Seriously, linux's uid/gid model is so fundamentally terrible... Windows
/// NT got this right with SIDs.
///
/// Because of this, we have to ensure that anything we allocate is in the
/// range 1879048192 (0x70000000) to 2147483647 (0x7fffffff)
const GID_SYSTEM_NUMBER_PREFIX: u32 = 0x7000_0000;
const GID_SYSTEM_NUMBER_MASK: u32 = 0x0fff_ffff;

/// Systemd claims so many ranges to itself, we have to check we are in certain bounds.

/// This is the normal system range, we MUST NOT allow it to be allocated.
pub const GID_REGULAR_USER_MIN: u32 = 1000;
pub const GID_REGULAR_USER_MAX: u32 = 60000;

/// Systemd homed claims 60001 through 60577

pub const GID_UNUSED_A_MIN: u32 = 60578;
pub const GID_UNUSED_A_MAX: u32 = 61183;

/// Systemd dyn service users 61184 through 65519

pub const GID_UNUSED_B_MIN: u32 = 65520;
pub const GID_UNUSED_B_MAX: u32 = 65533;

/// nobody is 65534
/// 16bit uid -1 65535

pub const GID_UNUSED_C_MIN: u32 = 65536;
const GID_UNUSED_C_MAX: u32 = 524287;

/// systemd claims 524288 through 1879048191 for nspawn

const GID_NSPAWN_MIN: u32 = 524288;
const GID_NSPAWN_MAX: u32 = 1879048191;

const GID_UNUSED_D_MIN: u32 = 0x7000_0000;
pub const GID_UNUSED_D_MAX: u32 = 0x7fff_ffff;

/// Anything above 2147483648 can confuse the kernel (so basicly half the address space
/// can't be accessed.
// const GID_UNSAFE_MAX: u32 = 2147483648;

pub struct GidNumber {}

fn apply_gidnumber<T: Clone>(
    e: &mut Entry<EntryInvalid, T>,
    domain_version: DomainVersion,
) -> Result<(), OperationError> {
    if (e.attribute_equality(Attribute::Class, &EntryClass::PosixGroup.into())
        || e.attribute_equality(Attribute::Class, &EntryClass::PosixAccount.into()))
        && !e.attribute_pres(Attribute::GidNumber)
    {
        let u_ref = e
            .get_uuid()
            .ok_or(OperationError::InvalidEntryState)
            .inspect_err(|_e| {
                admin_error!("Invalid Entry State - Missing UUID");
            })?;

        let gid = uuid_to_gid_u32(u_ref);

        // Apply the mask to only take the last 24 bits, and then move them
        // to the correct range.
        let gid = gid & GID_SYSTEM_NUMBER_MASK;
        let gid = gid | GID_SYSTEM_NUMBER_PREFIX;

        let gid_v = Value::new_uint32(gid);
        admin_info!("Generated {} for {:?}", gid, u_ref);
        e.set_ava(&Attribute::GidNumber, once(gid_v));
        Ok(())
    } else if let Some(gid) = e.get_ava_single_uint32(Attribute::GidNumber) {
        if domain_version <= DOMAIN_LEVEL_6 {
            if gid < GID_REGULAR_USER_MIN {
                error!(
                    "Requested GID ({}) overlaps a system range. Allowed ranges are {} to {}, {} to {} and {} to {}",
                    gid,
                    GID_REGULAR_USER_MIN, GID_REGULAR_USER_MAX,
                    GID_UNUSED_C_MIN, GID_UNUSED_C_MAX,
                    GID_UNUSED_D_MIN, GID_UNUSED_D_MAX
                );
                Err(OperationError::PL0001GidOverlapsSystemRange)
            } else {
                Ok(())
            }
        } else {
            // If they provided us with a gid number, ensure it's in a safe range.
            if (GID_REGULAR_USER_MIN..=GID_REGULAR_USER_MAX).contains(&gid)
                || (GID_UNUSED_A_MIN..=GID_UNUSED_A_MAX).contains(&gid)
                || (GID_UNUSED_B_MIN..= GID_UNUSED_B_MAX).contains(&gid)
                || (GID_UNUSED_C_MIN..=GID_UNUSED_C_MAX).contains(&gid)
                // We won't ever generate an id in the nspawn range, but we do secretly allow
                // it to be set for compatability with services like freeipa or openldap. TBH
                // most people don't even use systemd nspawn anyway ...
                //
                // I made this design choice to avoid a tunable that may confuse people to
                // its purpose. This way things "just work" for imports and existing systems
                // but we do the right thing in the future.
                || (GID_NSPAWN_MIN..=GID_NSPAWN_MAX).contains(&gid)
                || (GID_UNUSED_D_MIN..=GID_UNUSED_D_MAX).contains(&gid)
            {
                Ok(())
            } else {
                // Note that here we don't advertise that we allow the nspawn range to be set, even
                // though we do allow it.
                error!(
                    "Requested GID ({}) overlaps a system range. Allowed ranges are {} to {}, {} to {} and {} to {}",
                    gid,
                    GID_REGULAR_USER_MIN, GID_REGULAR_USER_MAX,
                    GID_UNUSED_C_MIN, GID_UNUSED_C_MAX,
                    GID_UNUSED_D_MIN, GID_UNUSED_D_MAX
                );
                Err(OperationError::PL0001GidOverlapsSystemRange)
            }
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
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let dv = qs.get_domain_version();
        cand.iter_mut()
            .try_for_each(|cand| apply_gidnumber(cand, dv))
    }

    #[instrument(level = "debug", name = "gidnumber_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        let dv = qs.get_domain_version();
        cand.iter_mut()
            .try_for_each(|cand| apply_gidnumber(cand, dv))
    }

    #[instrument(level = "debug", name = "gidnumber_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        let dv = qs.get_domain_version();
        cand.iter_mut()
            .try_for_each(|cand| apply_gidnumber(cand, dv))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GID_REGULAR_USER_MAX, GID_REGULAR_USER_MIN, GID_UNUSED_A_MAX, GID_UNUSED_A_MIN,
        GID_UNUSED_B_MAX, GID_UNUSED_B_MIN, GID_UNUSED_C_MIN, GID_UNUSED_D_MAX,
    };
    use crate::prelude::*;

    use kanidm_proto::internal::DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus;

    #[qs_test(domain_level=DOMAIN_LEVEL_7)]
    async fn test_gidnumber_generate(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.expect("txn");

        // Test that the gid number is generated on create
        {
            let user_a_uuid = uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244");
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson_1")),
                (Attribute::Uuid, Value::Uuid(user_a_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_a = server_txn
                .internal_search_uuid(user_a_uuid)
                .expect("Unable to access user");

            let user_a_uid = user_a
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_a_uid, 0x797ef244);
        }

        // test that gid is not altered if provided on create.
        let user_b_uuid = uuid!("d90fb0cb-6785-4f36-94cb-e364d9c13255");
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson_2")),
                (Attribute::Uuid, Value::Uuid(user_b_uuid)),
                (Attribute::GidNumber, Value::Uint32(10001)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_b = server_txn
                .internal_search_uuid(user_b_uuid)
                .expect("Unable to access user");

            let user_b_uid = user_b
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_b_uid, 10001);
        }

        // Test that if the value is deleted, it is correctly regenerated.
        {
            let modlist = modlist!([m_purge(Attribute::GidNumber)]);
            server_txn
                .internal_modify_uuid(user_b_uuid, &modlist)
                .expect("Unable to modify user");

            let user_b = server_txn
                .internal_search_uuid(user_b_uuid)
                .expect("Unable to access user");

            let user_b_uid = user_b
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_b_uid, 0x79c13255);
        }

        let user_c_uuid = uuid!("0d5086b0-74f9-4518-92b4-89df0c55971b");
        // Test that an entry when modified to have posix attributes will have
        // it's gidnumber generated.
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_3")),
                (Attribute::Uuid, Value::Uuid(user_c_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_c = server_txn
                .internal_search_uuid(user_c_uuid)
                .expect("Unable to access user");

            assert_eq!(user_c.get_ava_single_uint32(Attribute::GidNumber), None);

            let modlist = modlist!([m_pres(
                Attribute::Class,
                &EntryClass::PosixAccount.to_value()
            )]);
            server_txn
                .internal_modify_uuid(user_c_uuid, &modlist)
                .expect("Unable to modify user");

            let user_c = server_txn
                .internal_search_uuid(user_c_uuid)
                .expect("Unable to access user");

            let user_c_uid = user_c
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_c_uid, 0x7c55971b);
        }

        let user_d_uuid = uuid!("36dc9010-d80c-404b-b5ba-8f66657c2f1d");
        // Test that an entry when modified to have posix attributes will have
        // it's gidnumber generated.
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_4")),
                (Attribute::Uuid, Value::Uuid(user_d_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_d = server_txn
                .internal_search_uuid(user_d_uuid)
                .expect("Unable to access user");

            assert_eq!(user_d.get_ava_single_uint32(Attribute::GidNumber), None);

            let modlist = modlist!([m_pres(
                Attribute::Class,
                &EntryClass::PosixAccount.to_value()
            )]);
            server_txn
                .internal_modify_uuid(user_d_uuid, &modlist)
                .expect("Unable to modify user");

            let user_d = server_txn
                .internal_search_uuid(user_d_uuid)
                .expect("Unable to access user");

            let user_d_uid = user_d
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_d_uid, 0x757c2f1d);
        }

        let user_e_uuid = uuid!("a6dc0d68-9c7a-4dad-b1e2-f6274b691373");
        // Test that an entry when modified to have posix attributes, if a gidnumber
        // is provided then it is respected.
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_5")),
                (Attribute::Uuid, Value::Uuid(user_e_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_e = server_txn
                .internal_search_uuid(user_e_uuid)
                .expect("Unable to access user");

            assert_eq!(user_e.get_ava_single_uint32(Attribute::GidNumber), None);

            let modlist = modlist!([
                m_pres(Attribute::Class, &EntryClass::PosixAccount.to_value()),
                m_pres(Attribute::GidNumber, &Value::Uint32(10002))
            ]);
            server_txn
                .internal_modify_uuid(user_e_uuid, &modlist)
                .expect("Unable to modify user");

            let user_e = server_txn
                .internal_search_uuid(user_e_uuid)
                .expect("Unable to access user");

            let user_e_uid = user_e
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_e_uid, 10002);
        }

        // Test rejection of important gid values.
        let user_f_uuid = uuid!("33afc396-2434-47e5-b143-05176148b50e");
        // Test that an entry when modified to have posix attributes, if a gidnumber
        // is provided then it is respected.
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_6")),
                (Attribute::Uuid, Value::Uuid(user_f_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            for id in [
                0,
                500,
                GID_REGULAR_USER_MIN - 1,
                GID_REGULAR_USER_MAX + 1,
                GID_UNUSED_A_MIN - 1,
                GID_UNUSED_A_MAX + 1,
                GID_UNUSED_B_MIN - 1,
                GID_UNUSED_B_MAX + 1,
                GID_UNUSED_C_MIN - 1,
                GID_UNUSED_D_MAX + 1,
                u32::MAX,
            ] {
                let modlist = modlist!([
                    m_pres(Attribute::Class, &EntryClass::PosixAccount.to_value()),
                    m_pres(Attribute::GidNumber, &Value::Uint32(id))
                ]);
                let op_result = server_txn.internal_modify_uuid(user_f_uuid, &modlist);

                trace!(?id);
                assert_eq!(op_result, Err(OperationError::PL0001GidOverlapsSystemRange));
            }
        }

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_6)]
    async fn test_gidnumber_domain_level_6(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.expect("txn");

        // This will be INVALID in DL 7 but it's allowed for DL6
        let user_a_uuid = uuid!("d90fb0cb-6785-4f36-94cb-e364d9c13255");
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson_2")),
                (Attribute::Uuid, Value::Uuid(user_a_uuid)),
                // NOTE HERE: We do GID_UNUSED_A_MIN minus 1 which isn't accepted
                // on DL7
                (Attribute::GidNumber, Value::Uint32(GID_UNUSED_A_MIN - 1)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            let user_a = server_txn
                .internal_search_uuid(user_a_uuid)
                .expect("Unable to access user");

            let user_a_uid = user_a
                .get_ava_single_uint32(Attribute::GidNumber)
                .expect("gidnumber not present on account");

            assert_eq!(user_a_uid, GID_UNUSED_A_MIN - 1);
        }

        assert!(server_txn.commit().is_ok());

        // Now, do the DL6 upgrade check - will FAIL because the above user has an invalid ID.
        let mut server_txn = server.read().await.unwrap();

        let check_item = server_txn
            .domain_upgrade_check_6_to_7_gidnumber()
            .expect("Failed to perform migration check.");

        assert_eq!(
            check_item.status,
            ProtoDomainUpgradeCheckStatus::Fail6To7Gidnumber
        );

        drop(server_txn);

        let mut server_txn = server.write(duration_from_epoch_now()).await.expect("txn");

        // Test rejection of important gid values.
        let user_b_uuid = uuid!("33afc396-2434-47e5-b143-05176148b50e");
        // Test that an entry when modified to have posix attributes, if a gidnumber
        // is provided then it is respected.
        {
            let op_result = server_txn.internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_6")),
                (Attribute::Uuid, Value::Uuid(user_b_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson")),
                (Attribute::DisplayName, Value::new_utf8s("testperson"))
            )]);

            assert!(op_result.is_ok());

            for id in [0, 500, GID_REGULAR_USER_MIN - 1] {
                let modlist = modlist!([
                    m_pres(Attribute::Class, &EntryClass::PosixAccount.to_value()),
                    m_pres(Attribute::GidNumber, &Value::Uint32(id))
                ]);
                let op_result = server_txn.internal_modify_uuid(user_b_uuid, &modlist);

                trace!(?id);
                assert_eq!(op_result, Err(OperationError::PL0001GidOverlapsSystemRange));
            }
        }

        assert!(server_txn.commit().is_ok());
    }
}
