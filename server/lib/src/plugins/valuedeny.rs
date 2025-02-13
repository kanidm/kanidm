use std::sync::Arc;

use crate::plugins::Plugin;
use crate::prelude::*;

pub struct ValueDeny {}

impl Plugin for ValueDeny {
    fn id() -> &'static str {
        "plugin_value_deny"
    }

    #[instrument(level = "debug", name = "denied_names_pre_create_transform", skip_all)]
    #[allow(clippy::cognitive_complexity)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let denied_names = qs.denied_names();

        if denied_names.is_empty() {
            // Nothing to check.
            return Ok(());
        }

        let mut pass = true;

        for entry in cand {
            // If the entry doesn't have a uuid, it's invalid anyway and will fail schema.
            if let Some(e_uuid) = entry.get_uuid() {
                // SAFETY - Thanks to JpWarren blowing his nipper clean off, we need to
                // assert that the break glass accounts are NOT subject to this process.
                if e_uuid == UUID_ADMIN || e_uuid == UUID_IDM_ADMIN {
                    // These entries are exempt
                    continue;
                }
            }

            if let Some(name) = entry.get_ava_single_iname(Attribute::Name) {
                if denied_names.contains(name) {
                    pass = false;
                    error!(?name, "name denied by system configuration");
                }
            }
        }

        if pass {
            Ok(())
        } else {
            Err(OperationError::ValueDenyName)
        }
    }

    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(qs, pre_cand, cand)
    }

    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(qs, pre_cand, cand)
    }

    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let denied_names = qs.denied_names().clone();

        let mut results = Vec::with_capacity(0);

        for denied_name in denied_names {
            let filt = filter!(f_and(vec![
                f_eq(Attribute::Name, PartialValue::new_iname(&denied_name)),
                f_andnot(f_or(vec![
                    f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_ADMIN)),
                    f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_IDM_ADMIN)),
                ])),
            ]));
            match qs.internal_search(filt) {
                Ok(entries) => {
                    for entry in entries {
                        results.push(Err(ConsistencyError::DeniedName(entry.get_uuid())));
                    }
                }
                Err(err) => {
                    error!(?err);
                    results.push(Err(ConsistencyError::QueryServerSearchFailure))
                }
            }
        }

        results
    }
}

impl ValueDeny {
    #[instrument(level = "debug", name = "denied_names_modify", skip_all)]
    fn modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut [EntryInvalidCommitted],
    ) -> Result<(), OperationError> {
        let denied_names = qs.denied_names();

        if denied_names.is_empty() {
            // Nothing to check.
            return Ok(());
        }

        let mut pass = true;

        for (pre_entry, post_entry) in pre_cand.iter().zip(cand.iter()) {
            // If the entry doesn't have a uuid, it's invalid anyway and will fail schema.
            let e_uuid = pre_entry.get_uuid();
            // SAFETY - Thanks to JpWarren blowing his nipper clean off, we need to
            // assert that the break glass accounts are NOT subject to this process.
            if e_uuid == UUID_ADMIN || e_uuid == UUID_IDM_ADMIN {
                // These entries are exempt
                continue;
            }

            let pre_name = pre_entry.get_ava_single_iname(Attribute::Name);
            let post_name = post_entry.get_ava_single_iname(Attribute::Name);

            if let Some(name) = post_name {
                // Only if the name is changing, and is denied.
                if pre_name != post_name && denied_names.contains(name) {
                    pass = false;
                    error!(?name, "name denied by system configuration");
                }
            }
        }

        if pass {
            Ok(())
        } else {
            Err(OperationError::ValueDenyName)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    async fn setup_name_deny(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PVUUID_SYSTEM_CONFIG.clone())),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::DeniedName, Value::new_iname("tobias")),
                Modify::Present(Attribute::DeniedName, Value::new_iname("ellie")),
            ]),
        );
        assert!(server_txn.modify(&me_inv_m).is_ok());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_valuedeny_create(server: &QueryServer) {
        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("tobias")),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (Attribute::Description, Value::new_utf8s("Tobias")),
                (Attribute::DisplayName, Value::new_utf8s("Tobias"))
            ),])
            .is_err());
    }

    #[qs_test]
    async fn test_valuedeny_modify(server: &QueryServer) {
        // Create an entry that has a name which will become denied to test how it
        // interacts.
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let e_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("ellie")),
                (Attribute::Uuid, Value::Uuid(e_uuid)),
                (Attribute::Description, Value::new_utf8s("Ellie Meow")),
                (Attribute::DisplayName, Value::new_utf8s("Ellie Meow"))
            ),])
            .is_ok());

        assert!(server_txn.commit().is_ok());

        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Attempt to mod ellie.

        // Can mod a different attribute
        assert!(server_txn
            .internal_modify_uuid(
                e_uuid,
                &ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("tobias"))
            )
            .is_ok());

        // Can't mod to another invalid name.
        assert!(server_txn
            .internal_modify_uuid(
                e_uuid,
                &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("tobias"))
            )
            .is_err());

        // Can mod to a valid name.
        assert!(server_txn
            .internal_modify_uuid(
                e_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::Name,
                    Value::new_iname("miss_meowington")
                )
            )
            .is_ok());

        // Now mod from the valid name to an invalid one.
        assert!(server_txn
            .internal_modify_uuid(
                e_uuid,
                &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("tobias"))
            )
            .is_err());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_valuedeny_jpwarren_special(server: &QueryServer) {
        // Assert that our break glass accounts are exempt from this processing.
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PVUUID_SYSTEM_CONFIG.clone())),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::DeniedName, Value::new_iname("admin")),
                Modify::Present(Attribute::DeniedName, Value::new_iname("idm_admin")),
            ]),
        );
        assert!(server_txn.modify(&me_inv_m).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        assert!(server_txn
            .internal_modify_uuid(
                UUID_IDM_ADMIN,
                &ModifyList::new_purge_and_set(
                    Attribute::DisplayName,
                    Value::new_utf8s("Idm Admin")
                )
            )
            .is_ok());

        assert!(server_txn
            .internal_modify_uuid(
                UUID_ADMIN,
                &ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("Admin"))
            )
            .is_ok());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_valuedeny_batch_modify(server: &QueryServer) {
        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("newname")),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (Attribute::Description, Value::new_utf8s("Tobias")),
                (Attribute::DisplayName, Value::new_utf8s("Tobias"))
            ),])
            .is_ok());

        // Now batch mod

        assert!(server_txn
            .internal_batch_modify(
                [(
                    t_uuid,
                    ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("tobias"))
                )]
                .into_iter()
            )
            .is_err());
    }
}
