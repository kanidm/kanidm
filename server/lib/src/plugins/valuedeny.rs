use std::sync::Arc;

use crate::plugins::Plugin;
use crate::prelude::*;

pub struct ValueDeny {}

impl Plugin for ValueDeny {
    fn id() -> &'static str {
        "plugin_value_deny"
    }

    #[instrument(level = "debug", name = "base_pre_create_transform", skip_all)]
    #[allow(clippy::cognitive_complexity)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let denied_names = qs.denied_names();

        let mut pass = true;

        for entry in cand {
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

    #[instrument(level = "debug", name = "base_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(qs, cand)
    }

    #[instrument(level = "debug", name = "base_pre_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify(qs, cand)
    }

    #[instrument(level = "debug", name = "base::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let denied_names = qs.denied_names().clone();

        let mut results = Vec::with_capacity(0);

        for denied_name in denied_names {
            let filt = filter!(f_eq(Attribute::Name, PartialValue::new_iname(&denied_name)));
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
    fn modify(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        let denied_names = qs.denied_names();

        let mut pass = true;

        for entry in cand {
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
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    async fn setup_name_deny(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PVUUID_SYSTEM_CONFIG.clone())),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::DeniedName.into(),
                Value::new_iname("tobias"),
            )]),
        );
        assert!(server_txn.modify(&me_inv_m).is_ok());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_valuedeny_create(server: &QueryServer) {
        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await;
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
        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await;
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

        // Now mod it

        assert!(server_txn
            .internal_modify_uuid(
                t_uuid,
                &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("tobias"))
            )
            .is_err());
    }

    #[qs_test]
    async fn test_valuedeny_batch_modify(server: &QueryServer) {
        setup_name_deny(server).await;

        let mut server_txn = server.write(duration_from_epoch_now()).await;
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
