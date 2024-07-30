use std::collections::BTreeSet;
use std::sync::Arc;

use kanidm_proto::internal::OperationError;

use crate::event::{CreateEvent, DeleteEvent};

use crate::prelude::ModifyEvent;
use crate::prelude::Uuid;

use super::{BatchModifyEvent, EntrySealedCommitted, Plugin, QueryServerWriteTransaction};

pub struct WriteOperationCounter {}

impl WriteOperationCounter {
    fn increase_write_ops_counter(qs: &mut QueryServerWriteTransaction) {
        qs.increase_write_ops_since_last_repl();
    }

    fn reset_write_ops_counter(qs: &mut QueryServerWriteTransaction) {
        qs.reset_write_ops_since_last_repl();
    }
}

impl Plugin for WriteOperationCounter {
    fn id() -> &'static str {
        "plugin_write_operation_counter"
    }

    fn post_create(
        qs: &mut QueryServerWriteTransaction,
        // List of what we committed that was valid?
        _cand: &[EntrySealedCommitted],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::increase_write_ops_counter(qs);
        Ok(())
    }
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::increase_write_ops_counter(qs);
        Ok(())
    }

    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::increase_write_ops_counter(qs);
        Ok(())
    }

    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        // List of what we delete that was valid?
        _cand: &[EntrySealedCommitted],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Self::increase_write_ops_counter(qs);
        Ok(())
    }

    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        Self::reset_write_ops_counter(qs);
        Ok(())
    }

    fn post_repl_incremental_conflict(
        qs: &mut QueryServerWriteTransaction,
        _cand: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        _conflict_uuids: &mut BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        Self::reset_write_ops_counter(qs);
        Ok(())
    }

    fn post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        _cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        Self::reset_write_ops_counter(qs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[qs_test(domain_level=DOMAIN_LEVEL_7)]
    async fn entry_creation(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        server_txn.reset_write_ops_since_last_repl();

        // Test that the gid number is generated on create

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
        assert!(server_txn.commit().is_ok());

        let write_ops = server.read().await.get_write_ops_since_last_repl();

        assert_eq!(1, write_ops);
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_7)]
    async fn entry_update(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        // Test that the gid number is generated on create

        let user_a_uuid = uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244");
        let op_result = server_txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::PosixAccount.to_value()),
            (Attribute::Name, Value::new_iname("testperson_1")),
            (Attribute::Uuid, Value::Uuid(user_a_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        )]);

        server_txn.reset_write_ops_since_last_repl();

        assert!(op_result.is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;

        server_txn
            .internal_modify(
                &filter!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname("testperson_1")
                )),
                &modlist!([
                    m_purge(Attribute::Name),
                    m_pres(Attribute::Name, &Value::new_iname("new_name"))
                ]),
            )
            .expect("Failed to modify user");

        assert!(server_txn.commit().is_ok());

        let write_ops = server.read().await.get_write_ops_since_last_repl();

        assert_eq!(1, write_ops);
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_7)]
    async fn entry_delete(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;

        // Test that the gid number is generated on create

        let user_a_uuid = uuid!("83a0927f-3de1-45ec-bea0-2f7b997ef244");
        let op_result = server_txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::PosixAccount.to_value()),
            (Attribute::Name, Value::new_iname("testperson_1")),
            (Attribute::Uuid, Value::Uuid(user_a_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        )]);

        server_txn.reset_write_ops_since_last_repl();

        assert!(op_result.is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;

        server_txn
            .internal_delete(&filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson_1")
            )))
            .expect("Failed to modify user");

        assert!(server_txn.commit().is_ok());

        let write_ops = server.read().await.get_write_ops_since_last_repl();

        assert_eq!(1, write_ops);
    }
}
