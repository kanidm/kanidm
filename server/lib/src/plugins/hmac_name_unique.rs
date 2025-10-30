use crate::plugins::Plugin;
use crate::prelude::*;
use std::sync::Arc;

pub struct HmacNameUnique {}

impl Plugin for HmacNameUnique {
    fn id() -> &'static str {
        "plugin_hmac_name_unique"
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // Self::handle_name_creation(cand, qs.get_txn_cid())
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        // Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
        Ok(())
    }

    #[instrument(level = "debug", name = "refint_post_delete", skip_all)]
    fn post_delete(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // What to do about deletes? We also need to consider what happens with an
        // entry revive?

        // on-delete -> make an hmac-tombstone.

        // on-revive -> merge back into the origin entry.

        // We also need an on-revive handle

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::valueset::ValueSetIname;

    // Do I need a migration to update all the hmac values of existing names?
    // Probably yes?

    #[qs_test]
    async fn hmac_name_unique_basic(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        // Create person x2
        let uuid_e1 = Uuid::new_v4();
        let uuid_e2 = Uuid::new_v4();

        let e1: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e1)),
            (Attribute::Name, Value::new_iname("test_person_1")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 1"))
        );

        let e2: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e2)),
            (Attribute::Name, Value::new_iname("test_person_2")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 2"))
        );

        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_create(vec![e1, e2])
            .expect("Unable to create test entries");

        server_txn.commit().expect("Unable to commit");

        // They should have an hmac of the name?
        let mut server_txn = server.write(curtime).await.unwrap();

        let entry_1 = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let entry_2 = server_txn
            .internal_search_uuid(uuid_e2)
            .expect("Unable to access entry 2");

        let hmac_name_history_1 = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        let hmac_name_history_2 = entry_2
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        assert_eq!(hmac_name_history_1.len(), 1);
        assert_eq!(hmac_name_history_2.len(), 1);
        assert_ne!(hmac_name_history_1, hmac_name_history_2);

        // Change the name
        let new_name = ValueSetIname::new("test_person_name_update");
        let modlist = ModifyList::new_set(Attribute::Name, new_name);

        server_txn
            .internal_modify_uuid(uuid_e1, &modlist)
            .expect("Unable to update users name");

        // They now have two hmacs
        let entry_1_update = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let hmac_name_history_1_update = entry_1_update
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        assert_eq!(hmac_name_history_1_update.len(), 2);
        assert_ne!(hmac_name_history_1_update, hmac_name_history_1);
        assert_ne!(hmac_name_history_1_update, hmac_name_history_2);

        // But the new update is a superset of the previous history.
        assert!(hmac_name_history_1_update.is_superset(hmac_name_history_1));

        // Enable the feature.
        server_txn.reload().expect("Unable to reload");

        // The second account can't change to an older name of the first account
        // even though it's available right now.
        let new_name = ValueSetIname::new("test_person_1");
        let modlist = ModifyList::new_set(Attribute::Name, new_name);

        let _result = server_txn
            .internal_modify_uuid(uuid_e2, &modlist)
            .expect_err("Should not succeed!");

        // Assert the result
        assert!(false);

        // But the first CAN go back to it's original name.
        server_txn
            .internal_modify_uuid(uuid_e1, &modlist)
            .expect("Unable to update users name");

        server_txn.commit().expect("Unable to commit");
    }

    // Test that if we have two accounts that both flip-flop on a name, once the feature turns
    // on, neither can claim it again.
    #[qs_test]
    async fn hmac_name_unique_flip_flop(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        // Create person x2
        let uuid_e1 = Uuid::new_v4();
        let uuid_e2 = Uuid::new_v4();

        let e1: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e1)),
            (Attribute::Name, Value::new_iname("test_person_1")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 1"))
        );

        let e2: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e2)),
            (Attribute::Name, Value::new_iname("test_person_2")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 2"))
        );

        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_create(vec![e1, e2])
            .expect("Unable to create test entries");

        server_txn.commit().expect("Unable to commit");

        let mut server_txn = server.write(curtime).await.unwrap();

        let new_name = ValueSetIname::new("test_person_1");
        let modlist_name_1 = ModifyList::new_set(Attribute::Name, new_name);

        let new_name = ValueSetIname::new("test_person_2");
        let modlist_name_2 = ModifyList::new_set(Attribute::Name, new_name);

        let new_name = ValueSetIname::new("test_person_name_update");
        let modlist_name_update = ModifyList::new_set(Attribute::Name, new_name);

        server_txn
            .internal_modify_uuid(uuid_e1, &modlist_name_update)
            .expect("Unable to update users name");

        server_txn
            .internal_modify_uuid(uuid_e1, &modlist_name_1)
            .expect("Unable to update users name");

        server_txn
            .internal_modify_uuid(uuid_e2, &modlist_name_update)
            .expect("Unable to update users name");

        server_txn
            .internal_modify_uuid(uuid_e2, &modlist_name_2)
            .expect("Unable to update users name");

        // Enable the feature.
        server_txn.reload().expect("Unable to reload");

        // Now none of you can have it.
        let _result = server_txn
            .internal_modify_uuid(uuid_e1, &modlist_name_update)
            .expect_err("Should not succeed!");

        let _result = server_txn
            .internal_modify_uuid(uuid_e2, &modlist_name_update)
            .expect_err("Should not succeed!");

        server_txn.commit().expect("Unable to commit");
    }

    #[qs_test]
    async fn hmac_name_unique_beyond_the_grave(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        // Create person x2
        let uuid_e1 = Uuid::new_v4();

        let e1: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e1)),
            (Attribute::Name, Value::new_iname("test_person")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 1"))
        );

        let mut server_txn = server.write(curtime).await.unwrap();

        // TURN ON the hmac feature here.
        assert!(false);

        server_txn
            .internal_create(vec![e1])
            .expect("Unable to create test entries");

        server_txn.commit().expect("Unable to commit");

        // Now, we delete the person
        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_delete_uuid(uuid_e1)
            .expect("Unable to delete entry");

        server_txn.commit().expect("Unable to commit");

        // Now it's deleted, the new create will FAIL
        let mut server_txn = server.write(curtime).await.unwrap();

        let uuid_e2 = Uuid::new_v4();
        let e2: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e2)),
            (Attribute::Name, Value::new_iname("test_person")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 2"))
        );

        let _result = server_txn
            .internal_create(vec![e2.clone()])
            .expect_err("Should not be able to create the entry");
        // check the result

        drop(server_txn);

        // Move past the recyclebin window
        let curtime = curtime + Duration::from_secs(CHANGELOG_MAX_AGE + 1);

        let mut server_txn = server.write(curtime).await.unwrap();
        assert!(server_txn.purge_recycled().is_ok());

        server_txn.commit().expect("Unable to commit");

        // Now, the tombstone will exist, but so should our marker entry
        // that carries the hmacs. As a result, we still can't create the
        // conflicting entry.

        let mut server_txn = server.write(curtime).await.unwrap();

        let _result = server_txn
            .internal_create(vec![e2])
            .expect_err("Should not be able to create the entry");
    }

    #[qs_test]
    async fn hmac_name_unique_revive_merge(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        // Create person
        let uuid_e1 = Uuid::new_v4();

        let e1: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid_e1)),
            (Attribute::Name, Value::new_iname("test_person")),
            (Attribute::DisplayName, Value::new_utf8s("Test Person 1"))
        );

        let mut server_txn = server.write(curtime).await.unwrap();

        // TURN ON the hmac feature here.
        assert!(false);

        server_txn
            .internal_create(vec![e1])
            .expect("Unable to create test entries");

        server_txn.commit().expect("Unable to commit");

        // Now, we delete the person
        let mut server_txn = server.write(curtime).await.unwrap();

        // Stash their history.
        let entry_1 = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let hmac_name_history_1_step_1 = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        server_txn
            .internal_delete_uuid(uuid_e1)
            .expect("Unable to delete entry");

        server_txn.commit().expect("Unable to commit");

        // Now check that the hmac entry exists
        // query for something that related?

        let mut server_txn = server.write(curtime).await.unwrap();

        assert!(false);

        let filter = filter!(f_eq(Attribute::Name, PartialValue::Uuid(uuid_e1)));

        let entry_1 = server_txn
            .internal_search(filter)
            .expect("Unable to access entry 1")
            .pop()
            .expect("No results were returned!");

        let hmac_name_history_1_step_2 = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        // Revive
        server_txn
            .internal_revive_uuid(uuid_e1)
            .expect("Unable to revive the entry");

        // Now check the related entry is gone.

        // The hmac values are back in the entry.
        let entry_1 = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let hmac_name_history_1_step_3 = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        assert_eq!(hmac_name_history_1_step_1, hmac_name_history_1_step_3);
        assert_eq!(hmac_name_history_1_step_1, hmac_name_history_1_step_2);

        server_txn.commit().expect("Unable to commit");
    }
}
