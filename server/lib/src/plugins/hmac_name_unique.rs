use crate::event::ReviveRecycledEvent;
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::valueset::ValueSetSha256;
use crypto_glue::{hmac_s256::HmacSha256, traits::Mac};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

pub struct HmacNameUnique {}

fn create_hmac_history(
    qs: &mut QueryServerWriteTransaction,
    cand: &mut [EntryInvalidNew],
) -> Result<(), OperationError> {
    let domain_level = qs.get_domain_version();
    if domain_level < DOMAIN_LEVEL_12 {
        trace!("Skipping hmac name history generation");
        return Ok(());
    }

    let hmac_name_history_config = qs.get_feature_hmac_name_history_config();

    if !hmac_name_history_config.enabled {
        debug!("hmac name history not enabled");
        return Ok(());
    }

    for entry in cand.iter_mut() {
        if entry.has_class(&EntryClass::Account) {
            let Some(entry_name) = entry.get_ava_single_iname(Attribute::Name) else {
                debug!(uuid = ?entry.get_uuid(), "Skipping entry without attribute name");
                continue;
            };

            let hmac_key = hmac_name_history_config.key.deref();
            let mut hmac = HmacSha256::new(hmac_key);
            hmac.update(entry_name.as_bytes());
            let name_hmac = hmac.finalize().into_bytes();

            let hmac_set = ValueSetSha256::new(name_hmac);
            entry.set_ava_set(&Attribute::HmacNameHistory, hmac_set);
        }
    }

    Ok(())
}

fn update_hmac_history(
    qs: &mut QueryServerWriteTransaction,
    pre_cand: &[Arc<EntrySealedCommitted>],
    cand: &mut [EntryInvalidCommitted],
) -> Result<(), OperationError> {
    let domain_level = qs.get_domain_version();
    if domain_level < DOMAIN_LEVEL_12 {
        trace!("Skipping hmac name history generation");
        return Ok(());
    }

    let hmac_name_history_config = qs.get_feature_hmac_name_history_config();

    if !hmac_name_history_config.enabled {
        debug!("hmac name history not enabled");
        return Ok(());
    }

    for (pre, post) in pre_cand.iter().zip(cand) {
        if post.has_class(&EntryClass::Account) {
            let pre_name_option = pre.get_ava_single_iname(Attribute::Name);
            let post_name_option = post.get_ava_single_iname(Attribute::Name);

            if let (Some(pre_name), Some(post_name)) = (pre_name_option, post_name_option) {
                if pre_name != post_name {
                    // Okay, update the hmacs now.

                    let hmac_key = hmac_name_history_config.key.deref();
                    let mut hmac = HmacSha256::new(hmac_key);
                    hmac.update(post_name.as_bytes());
                    let name_hmac = hmac.finalize().into_bytes();

                    if let Some(hmac_set) = post
                        .get_ava_mut(Attribute::HmacNameHistory)
                        .and_then(|s| s.as_s256_set_mut())
                    {
                        hmac_set.insert(name_hmac);
                    } else {
                        let hmac_set = ValueSetSha256::new(name_hmac);
                        post.set_ava_set(&Attribute::HmacNameHistory, hmac_set);
                    }
                }
            }
        }
    }

    Ok(())
}

fn build_memorials(
    qs: &mut QueryServerWriteTransaction,
    cand: &[Arc<EntrySealedCommitted>],
    memorials: &mut BTreeMap<Uuid, EntryInitNew>,
) -> Result<(), OperationError> {
    let domain_level = qs.get_domain_version();
    if domain_level < DOMAIN_LEVEL_12 {
        trace!("Skipping hmac name history generation");
        return Ok(());
    }

    let hmac_name_history_config = qs.get_feature_hmac_name_history_config();

    if !hmac_name_history_config.enabled {
        debug!("hmac name history not enabled");
        return Ok(());
    }

    for delete_cand in cand {
        if delete_cand.has_class(&EntryClass::Account) {
            if let Some(hmac_set) = delete_cand.get_ava_set(Attribute::HmacNameHistory) {
                // Okay, they have an hmac name set, so we either need to add it to an
                // inprogress memorial, or we need to make a new one.
                let memorial_entry = memorials
                    .entry(delete_cand.get_uuid())
                    .or_insert_with(EntryInitNew::default);
                memorial_entry.set_ava_set(&Attribute::HmacNameHistory, hmac_set.clone());
            }
        }
    }

    Ok(())
}

fn teardown_memorials(
    qs: &mut QueryServerWriteTransaction,
    memorial_pairs: &mut [(&EntrySealedCommitted, &mut EntryInvalidCommitted)],
) -> Result<(), OperationError> {
    let domain_level = qs.get_domain_version();
    if domain_level < DOMAIN_LEVEL_12 {
        trace!("Skipping hmac name history generation");
        return Ok(());
    }

    let hmac_name_history_config = qs.get_feature_hmac_name_history_config();

    if !hmac_name_history_config.enabled {
        debug!("hmac name history not enabled");
        return Ok(());
    }

    for (memorial, revived) in memorial_pairs.iter_mut() {
        if revived.has_class(&EntryClass::Account) {
            if let Some(hmac_set) = memorial.get_ava_set(Attribute::HmacNameHistory) {
                revived.set_ava_set(&Attribute::HmacNameHistory, hmac_set.clone());
            }
        }
    }

    Ok(())
}

impl HmacNameUnique {
    #[instrument(level = "debug", name = "hmac_name_unique::fixup", skip_all)]
    pub(crate) fn fixup(qs: &mut QueryServerWriteTransaction) -> Result<(), OperationError> {
        let domain_level = qs.get_domain_version();
        if domain_level < DOMAIN_LEVEL_12 {
            trace!("Skipping hmac name history generation");
            // should be IMPOSSIBLE to activate fixup from a lower domain level!!!
            debug_assert!(false);
            return Err(OperationError::KG005HowDidYouEvenManageThis);
        }

        let hmac_name_history_config_enabled = qs.get_feature_hmac_name_history_config().enabled;

        if !hmac_name_history_config_enabled {
            debug!("hmac name history not enabled");
            // should be IMPOSSIBLE to activate fixup when the feature is disabled!!!
            debug_assert!(false);
            return Err(OperationError::KG005HowDidYouEvenManageThis);
        }

        // Delete any remaining HMAC memorials.
        let filt = filter!(f_eq(Attribute::Class, EntryClass::Memorial.into()));
        let modlist = ModifyList::new_purge(Attribute::HmacNameHistory);
        qs.internal_modify(&filt, &modlist)?;

        let filt = filter!(f_eq(Attribute::Class, EntryClass::Account.into()));
        let mut work_set = qs.internal_search_writeable(&filt)?;

        let hmac_name_history_config = qs.get_feature_hmac_name_history_config();

        for (_pre, entry) in work_set.iter_mut() {
            let Some(entry_name) = entry.get_ava_single_iname(Attribute::Name) else {
                debug!(uuid = ?entry.get_uuid(), "Skipping entry without attribute name");
                continue;
            };

            let hmac_key = hmac_name_history_config.key.deref();
            let mut hmac = HmacSha256::new(hmac_key);
            hmac.update(entry_name.as_bytes());
            let name_hmac = hmac.finalize().into_bytes();

            let hmac_set = ValueSetSha256::new(name_hmac);
            // Just stomp whatever value was there.
            entry.set_ava_set(&Attribute::HmacNameHistory, hmac_set);
        }

        qs.internal_apply_writable(work_set).inspect_err(|err| {
            error!(?err, "Failed to commit memberof group set");
        })
    }
}

impl Plugin for HmacNameUnique {
    fn id() -> &'static str {
        "plugin_hmac_name_unique"
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        create_hmac_history(qs, cand)
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        update_hmac_history(qs, pre_cand, cand)
    }

    #[instrument(level = "debug", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        update_hmac_history(qs, pre_cand, cand)
    }

    #[instrument(level = "debug", skip_all)]
    fn build_memorials(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Arc<EntrySealedCommitted>],
        memorials: &mut BTreeMap<Uuid, EntryInitNew>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        build_memorials(qs, cand, memorials)
    }

    #[instrument(level = "debug", skip_all)]
    fn teardown_memorials(
        qs: &mut QueryServerWriteTransaction,
        memorial_pairs: &mut [(&EntrySealedCommitted, &mut EntryInvalidCommitted)],
        _re: &ReviveRecycledEvent,
    ) -> Result<(), OperationError> {
        teardown_memorials(qs, memorial_pairs)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::valueset::ValueSetIname;

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

        // First check there are no HMAC's before we enable the feature
        let mut server_txn = server.write(curtime).await.unwrap();

        let entry_1 = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let entry_2 = server_txn
            .internal_search_uuid(uuid_e2)
            .expect("Unable to access entry 2");

        assert!(entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .is_none());

        assert!(entry_2
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .is_none());

        drop(server_txn);

        // Enable the feature
        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_modify_uuid(
                UUID_HMAC_NAME_FEATURE,
                &ModifyList::new_set(Attribute::Enabled, ValueSetBool::new(true)),
            )
            .expect("Unable to activate hmac name history feature");

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

        let result = server_txn
            .internal_modify_uuid(uuid_e2, &modlist)
            .expect_err("Should not succeed!");

        assert!(matches!(result, OperationError::AttributeUniqueness));

        // But the first CAN go back to it's original name.
        server_txn
            .internal_modify_uuid(uuid_e1, &modlist)
            .expect("Unable to update users name");

        server_txn.commit().expect("Unable to commit");
    }

    #[qs_test]
    async fn hmac_name_unique_beyond_the_grave(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_modify_uuid(
                UUID_HMAC_NAME_FEATURE,
                &ModifyList::new_set(Attribute::Enabled, ValueSetBool::new(true)),
            )
            .expect("Unable to activate hmac name history feature");

        server_txn.commit().expect("Unable to commit");

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

        let result = server_txn
            .internal_create(vec![e2.clone()])
            .expect_err("Should not be able to create the entry");

        assert!(matches!(result, OperationError::AttributeUniqueness));

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

        let result = server_txn
            .internal_create(vec![e2])
            .expect_err("Should not be able to create the entry");

        assert!(matches!(result, OperationError::AttributeUniqueness));
    }

    #[qs_test]
    async fn hmac_name_unique_revive_merge(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut server_txn = server.write(curtime).await.unwrap();

        server_txn
            .internal_modify_uuid(
                UUID_HMAC_NAME_FEATURE,
                &ModifyList::new_set(Attribute::Enabled, ValueSetBool::new(true)),
            )
            .expect("Unable to activate hmac name history feature");

        server_txn.commit().expect("Unable to commit");

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
        let mut server_txn = server.write(curtime).await.unwrap();

        let filter = filter!(f_eq(Attribute::InMemoriam, PartialValue::Uuid(uuid_e1)));

        let memorial = server_txn
            .internal_search(filter)
            .expect("Unable to access entry 1")
            .pop()
            .expect("No results were returned!");

        let memorial_uuid = memorial.get_uuid();

        let hmac_name_history_1_memorial = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        // Revive
        server_txn
            .internal_revive_uuid(uuid_e1)
            .expect("Unable to revive the entry");

        // Now check the related entry is gone.
        assert!(!server_txn
            .internal_exists_uuid(memorial_uuid)
            .expect("Unable to complete exists query"));

        // The hmac values are back in the entry.
        let entry_1 = server_txn
            .internal_search_uuid(uuid_e1)
            .expect("Unable to access entry 1");

        let hmac_name_history_1_step_3 = entry_1
            .get_ava_as_s256_set(Attribute::HmacNameHistory)
            .expect("No name history recorded");

        assert_eq!(hmac_name_history_1_step_1, hmac_name_history_1_step_3);
        assert_eq!(hmac_name_history_1_step_1, hmac_name_history_1_memorial);

        server_txn.commit().expect("Unable to commit");
    }
}
