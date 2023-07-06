use crate::be::BackendTransaction;
use crate::prelude::*;
use crate::repl::consumer::ConsumerState;
use crate::repl::entry::State;
use crate::repl::proto::ReplIncrementalContext;
use crate::repl::ruv::ReplicationUpdateVectorTransaction;
use crate::repl::ruv::{RangeDiffStatus, ReplicationUpdateVector};
use std::collections::BTreeMap;

fn repl_initialise(
    from: &mut QueryServerReadTransaction<'_>,
    to: &mut QueryServerWriteTransaction<'_>,
) -> Result<(), OperationError> {
    // First, build the refresh context.
    let refresh_context = from.supplier_provide_refresh()?;

    // Verify content of the refresh
    // eprintln!("{:#?}", refresh_context);

    // Apply it to the server
    to.consumer_apply_refresh(&refresh_context)?;

    // Need same d_uuid
    assert_eq!(from.get_domain_uuid(), to.get_domain_uuid());

    // Ruvs are the same now
    let a_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range == b_ruv_range);

    Ok(())
}

fn repl_incremental(
    from: &mut QueryServerReadTransaction<'_>,
    to: &mut QueryServerWriteTransaction<'_>,
) {
    let a_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range from");
    let b_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range to");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    // Now setup the consumer state for the next incremental replication.
    let a_ruv_range = to.consumer_get_state().expect("Unable to access RUV range");

    // Incremental.
    // Should now be on the other partner.

    // Get the changes.
    let changes = from
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    // Check the changes = should be empty.
    to.consumer_apply_changes(&changes)
        .expect("Unable to apply changes to consumer.");

    // RUV should be consistent again.
    let a_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);

    // May need to be "is subset" for future when we are testing
    // some more complex scenarioes.
    let valid = match ReplicationUpdateVector::range_diff(&a_ruv_range, &b_ruv_range) {
        RangeDiffStatus::Ok(require) => require.is_empty(),
        _ => false,
    };
    assert!(valid);
}

#[qs_pair_test]
async fn test_repl_refresh_basic(server_a: &QueryServer, server_b: &QueryServer) {
    // Rebuild / refresh the content of server a with the content from b.

    // To ensure we have a spectrum of content, we do some setup here such as creating
    // tombstones.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    // Verify the content of server_a and server_b are identical.
    let mut server_a_txn = server_a.read().await;

    let domain_entry_a = server_a_txn
        .internal_search_uuid(UUID_DOMAIN_INFO)
        .expect("Failed to access domain info");

    let domain_entry_b = server_b_txn
        .internal_search_uuid(UUID_DOMAIN_INFO)
        .expect("Failed to access domain info");

    // Same d_vers / domain info.
    assert_eq!(domain_entry_a, domain_entry_b);

    trace!(
        "domain_changestate a {:#?}",
        domain_entry_a.get_changestate()
    );
    trace!(
        "domain_changestate b {:#?}",
        domain_entry_b.get_changestate()
    );

    // Compare that their change states are identical too.
    assert_eq!(
        domain_entry_a.get_changestate(),
        domain_entry_b.get_changestate()
    );

    // There is some metadata here we should also consider testing such as key
    // reloads? These are done at the IDM level, but this is QS level, so do we need to change
    // these tests? Or should they be separate repl tests later?
    assert_eq!(*server_a_txn.d_info, *server_b_txn.d_info);

    // Now assert everything else in the db matches.

    let entries_a = server_a_txn
        .internal_search(filter_all!(f_pres("class")))
        .map(|ents| {
            ents.into_iter()
                .map(|e| (e.get_uuid(), e))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("Failed to access all entries");

    let entries_b = server_a_txn
        .internal_search(filter_all!(f_pres("class")))
        .map(|ents| {
            ents.into_iter()
                .map(|e| (e.get_uuid(), e))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("Failed to access all entries");

    // Basically do a select * then put into btreemaps and compare them all.

    // Need to have the same length!
    assert_eq!(entries_a.len(), entries_b.len());

    // We don't use the uuid-keys here since these are compared internally, they are
    // just to sort the two sets.
    std::iter::zip(entries_a.values(), entries_b.values()).for_each(|(ent_a, ent_b)| {
        assert_eq!(ent_a, ent_b);
        assert_eq!(ent_a.get_changestate(), ent_b.get_changestate());
    });

    // Done! The entry content are identical as are their replication metadata. We are good
    // to go!

    // Both servers will be post-test validated.
}

// Test that adding an entry to one side replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_add(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    //  - incremental - no changes should be present
    let mut server_a_txn = server_a.read().await;
    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");
    // End the read.
    drop(server_a_txn);

    // Get the changes.
    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    // Check the changes = should be empty.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    server_a_txn
        .consumer_apply_changes(&changes)
        .expect("Unable to apply changes to consumer.");

    // Do a ruv check - should still be the same.
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range == b_ruv_range);

    server_a_txn.commit().expect("Failed to commit");

    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.read().await;

    // Assert the entry is not on A.
    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    // Now setup the consumer state for the next incremental replication.
    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");
    // End the read.
    drop(server_a_txn);

    // Incremental.
    // Should now be on the other partner.

    // Get the changes.
    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    // Check the changes = should be empty.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    server_a_txn
        .consumer_apply_changes(&changes)
        .expect("Unable to apply changes to consumer.");

    // RUV should be consistent again.
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range == b_ruv_range);

    // Assert the entry is now present, and the same on both sides
    let e1 = server_a_txn
        .internal_search_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry to one side, then recycling it replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_recycle(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry to one side, then recycling it, and tombstoning it
// replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_tombstone(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await;
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality("class", &PVCLASS_TOMBSTONE));

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry -> tombstone then the tombstone is trimmed raises
// a replication error.
#[qs_pair_test]
async fn test_repl_increment_consumer_lagging_tombstone(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await;
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the tombstone trim time.
    let ct = ct + Duration::from_secs(CHANGELOG_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await;
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A *or* B.

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );
    assert_eq!(
        server_b_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    // The ruvs must be different
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    assert!(matches!(changes, ReplIncrementalContext::RefreshRequired));

    let result = server_a_txn
        .consumer_apply_changes(&changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::RefreshRequired));

    drop(server_a_txn);
    drop(server_b_txn);
}

// Write state cases.

// Create Entry an B -> A
// Write to A
// A -> B becomes consistent.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_write(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    // Now perform a write on A
    assert!(server_a_txn
        .internal_modify_uuid(t_uuid, &ModifyList::new_purge("description"))
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Incremental repl in the reverse direction.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;

    //               from               to
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert!(e1 == e2);
    assert!(e1.get_ava_set("description").is_none());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Create Entry on A -> B
// Write to both
// B -> A and A -> B become consistent.

#[qs_pair_test]
async fn test_repl_increment_simultaneous_bidirectional_write(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    // Now perform a write on A
    assert!(server_a_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set("description", Value::new_utf8s("repl_test"))
        )
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Also write to B.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    assert!(server_b_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set("displayname", Value::new_utf8s("repl_test"))
        )
        .is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // Incremental repl in the both directions.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;
    //               from               to
    repl_incremental(&mut server_a_txn, &mut server_b_txn);
    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;
    let mut server_b_txn = server_b.read().await;
    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);
    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Validate they are the same again.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.read().await;

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert!(e1 == e2);
    assert!(e1.get_ava_single_utf8("description") == Some("repl_test"));
    assert!(e1.get_ava_single_utf8("displayname") == Some("repl_test"));
}

// Create entry on A -> B
// Recycle
// Recycle propagates from A -> B
// TS on B
// B -> A TS

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_lifecycle(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Delete on A
    let mut server_a_txn = server_a.write(ct).await;
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Repl A -> B
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(ct).await;

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert!(e1 == e2);
    assert!(e1.attribute_equality("class", &PVCLASS_RECYCLED));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // At an earlier time make a change on A.
    let mut server_a_txn = server_a.write(ct).await;
    assert!(server_a_txn.internal_revive_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    // Now TS on B.
    let mut server_b_txn = server_b.write(ct).await;
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Repl A -> B - B will silently reject the update due to the TS state on B.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(ct).await;

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are NOT consistent.
    assert!(e1 != e2);
    // E1 from A is NOT a tombstone ... yet.
    assert!(!e1.attribute_equality("class", &PVCLASS_TOMBSTONE));
    // E2 from B is a tombstone!
    assert!(e2.attribute_equality("class", &PVCLASS_TOMBSTONE));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Repl B -> A - will have a TS at the end.
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // Ts on both.
    assert!(e1.attribute_equality("class", &PVCLASS_TOMBSTONE));
    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Create entry on A -> B
// Recycle on Both A/B
// Recycle propagates from A -> B, B -> A, keep latest.
// We already know the recycle -> ts state is good from other tests.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_recycle(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // On both servers, at separate timestamps, run the recycle.
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.write(ct).await;
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let ct = ct + Duration::from_secs(2);
    let mut server_b_txn = server_b.write(ct).await;
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Send server a -> b - ignored.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(ct).await;

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // They are equal, but their CL states are not. e2 should have been
    // retained due to being the latest!
    assert!(e1 == e2);
    assert!(e1.attribute_equality("class", &PVCLASS_RECYCLED));

    // Remember entry comparison doesn't compare last_mod_cid.
    assert!(e1.get_last_changed() < e2.get_last_changed());

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    let valid = match (e1_cs.current(), e2_cs.current()) {
        (
            State::Live {
                at: _,
                changes: changes_left,
            },
            State::Live {
                at: _,
                changes: changes_right,
            },
        ) => match (changes_left.get("class"), changes_right.get("class")) {
            (Some(cid_left), Some(cid_right)) => cid_left < cid_right,
            _ => false,
        },
        _ => false,
    };
    assert!(valid);

    // Now go the other way. They'll be equal again.
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert!(e1_cs == e2_cs);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Create + recycle entry on B -> A
// TS on Both,
// TS resolves to lowest AT.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_tombstone(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_b_txn = server_b.write(ct).await;
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(t_uuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    // And then recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now setup repl
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1 == e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now on both servers, perform a recycle -> ts at different times.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);
    let mut server_a_txn = server_a.write(ct).await;
    assert!(server_a_txn.purge_recycled().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let ct = ct + Duration::from_secs(1);
    let mut server_b_txn = server_b.write(ct).await;
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now do B -> A - no change on A as it's TS was earlier.
    let mut server_a_txn = server_a.write(ct).await;
    let mut server_b_txn = server_b.read().await;

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality("class", &PVCLASS_TOMBSTONE));
    assert!(e2.attribute_equality("class", &PVCLASS_TOMBSTONE));
    trace!("{:?}", e1.get_last_changed());
    trace!("{:?}", e2.get_last_changed());
    assert!(e1.get_last_changed() < e2.get_last_changed());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // A -> B - B should now have the A TS time.
    let mut server_a_txn = server_a.read().await;
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await;

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality("class", &PVCLASS_TOMBSTONE));
    assert!(e2.attribute_equality("class", &PVCLASS_TOMBSTONE));
    assert!(e1.get_last_changed() == e2.get_last_changed());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// conflict cases.

// both add entry with same uuid - only one can win!

// both add entry with same uuid, but one becomes ts - ts always wins.

// both add entry with same uuid, both become ts - merge, take lowest AT.

// Test RUV content when a server's changes have been trimmed out and are not present
// in a refresh. This is not about tombstones, this is about attribute state.

// Test change of a domain name over incremental.

// Test schema addition / change over incremental.

// Test change of domain version over incremental.

// Test when a group has a member A, and then the group is conflicted, that when
// group is moved to conflict the memberShip of A is removed.

// Multiple tombstone states / directions.

// Ref int deletes references when tombstone is replicated over. May need consumer
// to have some extra groups that need cleanup

// Test add then delete on an attribute, and that it replicates the empty state to
// the other side.

// Test memberof over replication boundaries.
