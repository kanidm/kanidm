use crate::be::BackendTransaction;
use crate::prelude::*;
use crate::repl::consumer::ConsumerState;
use crate::repl::proto::ReplIncrementalContext;
use crate::repl::ruv::ReplicationUpdateVectorTransaction;
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
    assert!(a_ruv_range == b_ruv_range);
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
