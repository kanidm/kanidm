use crate::be::BackendTransaction;
use crate::prelude::*;
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

    Ok(())
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
    let a_ruv_range = server_a_txn.get_be_txn().get_ruv().current_ruv_range();

    let b_ruv_range = server_b_txn.get_be_txn().get_ruv().current_ruv_range();

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range == b_ruv_range);

    // Both servers will be post-test validated.
}

#[qs_pair_test]
async fn test_repl_increment_basic(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    let mut server_b_txn = server_b.read().await;

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    let a_ruv_range = server_a_txn.get_be_txn().get_ruv().current_ruv_range();

    let b_ruv_range = server_b_txn.get_be_txn().get_ruv().current_ruv_range();

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range == b_ruv_range);

    // Check ruv
    //  - should be same
    //  - incremental
    //      - no change.

    // Add an entry.

    // Do a ruv check.

    // Incremental.
    // Should now be on the other partner.
}
