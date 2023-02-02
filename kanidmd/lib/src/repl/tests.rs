use crate::prelude::*;

#[qs_pair_test]
async fn test_repl_refresh_basic(server_a: &QueryServer, server_b: &QueryServer) {
    // Rebuild / refresh the content of server a with the content from b.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await;

    let mut server_b_txn = server_b.read().await;

    // First, build the refresh context.
    let refresh_context = server_b_txn
        .supplier_provide_refresh()
        .expect("Failed to build refresh");

    // Verify content of the refresh

    // Apply it to the server
    assert!(server_a_txn
        .consumer_apply_refresh(&refresh_context)
        .is_ok());

    // Verify the content of server_a and server_b are identical.

    // Both servers will be post-test validated.
}
