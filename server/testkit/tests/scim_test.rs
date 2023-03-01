use kanidm_client::KanidmClient;
use kanidmd_testkit::ADMIN_TEST_PASSWORD;

#[kanidmd_testkit::test]
async fn test_sync_account_lifecycle(rsclient: KanidmClient) {
    let a_res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(a_res.is_ok());

    let a_list = rsclient.idm_sync_account_list().await.unwrap();
    assert!(a_list.is_empty());

    rsclient
        .idm_sync_account_create("ipa_sync_account", Some("Demo of a sync account"))
        .await
        .unwrap();

    let a_list = rsclient.idm_sync_account_list().await.unwrap();
    assert!(!a_list.is_empty());

    let a = rsclient
        .idm_sync_account_get("ipa_sync_account")
        .await
        .unwrap();
    assert!(a.is_some());
    println!("{:?}", a);

    // Get a token

    // List sessions?

    // Reset Sign Key
    // Get New token

    // Get sync state

    // Delete session

    // Sync state fails.

    // Delete account
}
