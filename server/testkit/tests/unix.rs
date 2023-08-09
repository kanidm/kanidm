use kanidm_client::KanidmClient;
use kanidmd_testkit::*;

#[kanidmd_testkit::test]
async fn account_id_unix_token(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, "group_manager", "idm_group_manage_priv").await;
    // create test user without creating new groups
    create_user(&rsclient, NOT_ADMIN_TEST_USERNAME, "idm_admins").await;
    login_account(&rsclient, "group_manager").await;

    let response = rsclient
        .idm_account_unix_token_get(NOT_ADMIN_TEST_USERNAME)
        .await;
    assert!(response.is_err());
    if let Err(val) = response {
        assert!(format!("{:?}", val).contains("404"));
    }

    let response = rsclient.idm_account_unix_token_get("lol").await;
    assert!(response.is_err());
    if let Err(val) = response {
        assert!(format!("{:?}", val).contains("404"));
    }

    // testing empty results
    let response = rsclient.idm_account_unix_token_get("").await;
    assert!(response.is_err());
    if let Err(val) = response {
        assert!(format!("{:?}", val).contains("400"));
    }

    login_put_admin_idm_admins(&rsclient).await;

    rsclient
        .idm_person_account_unix_extend(NOT_ADMIN_TEST_USERNAME, None, None)
        .await
        .unwrap();

    // testing NOT_ADMIN_TEST_USERNAME has a token result, since we just added one
    assert!(rsclient
        .idm_account_unix_token_get(NOT_ADMIN_TEST_USERNAME)
        .await
        .is_ok());
}
