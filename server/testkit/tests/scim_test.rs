use compact_jwt::JwsUnverified;
use kanidm_client::KanidmClient;
use kanidm_proto::v1::ApiToken;
use kanidmd_testkit::ADMIN_TEST_PASSWORD;
use std::str::FromStr;
use url::Url;

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

    println!("{:?}", a);
    let sync_entry = a.expect("No sync account was created?!");

    // Shouldn't have a cred portal.
    assert!(!sync_entry.attrs.contains_key("sync_credential_portal"));

    let url = Url::parse("https://sink.ipa.example.com/reset").unwrap();

    // Set our credential portal.
    rsclient
        .idm_sync_account_set_credential_portal("ipa_sync_account", Some(&url))
        .await
        .unwrap();

    let a = rsclient
        .idm_sync_account_get("ipa_sync_account")
        .await
        .unwrap();

    let sync_entry = a.expect("No sync account present?");
    // Should have a cred portal.
    assert!(sync_entry.attrs.contains_key("sync_credential_portal"));

    // Get a token
    let token = rsclient
        .idm_sync_account_generate_token("ipa_sync_account", "token_label")
        .await
        .expect("Failed to generate token");

    let token_unverified = JwsUnverified::from_str(&token).expect("Failed to parse apitoken");

    let token: ApiToken = token_unverified
        .validate_embeded()
        .map(|j| j.into_inner())
        .expect("Embedded jwk not found");

    println!("{:?}", token);

    rsclient
        .idm_sync_account_destroy_token("ipa_sync_account")
        .await
        .expect("Failed to destroy token");
}
