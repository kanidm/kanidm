use kanidm_client::{ClientError, KanidmClient, StatusCode};
use kanidm_proto::constants::ATTR_MAIL;
use kanidmd_testkit::{create_user, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use serde_json::Value;

#[kanidmd_testkit::test]
async fn test_v1_person_id_patch(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!({"attrs": { ATTR_MAIL : ["crab@example.com"]}});

    let response: Value = match rsclient
        .perform_patch_request("/v1/person/foo", post_body)
        .await
    {
        Ok(val) => val,
        Err(err) => panic!("Failed to patch person: {err:?}"),
    };
    eprintln!("response: {response:#?}");
}

#[kanidmd_testkit::test]
async fn test_v1_person_id_ssh_pubkeys_post(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!([
        "ssh-key-tag-goes-here",
        "ed25519 im_a_real_ssh_public_key_just_trust_me comment"
    ]);

    let response: ClientError = match rsclient
        .perform_post_request::<serde_json::Value, String>("/v1/person/foo/_ssh_pubkeys", post_body)
        .await
    {
        Ok(val) => panic!("Expected failure to post person ssh pubkeys: {val:?}"),
        Err(err) => err,
    };
    eprintln!("response: {response:#?}");
    assert!(matches!(
        response,
        ClientError::Http(StatusCode::BAD_REQUEST, _, _)
    ));
}

#[kanidmd_testkit::test]
async fn test_v1_person_ssh_pubkey_space_tag_lifecycle(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(rsclient, "foo", "foogroup").await;

    let tag = "Yk 5 Nfc";
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst";

    let add = rsclient
        .idm_person_account_post_ssh_pubkey("foo", tag, key)
        .await;
    assert!(add.is_ok(), "add failed: {add:?}");

    let got = rsclient.idm_account_get_ssh_pubkey("foo", tag).await.unwrap();
    assert_eq!(got, Some(key.to_string()));

    let del = rsclient
        .idm_person_account_delete_ssh_pubkey("foo", tag)
        .await;
    assert!(del.is_ok(), "delete failed: {del:?}");

    let got_after_delete = rsclient.idm_account_get_ssh_pubkey("foo", tag).await.unwrap();
    assert_eq!(got_after_delete, None);
}
