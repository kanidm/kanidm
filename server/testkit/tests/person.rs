use kanidm_client::KanidmClient;
use kanidm_proto::constants::ATTR_MAIL;
use kanidmd_testkit::{create_user, ADMIN_TEST_PASSWORD};
use serde_json::Value;

#[kanidmd_testkit::test]
async fn test_v1_person_id_patch(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(&rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!({"attrs": { ATTR_MAIL : ["crab@example.com"]}});

    let response: Value = match rsclient
        .perform_patch_request("/v1/person/foo", post_body)
        .await
    {
        Ok(val) => val,
        Err(err) => panic!("Failed to patch person: {:?}", err),
    };

    eprintln!("response: {:#?}", response);
}
