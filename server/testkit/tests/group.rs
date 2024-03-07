use kanidm_client::KanidmClient;
use kanidm_proto::constants::ATTR_DESCRIPTION;
use kanidmd_testkit::{create_user, ADMIN_TEST_PASSWORD};
use serde_json::Value;

#[kanidmd_testkit::test]
async fn test_v1_group_id_patch(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(&rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!({"attrs": { ATTR_DESCRIPTION : ["Fancy group change"]}});

    let response: Value = match rsclient
        .perform_patch_request("/v1/group/foogroup", post_body)
        .await
    {
        Ok(val) => val,
        Err(err) => panic!("Failed to patch group: {:?}", err),
    };
    eprintln!("response: {:#?}", response);
}
