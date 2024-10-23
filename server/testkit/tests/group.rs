use kanidm_client::{ClientError, KanidmClient};
use kanidm_proto::constants::ATTR_DESCRIPTION;
use kanidmd_lib::idm::group::Group;
use kanidmd_testkit::{create_user, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use serde_json::Value;

#[kanidmd_testkit::test]
async fn test_v1_group_id_patch(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
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

#[kanidmd_testkit::test]
async fn test_v1_group_id_attr_post(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(&rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!(["foo"]);

    let response: ClientError = match rsclient
        .perform_post_request::<serde_json::Value, String>(
            "/v1/group/foogroup/_attr/member2",
            post_body,
        )
        .await
    {
        Ok(val) => panic!("Expected failure to post group attribute: {:?}", val),
        Err(err) => err,
    };
    eprintln!("response: {:#?}", response);
    assert!(matches!(
        response,
        ClientError::Http(reqwest::StatusCode::BAD_REQUEST, _, _)
    ));
}
