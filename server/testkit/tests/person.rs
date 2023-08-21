use kanidm_client::KanidmClient;
use kanidm_proto::constants::{APPLICATION_JSON, ATTR_EMAIL};
use reqwest::header::CONTENT_TYPE;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_person_patch(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let post_body = serde_json::json!({"attrs": { ATTR_EMAIL : "crab@example.com"}}).to_string();

    let response = match client
        .patch(rsclient.make_url("/v1/person/foo"))
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(post_body)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/person/foo"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 422);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}
