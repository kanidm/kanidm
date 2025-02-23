use kanidm_client::KanidmClient;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_system_post_attr(rsclient: KanidmClient) {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client
        .post(rsclient.make_url("/v1/system/_attr/domain_name"))
        .json(&serde_json::json!({"filter": "self"}))
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("v1/system/_attr/domain_name"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 422);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}
