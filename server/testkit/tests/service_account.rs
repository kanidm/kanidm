use kanidm_client::KanidmClient;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_service_account_id_attr_attr_delete(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let addr = rsclient.get_url();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // let post_body = serde_json::json!({"filter": "self"}).to_string();

    let response = match client
        .delete(format!("{}/v1/service_account/admin/_attr/email", &addr))
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!("Failed to query {:?} : {:#?}", addr, error);
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}
