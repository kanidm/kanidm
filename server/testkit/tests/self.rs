use kanidm_client::KanidmClient;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_self_applinks(rsclient: KanidmClient) {
    // TODO: #1787 applinks_get GET /v1/self/_applinks
    // We need to do manual reqwests here.
    let addr = rsclient.get_url();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // let post_body = serde_json::json!({"attrs": { "email" : "crab@example.com"}}).to_string();

    let response = match client
        .get(format!("{}/v1/self/_applinks", &addr))
        // .body(post_body)
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
// TODO: #1787 service_account_id_delete

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_self_whoami_uat(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let addr = rsclient.get_url();
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client.get(format!("{}/v1/self/_uat", &addr)).send().await {
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
