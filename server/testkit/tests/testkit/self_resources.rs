use kanidm_client::KanidmClient;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_self_applinks(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client
        .get(rsclient.make_url("/v1/self/_applinks"))
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/self/_applinks"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_self_whoami_uat(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client.get(rsclient.make_url("/v1/self/_uat")).send().await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/self/_uat"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}
