use kanidm_client::KanidmClient;

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_service_account_id_attr_attr_delete(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // let post_body = serde_json::json!({"filter": "self"}).to_string();

    let response = match client
        .delete(rsclient.make_url("/v1/service_account/admin/_attr/email"))
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/service_account/admin/_attr/email"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}
