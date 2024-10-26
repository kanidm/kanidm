use kanidm_client::KanidmClient;

#[kanidmd_testkit::test]
async fn test_https_manifest(rsclient: KanidmClient) {
    // We need to do manual reqwests here.

    // here we test the /ui/ endpoint which should have the headers
    let response = match reqwest::get(rsclient.make_url("/manifest.webmanifest")).await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/manifest.webmanifest"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 404);

    eprintln!(
        "csp headers: {:#?}",
        response
            .headers()
            .get(http::header::CONTENT_SECURITY_POLICY)
    );
}
