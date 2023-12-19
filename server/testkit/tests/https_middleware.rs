use kanidm_client::KanidmClient;

#[kanidmd_testkit::test]
async fn test_https_middleware_headers(rsclient: KanidmClient) {
    // We need to do manual reqwests here.

    // here we test the /ui/ endpoint which should have the headers
    let response = match reqwest::get(rsclient.make_url("/ui")).await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/ui"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);
    eprintln!(
        "csp headers: {:#?}",
        response
            .headers()
            .get(http::header::CONTENT_SECURITY_POLICY)
    );
    assert_ne!(
        response
            .headers()
            .get(http::header::CONTENT_SECURITY_POLICY),
        None
    );

    // here we test the /ui/login endpoint which should have the headers
    let response = match reqwest::get(rsclient.make_url("/ui/login")).await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/ui/login"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);

    eprintln!(
        "csp headers: {:#?}",
        response
            .headers()
            .get(http::header::CONTENT_SECURITY_POLICY)
    );
    assert_ne!(
        response
            .headers()
            .get(http::header::CONTENT_SECURITY_POLICY),
        None
    );
}
