use http::header::ORIGIN;
use kanidm_client::KanidmClient;

use kanidmd_testkit::{ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, TEST_CORS_ORIGIN};

#[kanidmd_testkit::test(cors_allowed_origins = Some(vec![
    TEST_CORS_ORIGIN.to_string()
]))]
async fn test_https_cors_headers(rsclient: KanidmClient) {
    // log in
    let auth_res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(auth_res.is_ok());

    // extract bearer token
    let bearer = rsclient
        .get_token()
        .await
        .expect("Failed to get bearer token!");
    let url = rsclient.make_url("/v1/self");

    // here we test the /v1/self endpoint which should have the headers
    let response = match reqwest::Client::new()
        .get(url.clone())
        .bearer_auth(bearer)
        .header(ORIGIN, TEST_CORS_ORIGIN)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!("Failed to query {:?} : {:#?}", url, error);
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);
    eprintln!(
        "CORS headers: {:#?}",
        response
            .headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    assert!(response
        .headers()
        .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_some_and(|hv| hv.to_str().is_ok_and(|v| v == TEST_CORS_ORIGIN)));
}
