use kanidm_client::{http::header, KanidmClient};
use kanidmd_core::config::ServerRole;

#[kanidmd_testkit::test(role = ServerRole::WriteReplica)]
async fn test_https_manifest(rsclient: &KanidmClient) {
    // We need to do manual reqwests here.
    let client = rsclient.client();

    // here we test the /ui/ endpoint which should have the headers
    let response = match client
        .get(rsclient.make_url("/manifest.webmanifest"))
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/manifest.webmanifest"),
                error
            );
        }
    };
    eprintln!("response: {response:#?}");
    assert_eq!(response.status(), 200);

    eprintln!(
        "csp headers: {:#?}",
        response.headers().get(header::CONTENT_SECURITY_POLICY)
    );
}
