use serde::{Deserialize, Serialize};
use tracing::info;

#[kanidmd_testkit::test]
async fn check_that_the_swagger_api_loads(rsclient: kanidm_client::KanidmClient) {
    #[derive(Serialize, Deserialize, Debug)]
    struct OpenAPIResponse {
        pub openapi: String,
    }

    rsclient.set_token("".into()).await;
    info!("Running test: check_that_the_swagger_api_loads");
    let url = rsclient.make_url("/docs/v1/openapi.json");
    let foo: OpenAPIResponse = reqwest::get(url)
        .await
        .expect("Failed to get openapi.json")
        .json()
        .await
        .unwrap();
    assert!(foo.openapi != "1.2.3");
}
