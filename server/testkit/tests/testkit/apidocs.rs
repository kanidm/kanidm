use jsonschema::Validator;
use serde::{Deserialize, Serialize};
use tracing::info;

#[kanidmd_testkit::test]
async fn check_that_the_swagger_api_loads(rsclient: &kanidm_client::KanidmClient) {
    #[derive(Serialize, Deserialize, Debug)]
    struct OpenAPIResponse {
        pub openapi: String,
    }

    rsclient.set_token("".into()).await;
    info!("Running test: check_that_the_swagger_api_loads");
    let url = rsclient.make_url("/docs/v1/openapi.json");

    let openapi_response = rsclient
        .perform_get_request::<OpenAPIResponse>(url.as_str())
        .await
        .expect("Failed to get openapi.json");
    assert_eq!(openapi_response.openapi, "3.1.0");

    // this validates that it's valid JSON schema, but not that it's valid openapi... but it's a start.
    let schema = rsclient
        .perform_get_request::<serde_json::Value>(url.as_str())
        .await
        .expect("Failed to get openapi.json");

    let instance = serde_json::json!("foo");
    let compiled = Validator::new(&schema).expect("A valid schema");
    assert!(jsonschema::is_valid(&schema, &instance));
    let result = compiled.validate(&instance);
    if let Err(errors) = result {
        println!("ERRORS!");
        println!("{errors:?}");
        panic!("Validation errors!");
    }
}
