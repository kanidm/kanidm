use jsonschema::JSONSchema;
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
    let foo: OpenAPIResponse = reqwest::get(url.clone())
        .await
        .expect("Failed to get openapi.json")
        .json()
        .await
        .unwrap();
    assert!(foo.openapi != "1.2.3");

    // this validates that it's valid JSON schema, but not that it's valid openapi... but it's a start.
    let schema: serde_json::Value = reqwest::get(url)
        .await
        .expect("Failed to get openapi.json")
        .json()
        .await
        .unwrap();

    let instance = serde_json::json!("foo");
    let compiled = JSONSchema::compile(&schema).expect("A valid schema");
    assert!(jsonschema::is_valid(&schema, &instance));
    let result = compiled.validate(&instance);
    if let Err(errors) = result {
        println!("ERRORS!");
        for error in errors {
            println!("Validation error: {}", error);
            println!("Instance path: {}", error.instance_path);
        }
        panic!("Validation errors!");
    }
}
