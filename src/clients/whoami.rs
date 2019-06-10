extern crate rsidm;
extern crate reqwest;

use rsidm::proto_v1::{WhoamiResponse};

fn main() {
    println!("Hello whoami");

    // Given the current ~/.rsidm/cookie (or none)
    // we should check who we are plus show the auth token that the server
    // would generate for us.

    let whoami_req = WhoamiRequest {
    };

    let mut response = client
        .get("http://127.0.0.1:8080/v1/whoami")
        // .body(serde_json::to_string(&whoami_req).unwrap())
        .send()
        .unwrap();

    println!("{:?}", response);

    // Parse it if desire.
    // let r: Response = serde_json::from_str(response.text().unwrap().as_str()).unwrap();
    // println!("{:?}", r);
}
