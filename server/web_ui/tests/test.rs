//! Test harnesses for WASM things.
//!
//! Here be crabs with troubling pasts.
//!
//! Run this on a mac with Safari using the following command:
//!
//! ```shell
//! wasm-pack test --chrome --headless
//!```
//!

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1, 1);
}

// #[cfg(feature = "webdriver")]
// #[kanidmd_testkit::test]
// async fn test_webdriver_ui_loads(rsclient: kanidm_client::KanidmClient) {
//     use fantoccini::{ClientBuilder, Locator};
//     println!("rsclient: {}", rsclient.get_url());

//     let c = ClientBuilder::native()
//         .connect("http://localhost:4444")
//         .await
//         .expect("failed to connect to WebDriver");

//     c.goto(rsclient.get_url())
//         .await
//         .expect(format!("Failed to load page: {}", rsclient.get_url()).as_str());

//     println!("Waiting for page to load");
//     c.wait();

//     c.find(Locator::Id("input#username"))
//         .await
//         .expect("Couldn't find input id=username")
//         .click()
//         .await
//         .expect("Couldn't click the username input?");
// }
