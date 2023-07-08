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

use headless_chrome::Browser;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1, 1);
}

#[kanidmd_testkit::test]
async fn test_ui_loads(rsclient: kanidm_client::KanidmClient)  {
    println!("rsclient: {}", rsclient.get_url());

    let browser = Browser::default().unwrap();
    let tab = browser.new_tab().unwrap();

    tab.navigate_to(rsclient.get_url()).unwrap();

    tab.wait_for_element("input#username").unwrap().click().unwrap();
    // Type in a query and press `Enter`
    tab.type_str("testuser").unwrap().press_key("Enter").unwrap();
}

