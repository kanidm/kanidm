/// Test harnesses for WASM things.
///
/// Here be crabs with troubling pasts.
///
/// Run this on a mac with Safari using the following command:
///
/// ```shell
/// wasm-pack test --safari
/// ```
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1, 1);
}
