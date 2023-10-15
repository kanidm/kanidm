#[allow(unused_imports)] // because it's needed to compile wasm things
use wasm_bindgen::prelude::wasm_bindgen;

use wasm_bindgen::JsValue;

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// it's event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    // yew::Renderer::<AdminApp>::new().render();
    Ok(())
}
