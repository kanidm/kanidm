//! This handles the login/auth flows, and is designed to be smol and snappy
//! so it loads fast and gets the user to where they need to go!
//!
//! - /ui/login
//! - /ui/oauth2
//! - /ui/reauth

mod components;
mod oauth2;
pub mod router;

#[allow(unused_imports)] // because it's needed to compile wasm things
use wasm_bindgen::prelude::wasm_bindgen;

use wasm_bindgen::JsValue;

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// its event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<components::LoginApp>::new().render();
    Ok(())
}
