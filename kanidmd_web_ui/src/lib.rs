#![recursion_limit = "256"]

use wasm_bindgen::prelude::*;
use yew::prelude::*;

mod login;

#[wasm_bindgen]
pub fn run_login_app() -> Result<(), JsValue> {
    yew::start_app::<login::LoginApp>();
    Ok(())
}
