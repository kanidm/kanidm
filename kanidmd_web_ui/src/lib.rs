#![recursion_limit = "256"]
#![deny(warnings)]

use wasm_bindgen::prelude::*;

mod error;
mod login;
mod manager;
mod models;
mod oauth2;
mod utils;
mod views;

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app_as_body::<manager::ManagerApp>();
    Ok(())
}
