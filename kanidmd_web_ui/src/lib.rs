#![recursion_limit = "256"]

use wasm_bindgen::prelude::*;

#[macro_use]
extern crate serde_derive;

mod login;
mod manager;
mod models;
mod oauth2;
mod views;

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app_as_body::<manager::ManagerApp>();
    Ok(())
}
