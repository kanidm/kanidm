#![recursion_limit = "256"]
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use wasm_bindgen::prelude::*;

#[macro_use]
mod macros;

mod constants;
mod credential;
mod error;
mod login;
mod manager;
mod models;
mod oauth2;
mod utils;
mod views;

mod components;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<manager::ManagerApp>::new().render();
    #[cfg(debug_assertions)]
    gloo::console::debug!(kanidm_proto::utils::get_version("kanidmd_web_ui"));
    Ok(())
}
