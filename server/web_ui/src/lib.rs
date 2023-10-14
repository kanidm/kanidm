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
// Needed as yew-router::Routable uses std::collection::HashMap
#![allow(clippy::disallowed_types)]

use kanidmd_web_ui_shared::RequestMethod;
use wasm_bindgen::prelude::*;

mod credential;
mod login;
mod manager;
mod models;
mod oauth2;
// mod utils;
mod views;

mod components;

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// its event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<manager::ManagerApp>::new().render();
    Ok(())
}
