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

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<manager::ManagerApp>();
    Ok(())
}
