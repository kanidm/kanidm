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

use error::FetchError;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestMethod {
    GET,
    POST,
    PUT,
}

impl ToString for RequestMethod {
    fn to_string(&self) -> String {
        match self {
            RequestMethod::PUT => "PUT".to_string(),
            RequestMethod::POST => "POST".to_string(),
            RequestMethod::GET => "GET".to_string(),
        }
    }
}

/// Build and send a request to the backend, with some standard headers and pull back
/// (kopid, status, json, headers)
pub async fn do_request(
    uri: &str,
    method: RequestMethod,
    body: Option<JsValue>,
) -> Result<(Option<String>, u16, JsValue, Headers), FetchError> {
    let mut opts = RequestInit::new();
    opts.method(&method.to_string());
    opts.mode(RequestMode::SameOrigin);
    opts.credentials(web_sys::RequestCredentials::SameOrigin);
    if let Some(body) = body {
        opts.body(Some(&body));
    }

    let request = Request::new_with_str_and_init(uri, &opts)?;
    request
        .headers()
        .set("content-type", "application/json")
        .expect_throw("failed to set header");

    let window = utils::window();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    let status = resp.status();
    let headers: Headers = resp.headers();

    let kopid = headers.get("x-kanidm-opid").ok().flatten();

    Ok((kopid, status, JsFuture::from(resp.json()?).await?, headers))
}
