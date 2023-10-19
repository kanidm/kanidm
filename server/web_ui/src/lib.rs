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

use error::FetchError;
use gloo::console;
use kanidm_proto::constants::{APPLICATION_JSON, KSESSIONID};
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

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// it's event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<manager::ManagerApp>::new().render();
    Ok(())
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
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
        #[cfg(debug_assertions)]
        if method == RequestMethod::GET {
            gloo::console::debug!("This seems odd, you've supplied a body with a GET request?")
        }
        opts.body(Some(&body));
    }

    let request = Request::new_with_str_and_init(uri, &opts)?;
    request
        .headers()
        .set(crate::constants::CONTENT_TYPE, APPLICATION_JSON)
        .expect_throw("failed to set content-type header");

    if let Some(sessionid) = models::pop_auth_session_id() {
        request
            .headers()
            .set(KSESSIONID, &sessionid)
            .expect_throw("failed to set auth session id header");
    }

    if let Some(bearer_token) = models::get_bearer_token() {
        request
            .headers()
            .set("authorization", &bearer_token)
            .expect_throw("failed to set authorisation header");
    }

    let window = utils::window();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    let status = resp.status();
    let headers: Headers = resp.headers();

    if let Some(sessionid) = headers.get(KSESSIONID).ok().flatten() {
        models::push_auth_session_id(sessionid);
    }

    let kopid = headers.get("x-kanidm-opid").ok().flatten();

    let body = match resp.json() {
        Ok(json_future) => match JsFuture::from(json_future).await {
            Ok(body) => body,
            Err(e) => {
                let e_msg = format!("future json error -> {:?}", e);
                console::error!(e_msg.as_str());
                JsValue::NULL
            }
        },
        Err(e) => {
            let e_msg = format!("response json error -> {:?}", e);
            console::error!(e_msg.as_str());
            JsValue::NULL
        }
    };

    Ok((kopid, status, body, headers))
}
